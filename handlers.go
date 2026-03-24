package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var oauthConfig *oauth2.Config

func init() {
	oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "https://api.echo-link.app/auth/callback",
		Scopes: []string{
			"openid",
			"email",
		},
		Endpoint: google.Endpoint,
	}
}

// PairData represents the data exchanged between logged-in users via PIN.
type PairData struct {
	IpAddress string `json:"ip_address" binding:"required"`
	PublicKey string `json:"public_key" binding:"required"`
	Hostname  string `json:"hostname" binding:"required"`
}

// HandleLogin redirects the user to Google OAuth consent page
func HandleLogin(c *gin.Context) {
	// In production, state should be random and verified
	state := "random-state-string"
	url := oauthConfig.AuthCodeURL(state)
	c.Redirect(http.StatusFound, url)
}

// HandleCallback receives the OAuth code, gets user info, and deep links back
func HandleCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.String(http.StatusBadRequest, "No code in request")
		return
	}

	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to exchange token")
		return
	}

	// Fetch user info
	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to get user info")
		return
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		c.String(http.StatusInternalServerError, "Failed to decode user info")
		return
	}

	email := userInfo.Email
	if email == "" {
		c.String(http.StatusBadRequest, "Email not found")
		return
	}

	username := sanitizeUsername(email)

	// 1. Attempt to create the user in Headscale
	if err := CreateHeadscaleUser(username); err != nil {
		log.Printf("Error creating user %s: %v", username, err)
		c.String(http.StatusInternalServerError, "Failed to sync user with control plane")
		return
	}

	// 2. Mint a permanent Pre-Auth Key for this user
	authKey, err := CreatePreAuthKey(username, false, nil)
	if err != nil {
		log.Printf("Error generating pre-auth key for %s: %v", username, err)
		c.String(http.StatusInternalServerError, "Failed to generate auth key")
		return
	}

	// Create the deep link URL
	redirectUrl := fmt.Sprintf("echolink://login?authkey=%s&username=%s", authKey, username)

	// Redirect the user's browser to the deep link
	c.Redirect(http.StatusFound, redirectUrl)
}

// HandleGuestInvite generates a 6-digit PIN, mints an ephemeral Pre-Auth Key
// tagged with 'tag:guest', and stores the mapping in RAM for 5 minutes.
func HandleGuestInvite(c *gin.Context) {
	// First, ensure a generic "guest" user exists in Headscale to bind these keys to
	guestUser := "echolink-guests"
	if err := CreateHeadscaleUser(guestUser); err != nil {
		log.Printf("Error ensuring guest user exists: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Control plane error"})
		return
	}

	// Mint an ephemeral key with the guest tag
	authKey, err := CreatePreAuthKey(guestUser, true, []string{"tag:guest"})
	if err != nil {
		log.Printf("Error generating guest pre-auth key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate guest key"})
		return
	}

	// Generate 6-digit PIN
	pin := generatePIN(6)

	// Save to in-memory store
	SavePIN(pin, authKey)

	c.JSON(http.StatusOK, gin.H{
		"pin":                pin,
		"expires_in_minutes": 5,
	})
}

// ClaimRequest represents the guest submitting a PIN
type ClaimRequest struct {
	PIN string `json:"pin" binding:"required"`
}

// HandleGuestClaim validates the PIN and returns the associated Pre-Auth Key,
// consuming the PIN in the process.
func HandleGuestClaim(c *gin.Context) {
	var req ClaimRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing or invalid PIN"})
		return
	}

	val, found := GetAndRemovePIN(req.PIN)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Invalid or expired PIN"})
		return
	}

	authKey, ok := val.(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PIN does not match a Guest Pre-Auth Key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"auth_key": authKey,
	})
}

// HandlePairCreate receives PairData from Host, generates a 6-digit PIN, and saves to store.
func HandlePairCreate(c *gin.Context) {
	var data PairData
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or missing PairData"})
		return
	}

	// Generate 6-digit PIN
	pin := generatePIN(6)

	// Save to in-memory store
	SavePIN(pin, data)

	c.JSON(http.StatusOK, gin.H{
		"pin":                pin,
		"expires_in_minutes": 5,
	})
}

// HandlePairClaim receives PIN, returns PairData to Client.
func HandlePairClaim(c *gin.Context) {
	var req ClaimRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing or invalid PIN"})
		return
	}

	val, found := GetAndRemovePIN(req.PIN)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Invalid or expired PIN"})
		return
	}

	data, ok := val.(PairData)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PIN does not match an authenticated pair request"})
		return
	}

	c.JSON(http.StatusOK, data)
}

// Helper to format email into a valid Headscale username
func sanitizeUsername(email string) string {
	s := strings.ReplaceAll(email, "@", "_")
	s = strings.ReplaceAll(s, ".", "_")

	// Headscale requires username to start with a letter.
	// If it starts with a digit or other character, prepend 'u'
	if len(s) > 0 && !unicode.IsLetter(rune(s[0])) {
		s = "u" + s
	}

	// Headscale requires username to be at least 2 characters long.
	if len(s) < 2 {
		s = s + "user"
	}

	return s
}

// Helper to generate a random numeric PIN
func generatePIN(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "123456" // Fallback, shouldn't happen
	}
	for i := 0; i < length; i++ {
		b[i] = (b[i] % 10) + 48 // ASCII 0-9
	}
	return string(b)
}

type DeleteNodeRequest struct {
	IpAddress string `json:"ip_address" binding:"required"`
}

func HandleDeleteNode(c *gin.Context) {
	var req DeleteNodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing or invalid ip_address"})
		return
	}

	if err := DeleteHeadscaleNodeByIP(req.IpAddress); err != nil {
		log.Printf("Error deleting node %s: %v", req.IpAddress, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete node"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Node deleted successfully"})
}
