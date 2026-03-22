package main

import (
        "context"
        "crypto/rand"
        "log"
        "net/http"
        "os"
        "strings"
        "unicode"

        "github.com/gin-gonic/gin"
        "google.golang.org/api/idtoken"
)

// LoginRequest represents the incoming JWT from the client
type LoginRequest struct {
        IDToken string `json:"id_token" binding:"required"`
}

// PairData represents the data exchanged between logged-in users via PIN.
type PairData struct {
        IpAddress string `json:"ip_address" binding:"required"`
        PublicKey string `json:"public_key" binding:"required"`
        Hostname  string `json:"hostname" binding:"required"`
}

// HandleLogin verifies the Google JWT, ensures the user exists in Headscale,
// and mints a permanent Pre-Auth Key.
func HandleLogin(c *gin.Context) {
        var req LoginRequest
        if err := c.ShouldBindJSON(&req); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": "Missing or invalid id_token"})
                return
        }

        clientID := os.Getenv("GOOGLE_CLIENT_ID")

        // Verify the token
        payload, err := idtoken.Validate(context.Background(), req.IDToken, clientID)
        if err != nil {
                log.Printf("JWT validation failed: %v", err)
                c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
                return
        }

        // Extract email to use as the Headscale username
        // Headscale usernames must be alphanumeric + hyphens/underscores.
        // We'll replace '@' and '.' to make it compatible.
        email, ok := payload.Claims["email"].(string)
        if !ok || email == "" {
                c.JSON(http.StatusUnauthorized, gin.H{"error": "Email not found in token"})
                return
        }

        username := sanitizeUsername(email)

        // 1. Attempt to create the user in Headscale (ignore conflict if exists)
        if err := CreateHeadscaleUser(username); err != nil {
                log.Printf("Error creating user %s: %v", username, err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sync user with control plane"})
                return
        }

        // 2. Mint a permanent Pre-Auth Key for this user
        authKey, err := CreatePreAuthKey(username, false, nil)
        if err != nil {
                log.Printf("Error generating pre-auth key for %s: %v", username, err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate auth key"})
                return
        }

        c.JSON(http.StatusOK, gin.H{
                "username": username,
                "auth_key": authKey,
        })
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
