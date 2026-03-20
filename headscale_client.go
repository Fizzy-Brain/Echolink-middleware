package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// CreateHeadscaleUser attempts to create a user in Headscale.
// It returns nil if the user is created successfully or if the user already exists (409 Conflict).
func CreateHeadscaleUser(username string) error {
	url := fmt.Sprintf("%s/api/v1/user", os.Getenv("HEADSCALE_URL"))
	
	payload := map[string]string{
		"name": username,
	}
	
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+os.Getenv("HEADSCALE_API_KEY"))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusConflict {
		// Created or already exists
		return nil
	}

	respBody, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("headscale user creation failed with status %d: %s", resp.StatusCode, string(respBody))
}

// CreatePreAuthKey asks Headscale to generate a pre-authentication key for the given user.
func CreatePreAuthKey(username string, ephemeral bool, tags []string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/preauthkey", os.Getenv("HEADSCALE_URL"))

	// Build expiration time (e.g., 24 hours from now)
	expiration := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	if ephemeral {
		// Ephemeral keys used by guests can expire sooner
		expiration = time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	}

	payload := map[string]interface{}{
		"user":       username,
		"reusable":   false,
		"ephemeral":  ephemeral,
		"expiration": expiration,
	}

	if len(tags) > 0 {
		payload["acl_tags"] = tags
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+os.Getenv("HEADSCALE_API_KEY"))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("headscale key generation failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		PreAuthKey struct {
			Key string `json:"key"`
		} `json:"preAuthKey"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.PreAuthKey.Key, nil
}
