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

// CreateHeadscaleUser attempts to create a user in Headscale and returns their string/uint64 ID.
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
                return nil
        }

        respBody, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("headscale user creation failed with status %d: %s", resp.StatusCode, string(respBody))
}

// CreatePreAuthKey asks Headscale to generate a pre-authentication key for the given user.
func CreatePreAuthKey(username string, ephemeral bool, tags []string) (string, error) {
        url := fmt.Sprintf("%s/api/v1/preauthkey", os.Getenv("HEADSCALE_URL"))

        expiration := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
        if ephemeral {
                expiration = time.Now().Add(1 * time.Hour).Format(time.RFC3339)
        }

        // Headscale v0.22/0.23 API transition:
        // Try passing the username string in the "user" field.
        // If the protobuf complains it wants a uint64, it means the API is actually
        // expecting "user" to be a string name in newer versions, but the error
        // 'invalid value for uint64 field user' strongly implies it's an older
        // headscale version or specific fork where the field maps to user_id.
        // Actually, in Headscale v0.23, you pass the string username in the "user" query param
        // for GET requests, but for POST it might want `user` as string.
        // Let's pass the username string, but if it fails, maybe we need `namespace`?
        // Wait, the error explicitly said: `invalid value for uint64 field user: "nameless..."`
        // Let's fetch the user ID first!

        userID, err := getHeadscaleUserID(username)
        if err != nil {
            return "", fmt.Errorf("could not get user ID: %v", err)
        }

        payload := map[string]interface{}{
                "user":       username, // In some versions this must be string
                "user_id":    userID,   // In some versions it expects user_id
                "reusable":   false,
                "ephemeral":  ephemeral,
                "expiration": expiration,
        }
        // If the proto explicitly complained about `uint64 field user`, we MUST send a number in `user`.
        // Let's overwrite "user" with the numeric ID.
        payload["user"] = userID

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
                // If it failed because it actually expected a string in "user", let's try fallback to string "user"
                // but the original error was `uint64 field user`.
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

func getHeadscaleUserID(username string) (uint64, error) {
        // We can list all users and find the matching one to get its ID
        url := fmt.Sprintf("%s/api/v1/user", os.Getenv("HEADSCALE_URL"))
        req, _ := http.NewRequest("GET", url, nil)
        req.Header.Set("Authorization", "Bearer "+os.Getenv("HEADSCALE_API_KEY"))

        client := &http.Client{Timeout: 10 * time.Second}
        resp, err := client.Do(req)
        if err != nil {
            return 0, err
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
            return 0, fmt.Errorf("failed to list users: %d", resp.StatusCode)
        }

        var result struct {
            Users []struct {
                ID uint64 `json:"id"`
                // Sometimes it's a string ID, but proto error said uint64
                Name string `json:"name"`
            } `json:"users"`
        }

        if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
            return 0, err
        }

        for _, u := range result.Users {
            if u.Name == username {
                return u.ID, nil
            }
        }

        return 0, fmt.Errorf("user %s not found after creation", username)
}
