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
func CreateHeadscaleUser(username string) error {
        // 1. FIRST, check if user exists to avoid the UNIQUE constraint error
        checkUrl := fmt.Sprintf("%s/api/v1/user", os.Getenv("HEADSCALE_URL"))
        checkReq, _ := http.NewRequest("GET", checkUrl, nil)
        checkReq.Header.Set("Authorization", "Bearer "+os.Getenv("HEADSCALE_API_KEY"))

        client := &http.Client{Timeout: 10 * time.Second}
        checkResp, err := client.Do(checkReq)
        if err == nil {
                defer checkResp.Body.Close()
                if checkResp.StatusCode == http.StatusOK {
                        var result struct {
                                Users []struct {
                                        Name string `json:"name"`
                                } `json:"users"`
                        }
                        if json.NewDecoder(checkResp.Body).Decode(&result) == nil {
                                for _, u := range result.Users {
                                        if u.Name == username {
                                                return nil // User already exists, we are good!
                                        }
                                }
                        }
                }
        }

        // 2. ONLY IF NOT FOUND, create them
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

        userID, err := getHeadscaleUserID(username)
        if err != nil {
            return "", fmt.Errorf("could not get user ID: %v", err)
        }

        payload := map[string]interface{}{
                "user":       userID, // Send the parsed interface ID (string or number depending on Headscale version)
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
                // Fallback: If it failed because it actually expected a string in "user", try passing username directly.
                respBody, _ := io.ReadAll(resp.Body)
                if bytes.Contains(respBody, []byte("invalid value")) || bytes.Contains(respBody, []byte("type")) {
                        payload["user"] = username
                        body, _ = json.Marshal(payload)
                        req, _ = http.NewRequest("POST", url, bytes.NewBuffer(body))
                        req.Header.Set("Authorization", "Bearer "+os.Getenv("HEADSCALE_API_KEY"))
                        req.Header.Set("Content-Type", "application/json")
                        resp2, err2 := client.Do(req)
                        if err2 == nil {
                                defer resp2.Body.Close()
                                if resp2.StatusCode == http.StatusOK {
                                        var result struct {
                                                PreAuthKey struct {
                                                        Key string `json:"key"`
                                                } `json:"preAuthKey"`
                                        }
                                        if err := json.NewDecoder(resp2.Body).Decode(&result); err == nil {
                                                return result.PreAuthKey.Key, nil
                                        }
                                }
                        }
                }
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

func getHeadscaleUserID(username string) (interface{}, error) {
        url := fmt.Sprintf("%s/api/v1/user", os.Getenv("HEADSCALE_URL"))
        req, _ := http.NewRequest("GET", url, nil)
        req.Header.Set("Authorization", "Bearer "+os.Getenv("HEADSCALE_API_KEY"))

        client := &http.Client{Timeout: 10 * time.Second}
        resp, err := client.Do(req)
        if err != nil {
            return nil, err
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
            return nil, fmt.Errorf("failed to list users: %d", resp.StatusCode)
        }

        var result struct {
            Users []struct {
                ID interface{} `json:"id"` // Safely handle both uint64 and string ID formats returned by varying Headscale versions
                Name string `json:"name"`
            } `json:"users"`
        }

        if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
            return nil, err
        }

        for _, u := range result.Users {
            if u.Name == username {
                return u.ID, nil
            }
        }

        return nil, fmt.Errorf("user %s not found after creation", username)
}
