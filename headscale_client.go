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
        // 1. FIRST, check if user exists using the 'name' filter to be efficient
        checkUrl := fmt.Sprintf("%s/api/v1/user?name=%s", os.Getenv("HEADSCALE_URL"), username)
        checkReq, _ := http.NewRequest("GET", checkUrl, nil)
        checkReq.Header.Set("Authorization", "Bearer " + os.Getenv("HEADSCALE_API_KEY"))

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
                                                return nil // User already exists!
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

        req.Header.Set("Authorization", "Bearer " + os.Getenv("HEADSCALE_API_KEY"))
        req.Header.Set("Content-Type", "application/json")

        resp, err := client.Do(req)
        if err != nil {
                return err
        }
        defer resp.Body.Close()

        // 200 OK or 409 Conflict (already exists) are both "success"
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

        // 1. Always attempt to get the numeric/string ID first
        userID, err := getHeadscaleUserID(username)

        // If we truly couldn't find the user ID, we can't reliably create a key in newer Headscale versions.
        // But we'll still try the 'username' as a desperate fallback if ID retrieval failed.
        targetUser := userID
        if err != nil || targetUser == nil {
                targetUser = username
        }

        payload := map[string]interface{}{
                "user":       targetUser,
                "reusable":   false,
                "ephemeral":  ephemeral,
                "expiration": expiration,
        }

        if len(tags) > 0 {
                payload["acl_tags"] = tags
        }

        // First attempt
        key, err := executePreAuthRequest(url, payload)
        if err == nil {
                return key, nil
        }

        // 2. FALLBACK: If the first attempt failed and we used an ID, try using the username string.
        // Or vice-versa. This handles Headscale version differences (Legacy vs Modern API).
        if targetUser != username {
                payload["user"] = username
                key, err = executePreAuthRequest(url, payload)
                if err == nil {
                        return key, nil
                }
        }

        return "", fmt.Errorf("headscale key generation failed: %v", err)
}

func executePreAuthRequest(url string, payload map[string]interface{}) (string, error) {
        body, _ := json.Marshal(payload)
        req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
        if err != nil {
                return "", err
        }

        req.Header.Set("Authorization", "Bearer " + os.Getenv("HEADSCALE_API_KEY"))
        req.Header.Set("Content-Type", "application/json")

        client := &http.Client{Timeout: 10 * time.Second}
        resp, err := client.Do(req)
        if err != nil {
                return "", err
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                respBody, _ := io.ReadAll(resp.Body)
                return "", fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
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
        url := fmt.Sprintf("%s/api/v1/user?name=%s", os.Getenv("HEADSCALE_URL"), username)
        req, _ := http.NewRequest("GET", url, nil)
        req.Header.Set("Authorization", "Bearer " + os.Getenv("HEADSCALE_API_KEY"))

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
                        ID   interface{} `json:"id"`
                        Name string      `json:"name"`
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

        return nil, fmt.Errorf("user %s not found", username)
}

// DeleteHeadscaleNodeByIP deletes a node from Headscale by its IP address.
func DeleteHeadscaleNodeByIP(ip string) error {
        url := fmt.Sprintf("%s/api/v1/node", os.Getenv("HEADSCALE_URL"))
        req, _ := http.NewRequest("GET", url, nil)
        req.Header.Set("Authorization", "Bearer " + os.Getenv("HEADSCALE_API_KEY"))

        client := &http.Client{Timeout: 10 * time.Second}
        resp, err := client.Do(req)
        if err != nil {
                return err
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                return fmt.Errorf("failed to list nodes: %d", resp.StatusCode)
        }

        var result struct {
                Nodes []struct {
                        ID          interface{} `json:"id"`
                        IPAddresses []string    `json:"ipAddresses"`
                } `json:"nodes"`
        }

        if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
                return err
        }

        var nodeID interface{}
        for _, n := range result.Nodes {
                for _, nodeIP := range n.IPAddresses {
                        if nodeIP == ip {
                                nodeID = n.ID
                                break
                        }
                }
                if nodeID != nil {
                        break
                }
        }

        if nodeID == nil {
                return fmt.Errorf("node with IP %s not found", ip)
        }

        deleteUrl := fmt.Sprintf("%s/api/v1/node/%v", os.Getenv("HEADSCALE_URL"), nodeID)
        delReq, _ := http.NewRequest("DELETE", deleteUrl, nil)
        delReq.Header.Set("Authorization", "Bearer " + os.Getenv("HEADSCALE_API_KEY"))

        delResp, err := client.Do(delReq)
        if err != nil {
                return err
        }
        defer delResp.Body.Close()

        if delResp.StatusCode != http.StatusOK {
                delBody, _ := io.ReadAll(delResp.Body)
                return fmt.Errorf("failed to delete node: %d %s", delResp.StatusCode, string(delBody))
        }

        return nil
}
