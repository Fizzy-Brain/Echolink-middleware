package main

import (
	"time"

	"github.com/patrickmn/go-cache"
)

var pinStore *cache.Cache

// InitStore initializes the in-memory cache with a 5-minute default expiration
// and a 1-minute cleanup interval for expired items.
func InitStore() {
	pinStore = cache.New(5*time.Minute, 1*time.Minute)
}

// SavePIN stores a mapping of PIN to the Headscale Pre-Auth Key.
func SavePIN(pin string, authKey string) {
	// The PIN is valid for exactly 5 minutes
	pinStore.Set(pin, authKey, 5*time.Minute)
}

// GetAndRemovePIN retrieves the Pre-Auth Key for a given PIN, and deletes the PIN
// from the store immediately to ensure it's a single-use claim.
// Returns (authKey, true) if found, or ("", false) if not found or expired.
func GetAndRemovePIN(pin string) (string, bool) {
	val, found := pinStore.Get(pin)
	if !found {
		return "", false
	}

	// Delete immediately to prevent replay claims
	pinStore.Delete(pin)

	authKey, ok := val.(string)
	if !ok {
		return "", false
	}

	return authKey, true
}
