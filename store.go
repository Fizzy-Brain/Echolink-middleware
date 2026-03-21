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

// SavePIN stores a mapping of PIN to some data (string or struct).
func SavePIN(pin string, data interface{}) {
	// The PIN is valid for exactly 5 minutes
	pinStore.Set(pin, data, 5*time.Minute)
}

// GetAndRemovePIN retrieves the data for a given PIN, and deletes the PIN
// from the store immediately to ensure it's a single-use claim.
// Returns (data, true) if found, or (nil, false) if not found or expired.
func GetAndRemovePIN(pin string) (interface{}, bool) {
	val, found := pinStore.Get(pin)
	if !found {
		return nil, false
	}

	// Delete immediately to prevent replay claims
	pinStore.Delete(pin)

	return val, true
}
