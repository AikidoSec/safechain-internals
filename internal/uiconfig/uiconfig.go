package uiconfig

import (
	"sync"

	"github.com/google/uuid"
)

const (
	DefaultBaseURL = "http://127.0.0.1:9876"
	DefaultToken   = "devtoken"
)

var (
	mu      sync.RWMutex
	baseURL = DefaultBaseURL
	token   = DefaultToken
)

// BaseURL returns the UI app server base URL (daemon posts proxy-status and blocked events here).
func BaseURL() string {
	mu.RLock()
	defer mu.RUnlock()
	return baseURL
}

// Token returns the shared token used for daemon↔UI communication.
func Token() string {
	mu.RLock()
	defer mu.RUnlock()
	return token
}

// SetBaseURL sets the UI base URL. Call at startup (e.g. when binding the app server).
func SetBaseURL(s string) {
	if s == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	baseURL = s
}

// SetToken sets the shared token. Use when the daemon starts the UI and passes the token to it.
func SetToken(s string) {
	if s == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	token = s
}

// GenerateAndSetToken generates a new token, sets it, and returns it.
// Call when the daemon starts the UI so it can pass this token to the UI process (e.g. -token=...).
func GenerateAndSetToken() string {
	newToken := uuid.New().String()
	mu.Lock()
	token = newToken
	mu.Unlock()
	return newToken
}
