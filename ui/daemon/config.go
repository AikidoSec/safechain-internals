package daemon

// Config holds daemon connection settings. Used only in Go; never exposed to frontend.
// Defaults are used when the app is started without -base-url / -token.
var (
	BASE_URL = "http://127.0.0.1:7878"
	TOKEN    = "devtoken"
)

// SetConfig sets the daemon API base URL and auth token (e.g. from command-line flags).
// Call this at startup before any daemon API calls.
func SetConfig(baseURL, token string) {
	if baseURL != "" {
		BASE_URL = baseURL
	}
	if token != "" {
		TOKEN = token
	}
}
