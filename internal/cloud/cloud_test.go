package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/config"
	"github.com/AikidoSec/safechain-internals/internal/platform"
)

// withTempRunDir points platform.GetConfig().RunDir at a t.TempDir for the
// duration of the test and restores the prior value on cleanup. Tests that
// call config.Save() need this so they don't write into the real run dir.
func withTempRunDir(t *testing.T) {
	t.Helper()
	pc := platform.GetConfig()
	prev := pc.RunDir
	pc.RunDir = t.TempDir()
	t.Cleanup(func() { pc.RunDir = prev })
}

func TestUnauthorizedTokenIsSuppressedUntilTokenChanges(t *testing.T) {
	withTempRunDir(t)
	Init()

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	cfg := &config.ConfigInfo{
		Token:    "bad-token",
		DeviceID: "device-1",
		BaseURL:  server.URL,
	}

	event := &HeartbeatEvent{}

	if _, err := SendHeartbeat(context.Background(), cfg, event); err == nil {
		t.Fatal("expected first heartbeat to fail with unauthorized")
	}
	if !cfg.IsCurrentTokenUnauthorized() {
		t.Fatal("expected token to be marked unauthorized after 401")
	}
	if requests != 1 {
		t.Fatalf("expected one network request, got %d", requests)
	}

	if _, err := SendHeartbeat(context.Background(), cfg, event); err == nil {
		t.Fatal("expected second heartbeat to be skipped")
	}
	if requests != 1 {
		t.Fatalf("expected unauthorized token suppression to skip network retry, got %d requests", requests)
	}

	cfg.SetToken("good-token")
	if cfg.IsCurrentTokenUnauthorized() {
		t.Fatal("expected unauthorized marker to clear when token changes")
	}

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	})

	if _, err := SendHeartbeat(context.Background(), cfg, event); err != nil {
		t.Fatalf("expected heartbeat with new token to succeed, got %v", err)
	}
	if requests != 2 {
		t.Fatalf("expected request after token change, got %d total requests", requests)
	}
}

// Simulates the race where a 401 for a token-in-flight arrives after the user
// has already replaced the token. The new token must not be marked unauthorized.
func TestStale401DoesNotPoisonReplacedToken(t *testing.T) {
	withTempRunDir(t)
	Init()

	received := make(chan string, 1)
	released := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Authorization")
		<-released
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	cfg := &config.ConfigInfo{
		Token:    "bad-token",
		DeviceID: "device-1",
		BaseURL:  server.URL,
	}

	done := make(chan error, 1)
	go func() {
		_, err := SendHeartbeat(context.Background(), cfg, &HeartbeatEvent{})
		done <- err
	}()

	if got := <-received; got != "bad-token" {
		t.Fatalf("expected request to be sent with bad-token, got %q", got)
	}
	cfg.SetToken("good-token")
	close(released)

	if err := <-done; err == nil {
		t.Fatal("expected in-flight heartbeat to fail with unauthorized")
	}
	if cfg.IsCurrentTokenUnauthorized() {
		t.Fatal("stale 401 must not mark the replacement token as unauthorized")
	}
	if cfg.LastUnauthorizedToken != "" {
		t.Fatalf("expected LastUnauthorizedToken to remain cleared, got %q", cfg.LastUnauthorizedToken)
	}
}
