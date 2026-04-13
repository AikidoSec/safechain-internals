package ingress

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestExtractChromeWebStoreDisplayName(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{
			name: "extracts og title",
			html: `<meta property="og:title" content="uBlock Origin - Chrome Web Store">`,
			want: "uBlock Origin",
		},
		{
			name: "supports reordered attributes",
			html: `<meta content="Bitwarden Password Manager - Chrome Web Store" property="og:title">`,
			want: "Bitwarden Password Manager",
		},
		{
			name: "decodes html entities",
			html: `<meta property="og:title" content="Tom &amp; Jerry - Chrome Web Store">`,
			want: "Tom & Jerry",
		},
		{
			name: "returns empty when suffix missing",
			html: `<meta property="og:title" content="Chrome Web Store">`,
			want: "",
		},
		{
			name: "returns empty when tag missing",
			html: `<title>Some Page</title>`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractChromeWebStoreDisplayName(tt.html)
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestChromeExtensionNameResolverLookupReturnsEmptyOnNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	resolver := &chromeExtensionNameResolver{
		client:  server.Client(),
		baseURL: server.URL + "/detail/%s",
		cache:   make(map[string]chromeExtensionNameCacheEntry),
		now:     time.Now,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	name, err := resolver.Lookup(ctx, "abcdefghijklmnopabcdefghijklmnop")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "" {
		t.Fatalf("expected empty name for non-200 response, got %q", name)
	}
}

func TestChromeExtensionNameResolverLookupCachesSuccessfulResponses(t *testing.T) {
	var requests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `<meta property="og:title" content="Ghostery Tracker &amp; Ad Blocker - Chrome Web Store">`)
	}))
	defer server.Close()

	resolver := &chromeExtensionNameResolver{
		client:  server.Client(),
		baseURL: server.URL + "/detail/%s",
		cache:   make(map[string]chromeExtensionNameCacheEntry),
		now:     time.Now,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	first, err := resolver.Lookup(ctx, "abcdefghijklmnopabcdefghijklmnop")
	if err != nil {
		t.Fatalf("first lookup failed: %v", err)
	}
	second, err := resolver.Lookup(ctx, "abcdefghijklmnopabcdefghijklmnop")
	if err != nil {
		t.Fatalf("second lookup failed: %v", err)
	}

	if first != "Ghostery Tracker & Ad Blocker" {
		t.Fatalf("unexpected first lookup result: %q", first)
	}
	if second != first {
		t.Fatalf("expected cached result %q, got %q", first, second)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("expected exactly one upstream request, got %d", got)
	}
}

func TestChromeExtensionNameResolverLookupExpiresOldEntries(t *testing.T) {
	var requests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `<meta property="og:title" content="uBlock Origin - Chrome Web Store">`)
	}))
	defer server.Close()

	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	resolver := &chromeExtensionNameResolver{
		client:  server.Client(),
		baseURL: server.URL + "/detail/%s",
		cache: map[string]chromeExtensionNameCacheEntry{
			"abcdefghijklmnopabcdefghijklmnop": {
				name:     "stale",
				cachedAt: now.Add(-chromeDisplayNameCacheTTL - time.Minute),
			},
		},
		now: func() time.Time { return now },
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	name, err := resolver.Lookup(ctx, "abcdefghijklmnopabcdefghijklmnop")
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if name != "uBlock Origin" {
		t.Fatalf("expected refreshed name, got %q", name)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("expected one upstream refresh after cache expiry, got %d", got)
	}
}

func TestChromeExtensionNameResolverSetCachedEvictsOldestEntryWhenFull(t *testing.T) {
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	resolver := &chromeExtensionNameResolver{
		cache: make(map[string]chromeExtensionNameCacheEntry, chromeDisplayNameCacheMaxEntries),
		now:   func() time.Time { return now },
	}

	for i := range chromeDisplayNameCacheMaxEntries {
		resolver.cache[fmt.Sprintf("ext-%04d", i)] = chromeExtensionNameCacheEntry{
			name:     fmt.Sprintf("name-%04d", i),
			cachedAt: now.Add(time.Duration(i) * time.Minute),
		}
	}

	resolver.setCached("new-entry", "New Entry")

	if len(resolver.cache) != chromeDisplayNameCacheMaxEntries {
		t.Fatalf("expected cache size to stay at %d, got %d", chromeDisplayNameCacheMaxEntries, len(resolver.cache))
	}
	if _, ok := resolver.cache["ext-0000"]; ok {
		t.Fatalf("expected oldest cache entry to be evicted")
	}
	if entry, ok := resolver.cache["new-entry"]; !ok || entry.name != "New Entry" {
		t.Fatalf("expected new cache entry to be stored")
	}
}
