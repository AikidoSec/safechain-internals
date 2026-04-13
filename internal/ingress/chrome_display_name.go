package ingress

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const chromeWebStoreLookupURL = "https://chromewebstore.google.com/detail/%s"

const (
	chromeDisplayNameCacheTTL        = 7 * 24 * time.Hour
	chromeDisplayNameCacheMaxEntries = 1000
)

var (
	// metaTagRegexp matches any <meta ...> tag, including self-closing variants.
	// Flags: i = case-insensitive, s = dot matches newline (handles multi-line tags).
	metaTagRegexp = regexp.MustCompile(`(?is)<meta\b[^>]*>`)

	// htmlAttributeRegexp extracts name=value pairs from an HTML tag string.
	// Handles all three quoting styles: double-quoted, single-quoted, and unquoted.
	// Flags: i = case-insensitive, s = dot matches newline.
	htmlAttributeRegexp = regexp.MustCompile("(?is)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s\"'=<>`]+)")

	chromeWebStoreSuffix  = " - Chrome Web Store"
	chromeLookupUserAgent = "SafeChain-Agent/1.0"
)

type chromeExtensionNameResolver struct {
	client  *http.Client
	baseURL string

	mu    sync.RWMutex
	cache map[string]chromeExtensionNameCacheEntry
	now   func() time.Time
}

type chromeExtensionNameCacheEntry struct {
	name     string
	cachedAt time.Time
}

func newChromeExtensionNameResolver() *chromeExtensionNameResolver {
	return &chromeExtensionNameResolver{
		client:  &http.Client{},
		baseURL: chromeWebStoreLookupURL,
		cache:   make(map[string]chromeExtensionNameCacheEntry),
		now:     time.Now,
	}
}

// Lookup fetches the human-readable display name for a Chrome extension by its ID.
// The result is cached after the first successful fetch so subsequent calls are free.
// Returns an empty string (with no error) when the name cannot be determined
//
//	name, err := r.Lookup(ctx, "cjpalhdlnbpafiamejdnhcphjbkeiagm")
//	// name == "uBlock Origin"
func (r *chromeExtensionNameResolver) Lookup(ctx context.Context, extensionID string) (string, error) {
	extensionID = strings.TrimSpace(strings.ToLower(extensionID))
	if extensionID == "" {
		return "", nil
	}

	if cached := r.getCached(extensionID); cached != "" {
		return cached, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(r.baseURL, extensionID), nil)
	if err != nil {
		return "", fmt.Errorf("build Chrome Web Store request: %w", err)
	}
	req.Header.Set("User-Agent", chromeLookupUserAgent)

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch Chrome Web Store page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", fmt.Errorf("read Chrome Web Store response body: %w", err)
	}

	name := extractChromeWebStoreDisplayName(string(body))
	if name == "" {
		return "", nil
	}

	r.setCached(extensionID, name)

	return name, nil
}

func (r *chromeExtensionNameResolver) getCached(extensionID string) string {
	r.mu.RLock()
	entry, ok := r.cache[extensionID]
	r.mu.RUnlock()
	if !ok {
		return ""
	}
	if r.now().Sub(entry.cachedAt) <= chromeDisplayNameCacheTTL {
		return entry.name
	}

	return ""
}

func (r *chromeExtensionNameResolver) setCached(extensionID, name string) {
	now := r.now()

	r.mu.Lock()
	defer r.mu.Unlock()

	r.pruneCacheLocked(now)
	r.cache[extensionID] = chromeExtensionNameCacheEntry{
		name:     name,
		cachedAt: now,
	}
}

func (r *chromeExtensionNameResolver) pruneCacheLocked(now time.Time) {
	var (
		oldestID    string
		oldestAt    time.Time
		foundOldest bool
	)

	for extensionID, entry := range r.cache {
		if now.Sub(entry.cachedAt) > chromeDisplayNameCacheTTL {
			delete(r.cache, extensionID)
			continue
		}
		if !foundOldest || entry.cachedAt.Before(oldestAt) {
			oldestID = extensionID
			oldestAt = entry.cachedAt
			foundOldest = true
		}
	}

	if len(r.cache) >= chromeDisplayNameCacheMaxEntries && foundOldest {
		delete(r.cache, oldestID)
	}
}

// extractChromeWebStoreDisplayName parses the og:title meta tag from a Chrome Web
// Store page and returns the extension name with the trailing " - Chrome Web Store"
// suffix stripped. Returns an empty string if the tag is absent or the content does
// not carry the expected suffix.
//
//	// given: <meta property="og:title" content="uBlock Origin - Chrome Web Store">
//	extractChromeWebStoreDisplayName(html) // "uBlock Origin"
func extractChromeWebStoreDisplayName(htmlBody string) string {
	for _, tag := range metaTagRegexp.FindAllString(htmlBody, -1) {
		name := extractChromeWebStoreDisplayNameFromMetaTag(tag)
		if name == "" {
			continue
		}
		return name
	}

	return ""
}

func extractChromeWebStoreDisplayNameFromMetaTag(tag string) string {
	attrs := parseHTMLAttributes(tag)
	if !strings.EqualFold(attrs["property"], "og:title") {
		return ""
	}

	content := strings.TrimSpace(attrs["content"])
	name, ok := strings.CutSuffix(content, chromeWebStoreSuffix)
	if !ok {
		// If the title does not end with the Chrome Web Store suffix, we may have
		// fetched an unexpected HTML page instead of the extension detail page, so
		// avoid returning a potentially incorrect display name.
		return ""
	}

	return strings.TrimSpace(name)
}

// parseHTMLAttributes extracts all name=value attribute pairs from a single HTML
// tag string. Attribute names are lowercased; values are unquoted and HTML-unescaped.
//
//	// given: <meta property="og:title" content="Tom &amp; Jerry - Chrome Web Store">
//	parseHTMLAttributes(tag) // {"property": "og:title", "content": "Tom & Jerry - Chrome Web Store"}
func parseHTMLAttributes(tag string) map[string]string {
	matches := htmlAttributeRegexp.FindAllStringSubmatch(tag, -1)
	if len(matches) == 0 {
		return nil
	}

	attrs := make(map[string]string, len(matches))
	for _, match := range matches {
		if len(match) != 3 {
			continue
		}
		name := strings.ToLower(match[1])
		value := strings.TrimSpace(match[2])
		value = strings.Trim(value, `"'`)
		attrs[name] = html.UnescapeString(value)
	}

	return attrs
}
