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
)

const chromeWebStoreLookupURL = "https://chromewebstore.google.com/detail/%s"

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
	cache map[string]string
}

func newChromeExtensionNameResolver() *chromeExtensionNameResolver {
	return &chromeExtensionNameResolver{
		client:  &http.Client{},
		baseURL: chromeWebStoreLookupURL,
		cache:   make(map[string]string),
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

	r.mu.RLock()
	cached := r.cache[extensionID]
	r.mu.RUnlock()
	if cached != "" {
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

	r.mu.Lock()
	r.cache[extensionID] = name
	r.mu.Unlock()

	return name, nil
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
	if content == "" {
		return ""
	}

	name, ok := strings.CutSuffix(content, chromeWebStoreSuffix)
	if !ok {
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
