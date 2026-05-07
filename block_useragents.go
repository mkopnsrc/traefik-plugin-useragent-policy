// Package traefik_plugin_block_useragents provides a plugin to block User-Agent based on browsers and OS.
package traefik_plugin_block_useragents

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
)

// BrowserConfig defines configuration for a single browser.
type BrowserConfig struct {
	Name    string `json:"name"`              // Browser name (e.g., "Chrome")
	Regex   string `json:"regex,omitempty"`   // Required: Exact regex pattern to match the browser
	Version string `json:"version,omitempty"` // Unused: Kept for compatibility but ignored
}

// Config holds the plugin configuration.
type Config struct {
	AllowedBrowsers []BrowserConfig `json:"allowedBrowsers,omitempty"` // List of browser configs
	AllowedOSTypes  []string        `json:"allowedOSTypes,omitempty"`  // Optional: List of allowed OS regex patterns
	// StrictMatch, when true, prepends \b to each browser/OS pattern so that
	// matches must begin at a word boundary. This prevents accidental
	// partial-word matches (e.g., "Chrome" matching inside "MyChrome"). It is
	// NOT a defense against active spoofing — see README "Security".
	StrictMatch bool `json:"strictMatch,omitempty"`
	// ClientIPHeader, when non-empty, names a request header whose first
	// comma-separated value is used as the client IP in blocked-request logs
	// instead of req.RemoteAddr. Typical value: "X-Forwarded-For". The header
	// content is trusted verbatim; only enable when Traefik's
	// forwardedHeaders.trustedIPs is configured to validate the source.
	ClientIPHeader string `json:"clientIPHeader,omitempty"`
}

// CreateConfig creates and initializes the plugin configuration.
func CreateConfig() *Config {
	return &Config{
		AllowedBrowsers: []BrowserConfig{},
		AllowedOSTypes:  []string{},
	}
}

// BlockUserAgents struct.
type BlockUserAgents struct {
	name           string
	next           http.Handler
	regexpsAllow   []*regexp.Regexp // Browser regex patterns
	osRegexpsAllow []*regexp.Regexp // OS regex patterns (optional)
	clientIPHeader string           // Header to read for client IP in logs (optional)
}

// BlockUserAgentsMessage struct for logging blocked requests. The "uri" field
// holds the request path only; query strings are intentionally omitted to
// avoid leaking tokens or other sensitive parameters into logs.
type BlockUserAgentsMessage struct {
	UserAgent  string `json:"user-agent"`
	RemoteAddr string `json:"ip"`
	Host       string `json:"host"`
	RequestURI string `json:"uri"`
}

// ValidateConfig validates the plugin configuration.
func ValidateConfig(config *Config) error {
	if len(config.AllowedBrowsers) == 0 {
		return fmt.Errorf("at least one allowed browser must be specified")
	}
	for _, bc := range config.AllowedBrowsers {
		if bc.Regex == "" {
			return fmt.Errorf("regex must be provided for browser: %s", bc.Name)
		}
	}
	return nil
}

// New creates and returns a plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if err := ValidateConfig(config); err != nil {
		return nil, err
	}
	regexpsAllow := make([]*regexp.Regexp, 0, len(config.AllowedBrowsers))
	osRegexpsAllow := make([]*regexp.Regexp, 0, len(config.AllowedOSTypes))

	// Compile regex patterns for allowed browsers
	for _, bc := range config.AllowedBrowsers {
		re, err := regexp.Compile(maybeAnchor(bc.Regex, config.StrictMatch))
		if err != nil {
			return nil, fmt.Errorf("error compiling browser regex for %s: %w", bc.Name, err)
		}
		regexpsAllow = append(regexpsAllow, re)
	}

	// Compile regex patterns for allowed OS types (if provided)
	for _, osPattern := range config.AllowedOSTypes {
		re, err := regexp.Compile(maybeAnchor(osPattern, config.StrictMatch))
		if err != nil {
			return nil, fmt.Errorf("error compiling OS regex %q: %w", osPattern, err)
		}
		osRegexpsAllow = append(osRegexpsAllow, re)
	}

	return &BlockUserAgents{
		name:           name,
		next:           next,
		regexpsAllow:   regexpsAllow,
		osRegexpsAllow: osRegexpsAllow,
		clientIPHeader: config.ClientIPHeader,
	}, nil
}

// maybeAnchor wraps the user pattern with a leading word boundary when strict
// matching is enabled. Wrapping with a non-capturing group prevents \b from
// binding only to the first alternative of an alternation pattern.
func maybeAnchor(pattern string, strict bool) string {
	if !strict {
		return pattern
	}
	return `\b(?:` + pattern + `)`
}

// ServeHTTP handles the HTTP request.
func (b *BlockUserAgents) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	userAgent := req.UserAgent()
	if userAgent == "" {
		b.logBlockedRequest(req, "No User-Agent")
		res.WriteHeader(http.StatusForbidden)
		return
	}

	// Check browser patterns
	browserMatch := false
	for _, re := range b.regexpsAllow {
		if re.MatchString(userAgent) {
			browserMatch = true
			break
		}
	}
	if !browserMatch {
		b.logBlockedRequest(req, "Unsupported Browser")
		res.WriteHeader(http.StatusForbidden)
		return
	}

	// Check OS patterns if provided
	if len(b.osRegexpsAllow) > 0 {
		osMatch := false
		for _, re := range b.osRegexpsAllow {
			if re.MatchString(userAgent) {
				osMatch = true
				break
			}
		}
		if !osMatch {
			b.logBlockedRequest(req, "Unsupported OS")
			res.WriteHeader(http.StatusForbidden)
			return
		}
	}

	b.next.ServeHTTP(res, req)
}

// clientIP returns the client IP for logging. When ClientIPHeader is
// configured, the first comma-separated value of that header is used; the
// content is trusted verbatim. Otherwise req.RemoteAddr is returned.
func (b *BlockUserAgents) clientIP(req *http.Request) string {
	if b.clientIPHeader == "" {
		return req.RemoteAddr
	}
	raw := req.Header.Get(b.clientIPHeader)
	if raw == "" {
		return req.RemoteAddr
	}
	if comma := strings.IndexByte(raw, ','); comma >= 0 {
		raw = raw[:comma]
	}
	return strings.TrimSpace(raw)
}

// logBlockedRequest logs details of a blocked request. The request path is
// logged without the query string to avoid surfacing tokens in logs.
func (b *BlockUserAgents) logBlockedRequest(req *http.Request, reason string) {
	message := &BlockUserAgentsMessage{
		UserAgent:  req.UserAgent(),
		RemoteAddr: b.clientIP(req),
		Host:       req.Host,
		RequestURI: req.URL.Path,
	}
	jsonMessage, err := json.Marshal(message)
	if err == nil {
		log.Printf("%s: Blocked (%s) - %s", b.name, reason, jsonMessage)
	} else {
		log.Printf("%s: Blocked (%s) - %s", b.name, reason, req.UserAgent())
	}
}
