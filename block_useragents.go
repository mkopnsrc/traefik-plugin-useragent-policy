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
	"sync/atomic"
	"time"
)

// Action values for BrowserConfig.Action.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

// Mode values for Config.Mode.
const (
	ModeEnforce = "enforce"
	ModeLogOnly = "log-only"
)

// BrowserConfig defines configuration for a single browser rule.
type BrowserConfig struct {
	Name    string `json:"name"`              // Browser name (e.g., "Chrome")
	Regex   string `json:"regex,omitempty"`   // Required: regex pattern to match the browser portion of the UA
	Version string `json:"version,omitempty"` // Unused: kept for compatibility but ignored
	// Action selects the rule's effect when the regex matches the User-Agent:
	//   "allow" (default, or empty) — permit the request when the UA matches.
	//   "deny"                      — block the request when the UA matches.
	// Deny rules are evaluated before allow rules, so a deny match always wins.
	// At least one rule with action="allow" must be configured; without one no
	// request could ever pass.
	Action string `json:"action,omitempty"`
}

// Config holds the plugin configuration.
type Config struct {
	AllowedBrowsers []BrowserConfig `json:"allowedBrowsers,omitempty"` // Browser rules (allow and deny — see BrowserConfig.Action)
	AllowedOSTypes  []string        `json:"allowedOSTypes,omitempty"`  // Optional: list of allowed OS regex patterns
	// StrictMatch, when true, prepends \b to each browser/OS pattern so that
	// matches must begin at a word boundary. Prevents accidental partial-word
	// matches (e.g., "Chrome" matching inside "MyChrome"). NOT a defense
	// against active spoofing — see README "Security".
	StrictMatch bool `json:"strictMatch,omitempty"`
	// ClientIPHeader, when non-empty, names a request header whose first
	// comma-separated value is used as the client IP in blocked-request logs
	// instead of req.RemoteAddr. Typical value: "X-Forwarded-For". The header
	// content is trusted verbatim; only enable when Traefik's
	// forwardedHeaders.trustedIPs is configured to validate the source.
	ClientIPHeader string `json:"clientIPHeader,omitempty"`
	// Mode controls whether block decisions are enforced or only observed.
	//   "enforce" (default, or empty) — block matched requests with 403.
	//   "log-only"                    — log what would be blocked but forward
	//                                   the request to the next handler. Useful
	//                                   for staging new rules without impact.
	Mode string `json:"mode,omitempty"`
	// BypassPaths is a list of literal URL path prefixes (matched with
	// strings.HasPrefix against req.URL.Path). Requests whose path matches any
	// prefix skip all User-Agent checks and pass straight to the next handler.
	// Intended for health checks, well-known endpoints, etc.
	BypassPaths []string `json:"bypassPaths,omitempty"`
	// MetricsLogInterval, when set to a positive Go duration string (e.g.
	// "60s", "5m"), starts a background goroutine that emits a single JSON
	// summary of the plugin's atomic counters at that interval. The goroutine
	// respects the context.Context passed to New() and exits on cancellation,
	// so Traefik plugin reloads do not leak goroutines. Default "" — disabled.
	MetricsLogInterval string `json:"metricsLogInterval,omitempty"`
	// LogSampleN, when greater than 1, suppresses per-reason blocked-request
	// log lines so that only every Nth occurrence is logged (e.g. LogSampleN=
	// 100 logs roughly 1% of blocks per reason). Reduces log volume during
	// floods. The first occurrence of each reason is always logged. Has no
	// effect on metrics counters. Default 0/1 — log every block.
	LogSampleN int `json:"logSampleN,omitempty"`
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
	regexpsAllow   []*regexp.Regexp // Browser allow patterns
	regexpsDeny    []*regexp.Regexp // Browser deny patterns (checked first)
	osRegexpsAllow []*regexp.Regexp // OS allow patterns (optional)
	clientIPHeader string           // Header to read for client IP in logs (optional)
	bypassPaths    []string         // Literal path prefixes that skip all checks
	logOnly        bool             // When true, log block decisions but forward the request
	logSampleN     uint64           // Per-reason log-sampling stride; 0/1 = log all

	// Atomic cumulative counters. Read via the metrics-log goroutine and at
	// test time; never reset. metricsSnapshot is the JSON shape of a summary
	// log line.
	cntTotal      atomic.Uint64
	cntAllowed    atomic.Uint64
	cntBypass     atomic.Uint64
	cntNoUA       atomic.Uint64
	cntDenied     atomic.Uint64
	cntBadBrowser atomic.Uint64
	cntBadOS      atomic.Uint64
}

// metricsSnapshot is the JSON payload emitted by the periodic metrics-log
// goroutine. Cumulative — operators compute rates by diffing snapshots.
type metricsSnapshot struct {
	Total          uint64 `json:"total"`
	Allowed        uint64 `json:"allowed"`
	Bypass         uint64 `json:"bypass"`
	BlockedNoUA    uint64 `json:"blocked_no_ua"`
	BlockedDeny    uint64 `json:"blocked_deny"`
	BlockedBrowser uint64 `json:"blocked_browser"`
	BlockedOS      uint64 `json:"blocked_os"`
}

// BlockUserAgentsMessage is the JSON shape of the blocked-request log line.
// The "uri" field holds the request path only; query strings are omitted to
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
		return fmt.Errorf("at least one browser rule must be specified")
	}
	allowCount := 0
	for _, bc := range config.AllowedBrowsers {
		if bc.Regex == "" {
			return fmt.Errorf("regex must be provided for browser: %s", bc.Name)
		}
		switch bc.Action {
		case "", ActionAllow:
			allowCount++
		case ActionDeny:
			// no-op
		default:
			return fmt.Errorf("invalid action %q for browser %s (must be %q or %q)", bc.Action, bc.Name, ActionAllow, ActionDeny)
		}
	}
	if allowCount == 0 {
		return fmt.Errorf("at least one browser rule with action %q is required", ActionAllow)
	}
	switch config.Mode {
	case "", ModeEnforce, ModeLogOnly:
		// ok
	default:
		return fmt.Errorf("invalid mode %q (must be %q or %q)", config.Mode, ModeEnforce, ModeLogOnly)
	}
	if config.LogSampleN < 0 {
		return fmt.Errorf("logSampleN must be >= 0, got %d", config.LogSampleN)
	}
	if config.MetricsLogInterval != "" {
		if _, err := time.ParseDuration(config.MetricsLogInterval); err != nil {
			return fmt.Errorf("metricsLogInterval %q is not a valid duration: %w", config.MetricsLogInterval, err)
		}
	}
	return nil
}

// New creates and returns a plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if err := ValidateConfig(config); err != nil {
		return nil, err
	}
	regexpsAllow := make([]*regexp.Regexp, 0, len(config.AllowedBrowsers))
	regexpsDeny := make([]*regexp.Regexp, 0)
	osRegexpsAllow := make([]*regexp.Regexp, 0, len(config.AllowedOSTypes))

	// Compile browser patterns into allow/deny buckets
	for _, bc := range config.AllowedBrowsers {
		re, err := regexp.Compile(maybeAnchor(bc.Regex, config.StrictMatch))
		if err != nil {
			return nil, fmt.Errorf("error compiling browser regex for %s: %w", bc.Name, err)
		}
		if bc.Action == ActionDeny {
			regexpsDeny = append(regexpsDeny, re)
		} else {
			regexpsAllow = append(regexpsAllow, re)
		}
	}

	// Compile regex patterns for allowed OS types (if provided)
	for _, osPattern := range config.AllowedOSTypes {
		re, err := regexp.Compile(maybeAnchor(osPattern, config.StrictMatch))
		if err != nil {
			return nil, fmt.Errorf("error compiling OS regex %q: %w", osPattern, err)
		}
		osRegexpsAllow = append(osRegexpsAllow, re)
	}

	b := &BlockUserAgents{
		name:           name,
		next:           next,
		regexpsAllow:   regexpsAllow,
		regexpsDeny:    regexpsDeny,
		osRegexpsAllow: osRegexpsAllow,
		clientIPHeader: config.ClientIPHeader,
		bypassPaths:    config.BypassPaths,
		logOnly:        config.Mode == ModeLogOnly,
		logSampleN:     uint64(config.LogSampleN),
	}

	// Periodic metrics summary, gated by config. The goroutine exits when
	// ctx is cancelled (Traefik plugin teardown), so reloads do not leak.
	if config.MetricsLogInterval != "" {
		// Already validated parseable in ValidateConfig.
		interval, _ := time.ParseDuration(config.MetricsLogInterval)
		if interval > 0 {
			go b.metricsLogLoop(ctx, interval)
		}
	}

	return b, nil
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
	b.cntTotal.Add(1)

	// Bypass paths skip all checks.
	for _, prefix := range b.bypassPaths {
		if strings.HasPrefix(req.URL.Path, prefix) {
			b.cntBypass.Add(1)
			b.next.ServeHTTP(res, req)
			return
		}
	}

	userAgent := req.UserAgent()
	if userAgent == "" {
		b.deny(res, req, "No User-Agent", &b.cntNoUA)
		return
	}

	// Deny rules first — a match here blocks regardless of allow rules.
	for _, re := range b.regexpsDeny {
		if re.MatchString(userAgent) {
			b.deny(res, req, "Denied Browser", &b.cntDenied)
			return
		}
	}

	// Allow rules — at least one must match.
	browserMatch := false
	for _, re := range b.regexpsAllow {
		if re.MatchString(userAgent) {
			browserMatch = true
			break
		}
	}
	if !browserMatch {
		b.deny(res, req, "Unsupported Browser", &b.cntBadBrowser)
		return
	}

	// OS rules if configured — at least one must match.
	if len(b.osRegexpsAllow) > 0 {
		osMatch := false
		for _, re := range b.osRegexpsAllow {
			if re.MatchString(userAgent) {
				osMatch = true
				break
			}
		}
		if !osMatch {
			b.deny(res, req, "Unsupported OS", &b.cntBadOS)
			return
		}
	}

	b.cntAllowed.Add(1)
	b.next.ServeHTTP(res, req)
}

// deny logs the block decision (subject to per-reason sampling) and either
// short-circuits with 403 (enforce mode) or forwards to the next handler
// (log-only mode). counter is the per-reason atomic that drives both metrics
// and the sampling stride.
func (b *BlockUserAgents) deny(res http.ResponseWriter, req *http.Request, reason string, counter *atomic.Uint64) {
	n := counter.Add(1)
	if b.shouldLog(n) {
		b.logBlockedRequest(req, reason)
	}
	if b.logOnly {
		b.next.ServeHTTP(res, req)
		return
	}
	res.WriteHeader(http.StatusForbidden)
}

// shouldLog returns true if the n-th occurrence of a given reason should be
// logged under the current sampling stride. Stride 0 or 1 logs every line.
// Stride N>1 logs the 1st, (N+1)-th, (2N+1)-th, ... occurrence per reason.
func (b *BlockUserAgents) shouldLog(n uint64) bool {
	if b.logSampleN <= 1 {
		return true
	}
	return n%b.logSampleN == 1
}

// metricsLogLoop emits a single JSON summary line every interval until ctx
// is cancelled. Started by New() when MetricsLogInterval is configured.
func (b *BlockUserAgents) metricsLogLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.logMetricsSnapshot()
		}
	}
}

// logMetricsSnapshot reads the atomic counters and emits one JSON log line
// prefixed with the middleware name. Cumulative numbers — operators diff
// successive snapshots to compute rates.
func (b *BlockUserAgents) logMetricsSnapshot() {
	snap := metricsSnapshot{
		Total:          b.cntTotal.Load(),
		Allowed:        b.cntAllowed.Load(),
		Bypass:         b.cntBypass.Load(),
		BlockedNoUA:    b.cntNoUA.Load(),
		BlockedDeny:    b.cntDenied.Load(),
		BlockedBrowser: b.cntBadBrowser.Load(),
		BlockedOS:      b.cntBadOS.Load(),
	}
	out, err := json.Marshal(snap)
	if err == nil {
		log.Printf("%s: metrics - %s", b.name, out)
	}
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

// logBlockedRequest logs details of a blocked request. In log-only mode the
// "Blocked" prefix becomes "Would-Block" so the log clearly distinguishes a
// staged rule from an enforced one.
func (b *BlockUserAgents) logBlockedRequest(req *http.Request, reason string) {
	message := &BlockUserAgentsMessage{
		UserAgent:  req.UserAgent(),
		RemoteAddr: b.clientIP(req),
		Host:       req.Host,
		RequestURI: req.URL.Path,
	}
	verb := "Blocked"
	if b.logOnly {
		verb = "Would-Block"
	}
	jsonMessage, err := json.Marshal(message)
	if err == nil {
		log.Printf("%s: %s (%s) - %s", b.name, verb, reason, jsonMessage)
	} else {
		log.Printf("%s: %s (%s) - %s", b.name, verb, reason, req.UserAgent())
	}
}
