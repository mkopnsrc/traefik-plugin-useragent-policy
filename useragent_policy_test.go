package traefik_plugin_useragent_policy

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func nopHandler() http.Handler {
	return http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
}

func TestNew_RejectsEmptyAllowedBrowsers(t *testing.T) {
	_, err := New(context.Background(), nopHandler(), CreateConfig(), "test")
	if err == nil {
		t.Fatal("expected error for empty AllowedBrowsers, got nil")
	}
}

func TestNew_RejectsBrowserMissingRegex(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome"}}
	_, err := New(context.Background(), nopHandler(), cfg, "test")
	if err == nil {
		t.Fatal("expected error for browser missing regex, got nil")
	}
}

func TestNew_RejectsInvalidBrowserRegex(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/[0-"}}
	_, err := New(context.Background(), nopHandler(), cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid browser regex, got nil")
	}
}

func TestNew_RejectsInvalidOSRegex(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/130"}}
	cfg.AllowedOSTypes = []string{"Linux", "[invalid"}
	_, err := New(context.Background(), nopHandler(), cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid OS regex, got nil")
	}
}

func TestServeHTTP(t *testing.T) {
	tests := []struct {
		name            string
		userAgent       string
		setUserAgent    bool
		allowedBrowsers []BrowserConfig
		allowedOSTypes  []string
		wantStatus      int
		wantNextCalled  bool
	}{
		{
			name:            "empty UA is blocked",
			setUserAgent:    false,
			allowedBrowsers: []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}},
			wantStatus:      http.StatusForbidden,
			wantNextCalled:  false,
		},
		{
			name:            "matching browser passes when no OS configured",
			userAgent:       "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36",
			setUserAgent:    true,
			allowedBrowsers: []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}},
			wantStatus:      http.StatusOK,
			wantNextCalled:  true,
		},
		{
			name:            "non-matching browser is blocked",
			userAgent:       "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",
			setUserAgent:    true,
			allowedBrowsers: []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}},
			wantStatus:      http.StatusForbidden,
			wantNextCalled:  false,
		},
		{
			name:            "matching browser and matching OS pass",
			userAgent:       "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0.0.0 Safari/537.36",
			setUserAgent:    true,
			allowedBrowsers: []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}},
			allowedOSTypes:  []string{`Windows NT 10\.0`},
			wantStatus:      http.StatusOK,
			wantNextCalled:  true,
		},
		{
			name:            "matching browser but non-matching OS is blocked",
			userAgent:       "Mozilla/5.0 (Macintosh) Chrome/130.0.0.0 Safari/537.36",
			setUserAgent:    true,
			allowedBrowsers: []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}},
			allowedOSTypes:  []string{`Windows NT 10\.0`, `Linux`},
			wantStatus:      http.StatusForbidden,
			wantNextCalled:  false,
		},
		{
			name:            "first matching browser among many wins",
			userAgent:       "Mozilla/5.0 Firefox/132.0",
			setUserAgent:    true,
			allowedBrowsers: []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}, {Name: "Firefox", Regex: "Firefox/13[1-5]"}},
			wantStatus:      http.StatusOK,
			wantNextCalled:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CreateConfig()
			cfg.AllowedBrowsers = tt.allowedBrowsers
			cfg.AllowedOSTypes = tt.allowedOSTypes

			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			handler, err := New(context.Background(), next, cfg, "test")
			if err != nil {
				t.Fatalf("New returned error: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			if tt.setUserAgent {
				req.Header.Set("User-Agent", tt.userAgent)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status: got %d, want %d", rec.Code, tt.wantStatus)
			}
			if nextCalled != tt.wantNextCalled {
				t.Errorf("next called: got %v, want %v", nextCalled, tt.wantNextCalled)
			}
		})
	}
}

func TestMaybeAnchor(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		strict  bool
		want    string
	}{
		{name: "strict false returns pattern unchanged", pattern: "Chrome/13[0-3]", strict: false, want: "Chrome/13[0-3]"},
		{name: "strict true wraps with word boundary and group", pattern: "Chrome/13[0-3]", strict: true, want: `\b(?:Chrome/13[0-3])`},
		{name: "strict true preserves alternation semantics", pattern: "Chrome|Firefox", strict: true, want: `\b(?:Chrome|Firefox)`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maybeAnchor(tt.pattern, tt.strict); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestServeHTTP_StrictMatch verifies that StrictMatch prevents
// partial-word matches that would otherwise leak through unanchored regex.
// Note: this does NOT prevent active spoofing — see README "Security".
func TestServeHTTP_StrictMatch(t *testing.T) {
	tests := []struct {
		name           string
		userAgent      string
		strictMatch    bool
		wantNextCalled bool
	}{
		{
			name:           "non-strict: partial-word match leaks through",
			userAgent:      "MyChrome/130 not-actually-chrome",
			strictMatch:    false,
			wantNextCalled: true,
		},
		{
			name:           "strict: partial-word match is blocked",
			userAgent:      "MyChrome/130 not-actually-chrome",
			strictMatch:    true,
			wantNextCalled: false,
		},
		{
			name:           "strict: word-bounded UA still matches",
			userAgent:      "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36",
			strictMatch:    true,
			wantNextCalled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CreateConfig()
			cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}}
			cfg.StrictMatch = tt.strictMatch

			nextCalled := false
			next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { nextCalled = true })

			handler, err := New(context.Background(), next, cfg, "test")
			if err != nil {
				t.Fatalf("New returned error: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if nextCalled != tt.wantNextCalled {
				t.Errorf("next called: got %v, want %v", nextCalled, tt.wantNextCalled)
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		headerVal  string
		remoteAddr string
		want       string
	}{
		{name: "no header configured falls back to RemoteAddr", headerName: "", remoteAddr: "10.0.0.1:1234", want: "10.0.0.1:1234"},
		{name: "header configured but absent falls back to RemoteAddr", headerName: "X-Forwarded-For", remoteAddr: "10.0.0.1:1234", want: "10.0.0.1:1234"},
		{name: "single value in header is used", headerName: "X-Forwarded-For", headerVal: "203.0.113.1", remoteAddr: "10.0.0.1:1234", want: "203.0.113.1"},
		{name: "comma-separated picks leftmost trimmed", headerName: "X-Forwarded-For", headerVal: "203.0.113.1, 198.51.100.7, 10.0.0.5", remoteAddr: "10.0.0.1:1234", want: "203.0.113.1"},
		{name: "leading whitespace in single value is trimmed", headerName: "X-Forwarded-For", headerVal: "  203.0.113.1  ", remoteAddr: "10.0.0.1:1234", want: "203.0.113.1"},
		{name: "leading whitespace before comma is trimmed", headerName: "X-Forwarded-For", headerVal: "  203.0.113.1  , 10.0.0.5", remoteAddr: "10.0.0.1:1234", want: "203.0.113.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &UserAgentPolicy{clientIPHeader: tt.headerName}
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.headerVal != "" {
				req.Header.Set(tt.headerName, tt.headerVal)
			}
			if got := b.clientIP(req); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestLogRedaction verifies that the blocked-request log line contains the
// request path but NOT the query string, which may carry sensitive tokens.
func TestLogRedaction(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}}

	handler, err := New(context.Background(), nopHandler(), cfg, "test")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOut)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/user?token=secret-abc-123&session=xyz", nil)
	req.Header.Set("User-Agent", "WrongBrowser/1.0")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	if !strings.Contains(out, "/api/user") {
		t.Errorf("log should contain request path /api/user, got: %s", out)
	}
	if strings.Contains(out, "token=secret-abc-123") || strings.Contains(out, "session=xyz") {
		t.Errorf("log must NOT contain query-string secrets, got: %s", out)
	}
}

func TestServeHTTP_ClientIPHeaderInLog(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}}
	cfg.ClientIPHeader = "X-Forwarded-For"

	handler, err := New(context.Background(), nopHandler(), cfg, "test")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOut)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	req.Header.Set("User-Agent", "WrongBrowser/1.0")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	if !strings.Contains(out, `"ip":"203.0.113.7"`) {
		t.Errorf("log should report client IP from X-Forwarded-For, got: %s", out)
	}
	if strings.Contains(out, "10.0.0.1:5555") {
		t.Errorf("log should NOT include proxy RemoteAddr when header is configured, got: %s", out)
	}
}

// Validation tests for the new fields.

func TestNew_RejectsInvalidMode(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/130"}}
	cfg.Mode = "monitor"
	if _, err := New(context.Background(), nopHandler(), cfg, "test"); err == nil {
		t.Fatal("expected error for invalid mode, got nil")
	}
}

func TestNew_RejectsInvalidAction(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/130", Action: "challenge"}}
	if _, err := New(context.Background(), nopHandler(), cfg, "test"); err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}
}

func TestNew_RejectsDenyOnlyConfig(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "BadBot", Regex: "EvilBot", Action: ActionDeny}}
	if _, err := New(context.Background(), nopHandler(), cfg, "test"); err == nil {
		t.Fatal("expected error for deny-only config, got nil")
	}
}

func TestNew_AcceptsExplicitAllowAction(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/130", Action: ActionAllow}}
	if _, err := New(context.Background(), nopHandler(), cfg, "test"); err != nil {
		t.Fatalf("expected no error for action=allow, got %v", err)
	}
}

// TestServeHTTP_DenyPrecedence verifies that deny rules block UAs that would
// otherwise match an allow rule.
func TestServeHTTP_DenyPrecedence(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{
		{Name: "Chrome", Regex: "Chrome/13[0-3]", Action: ActionAllow},
		{Name: "ChromeHeadless", Regex: "HeadlessChrome", Action: ActionDeny},
	}

	nextCalled := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { nextCalled = true })
	handler, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 HeadlessChrome/130.0.0.0 Safari/537.36 Chrome/130.0")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", rec.Code)
	}
	if nextCalled {
		t.Error("next must not be called when a deny rule matches")
	}
}

// TestServeHTTP_BypassPaths verifies that bypass-prefix paths skip all checks.
func TestServeHTTP_BypassPaths(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		userAgent      string
		setUserAgent   bool
		wantNextCalled bool
		wantStatus     int
	}{
		{name: "exact bypass match skips checks even without UA", path: "/healthz", setUserAgent: false, wantNextCalled: true, wantStatus: http.StatusOK},
		{name: "prefix bypass match skips checks even with bad UA", path: "/.well-known/acme-challenge/token", userAgent: "WrongBrowser/1.0", setUserAgent: true, wantNextCalled: true, wantStatus: http.StatusOK},
		{name: "non-bypass path with bad UA still blocked", path: "/api/data", userAgent: "WrongBrowser/1.0", setUserAgent: true, wantNextCalled: false, wantStatus: http.StatusForbidden},
		{name: "non-bypass path with good UA passes through normal flow", path: "/api/data", userAgent: "Mozilla/5.0 Chrome/130.0", setUserAgent: true, wantNextCalled: true, wantStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CreateConfig()
			cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}}
			cfg.BypassPaths = []string{"/healthz", "/.well-known/"}

			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})
			handler, err := New(context.Background(), next, cfg, "test")
			if err != nil {
				t.Fatalf("New returned error: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "http://example.com"+tt.path, nil)
			if tt.setUserAgent {
				req.Header.Set("User-Agent", tt.userAgent)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if nextCalled != tt.wantNextCalled {
				t.Errorf("next called: got %v, want %v", nextCalled, tt.wantNextCalled)
			}
			if rec.Code != tt.wantStatus {
				t.Errorf("status: got %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

// TestNew_RejectsInvalidMetricsLogInterval verifies that an unparseable
// duration string in MetricsLogInterval is caught at config-validation time
// rather than silently producing a no-op goroutine.
func TestNew_RejectsInvalidMetricsLogInterval(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/130"}}
	cfg.MetricsLogInterval = "not-a-duration"
	if _, err := New(context.Background(), nopHandler(), cfg, "test"); err == nil {
		t.Fatal("expected error for invalid metricsLogInterval, got nil")
	}
}

func TestNew_RejectsNegativeLogSampleN(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/130"}}
	cfg.LogSampleN = -1
	if _, err := New(context.Background(), nopHandler(), cfg, "test"); err == nil {
		t.Fatal("expected error for negative logSampleN, got nil")
	}
}

// TestNew_RejectsEmptyBypassPath catches the misconfiguration that would
// otherwise silently disable all UA checks: strings.HasPrefix(anyPath, "")
// returns true, so an empty entry in BypassPaths matches every request.
// A YAML typo like `bypassPaths: ["", "/healthz"]` must fail loudly at
// startup rather than letting traffic through.
func TestNew_RejectsEmptyBypassPath(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/130"}}
	cfg.BypassPaths = []string{"/healthz", ""}
	if _, err := New(context.Background(), nopHandler(), cfg, "test"); err == nil {
		t.Fatal("expected error for empty bypassPaths entry, got nil")
	}
}

// TestServeHTTP_CountersIncrement drives traffic through every code path
// and verifies the atomic counters end up with the right totals.
func TestServeHTTP_CountersIncrement(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{
		{Name: "Chrome", Regex: "Chrome/13[0-3]"},
		{Name: "BadBot", Regex: "EvilBot", Action: ActionDeny},
	}
	cfg.AllowedOSTypes = []string{"Linux"}
	cfg.BypassPaths = []string{"/healthz"}

	handler, err := New(context.Background(), nopHandler(), cfg, "test")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	b := handler.(*UserAgentPolicy)

	// Suppress log output during the noisy counter exercise.
	origOut := log.Writer()
	log.SetOutput(&bytes.Buffer{})
	defer log.SetOutput(origOut)

	type req struct {
		path string
		ua   string
	}
	for _, r := range []req{
		{"/healthz", ""}, // bypass (no UA needed)
		{"/healthz", "Mozilla/5.0 Chrome/130 Linux"}, // bypass
		{"/api", ""},                             // no UA -> blocked
		{"/api", "EvilBot/1.0"},                  // deny rule -> blocked
		{"/api", "OldBrowser/1"},                 // unsupported browser -> blocked
		{"/api", "Mozilla/5.0 Chrome/130 Mac"},   // browser ok, OS bad
		{"/api", "Mozilla/5.0 Chrome/130 Linux"}, // allowed
		{"/api", "Mozilla/5.0 Chrome/132 Linux"}, // allowed
	} {
		httpReq := httptest.NewRequest(http.MethodGet, "http://example.com"+r.path, nil)
		if r.ua != "" {
			httpReq.Header.Set("User-Agent", r.ua)
		}
		handler.ServeHTTP(httptest.NewRecorder(), httpReq)
	}

	want := map[string]uint64{
		"total":           8,
		"allowed":         2,
		"bypass":          2,
		"blocked_no_ua":   1,
		"blocked_deny":    1,
		"blocked_browser": 1,
		"blocked_os":      1,
	}
	got := map[string]uint64{
		"total":           atomic.LoadUint64(&b.cntTotal),
		"allowed":         atomic.LoadUint64(&b.cntAllowed),
		"bypass":          atomic.LoadUint64(&b.cntBypass),
		"blocked_no_ua":   atomic.LoadUint64(&b.cntNoUA),
		"blocked_deny":    atomic.LoadUint64(&b.cntDenied),
		"blocked_browser": atomic.LoadUint64(&b.cntBadBrowser),
		"blocked_os":      atomic.LoadUint64(&b.cntBadOS),
	}
	for k, want := range want {
		if got[k] != want {
			t.Errorf("counter %q: got %d, want %d", k, got[k], want)
		}
	}
}

// TestShouldLog verifies the per-reason sampling stride directly.
func TestShouldLog(t *testing.T) {
	tests := []struct {
		stride   uint64
		n        uint64
		wantTrue bool
	}{
		{stride: 0, n: 1, wantTrue: true},
		{stride: 0, n: 999, wantTrue: true},
		{stride: 1, n: 1, wantTrue: true},
		{stride: 1, n: 42, wantTrue: true},
		{stride: 100, n: 1, wantTrue: true},   // first occurrence always logs
		{stride: 100, n: 50, wantTrue: false}, // suppressed
		{stride: 100, n: 100, wantTrue: false},
		{stride: 100, n: 101, wantTrue: true}, // 100*1 + 1
		{stride: 100, n: 201, wantTrue: true}, // 100*2 + 1
		{stride: 100, n: 200, wantTrue: false},
	}
	for _, tt := range tests {
		b := &UserAgentPolicy{logSampleN: tt.stride}
		if got := b.shouldLog(tt.n); got != tt.wantTrue {
			t.Errorf("shouldLog(stride=%d, n=%d): got %v, want %v", tt.stride, tt.n, got, tt.wantTrue)
		}
	}
}

// TestServeHTTP_LogSamplingSuppresses verifies that with LogSampleN > 1 the
// log line emission rate per reason is throttled, while metrics counters
// still increment for every block. The first occurrence of each reason MUST
// log (operators need to see when a reason starts firing) — that's pinned
// down with the after-request-1 / after-request-2 buffer-length checks
// rather than only via the final count, so a future change to the sampling
// formula that still happens to produce 2 lines per 10 requests would still
// fail this test if it skipped the first occurrence.
func TestServeHTTP_LogSamplingSuppresses(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}}
	cfg.LogSampleN = 5

	handler, err := New(context.Background(), nopHandler(), cfg, "test")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	b := handler.(*UserAgentPolicy)

	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOut)

	send := func(ua string) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	// First blocked request must produce a log line — operators rely on
	// seeing when a reason starts firing, even with aggressive sampling.
	send("OldBrowser/1.0")
	if buf.Len() == 0 {
		t.Fatal("first blocked request produced no log line; first occurrence per reason must always log")
	}
	afterFirst := buf.Len()

	// Second blocked request (n=2 with stride=5) must NOT add a log line.
	send("OldBrowser/1.0")
	if buf.Len() != afterFirst {
		t.Errorf("second blocked request produced an extra log line; expected stride=5 to suppress n=2")
	}

	// Send 8 more to bring the total to 10. Combined with the first 2 we
	// expect exactly 2 lines for 'Unsupported Browser' (n=1 and n=6).
	for i := 0; i < 8; i++ {
		send("OldBrowser/1.0")
	}
	// And 10 no-UA requests, interleaved-effect verified by per-reason
	// counter independence below.
	for i := 0; i < 10; i++ {
		send("")
	}

	// All blocks must be counted regardless of sampling.
	if got := atomic.LoadUint64(&b.cntBadBrowser); got != 10 {
		t.Errorf("cntBadBrowser: got %d, want 10", got)
	}
	if got := atomic.LoadUint64(&b.cntNoUA); got != 10 {
		t.Errorf("cntNoUA: got %d, want 10", got)
	}

	browserLines := strings.Count(buf.String(), "Unsupported Browser")
	noUALines := strings.Count(buf.String(), "No User-Agent")
	if browserLines != 2 {
		t.Errorf("expected 2 'Unsupported Browser' log lines (n=1,6 of 10 with stride=5), got %d", browserLines)
	}
	if noUALines != 2 {
		t.Errorf("expected 2 'No User-Agent' log lines (n=1,6 of 10 with stride=5), got %d", noUALines)
	}
}

// TestLogMetricsSnapshot verifies the JSON shape of a single emitted summary
// line. Avoids fighting goroutine timing — calls the helper directly.
func TestLogMetricsSnapshot(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}}

	handler, err := New(context.Background(), nopHandler(), cfg, "test")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	b := handler.(*UserAgentPolicy)
	atomic.StoreUint64(&b.cntTotal, 42)
	atomic.StoreUint64(&b.cntAllowed, 30)
	atomic.StoreUint64(&b.cntBypass, 2)
	atomic.StoreUint64(&b.cntNoUA, 3)
	atomic.StoreUint64(&b.cntDenied, 4)
	atomic.StoreUint64(&b.cntBadBrowser, 2)
	atomic.StoreUint64(&b.cntBadOS, 1)

	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOut)

	b.logMetricsSnapshot()

	out := buf.String()
	idx := strings.Index(out, "{")
	if idx < 0 {
		t.Fatalf("no JSON in metrics log line: %s", out)
	}
	var snap metricsSnapshot
	if err := json.Unmarshal([]byte(strings.TrimSpace(out[idx:])), &snap); err != nil {
		t.Fatalf("metrics line is not valid JSON: %v\n%s", err, out)
	}
	want := metricsSnapshot{Total: 42, Allowed: 30, Bypass: 2, BlockedNoUA: 3, BlockedDeny: 4, BlockedBrowser: 2, BlockedOS: 1}
	if snap != want {
		t.Errorf("snapshot: got %+v, want %+v", snap, want)
	}
}

// TestMetricsLogLoop_RespectsContextCancellation is the load-bearing test
// for the goroutine lifecycle: when the context passed to New is canceled
// (Traefik plugin teardown), the metrics goroutine must exit. Otherwise
// every config reload leaks one goroutine.
func TestMetricsLogLoop_RespectsContextCancellation(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}}

	handler, err := New(context.Background(), nopHandler(), cfg, "test")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	b := handler.(*UserAgentPolicy)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		b.metricsLogLoop(ctx, 10*time.Millisecond)
		close(done)
	}()

	// Let it tick at least once.
	time.Sleep(25 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// goroutine exited as required
	case <-time.After(time.Second):
		t.Fatal("metricsLogLoop did not exit within 1s of context cancellation — goroutine leak risk")
	}
}

// TestServeHTTP_LogOnlyMode is the load-bearing assertion for mode=log-only:
// requests that would have been blocked must still reach the next handler,
// and the log line must clearly mark them as a would-block (not an enforced
// block) so operators can distinguish staged rules from active ones.
func TestServeHTTP_LogOnlyMode(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedBrowsers = []BrowserConfig{{Name: "Chrome", Regex: "Chrome/13[0-3]"}}
	cfg.Mode = ModeLogOnly

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusTeapot) // distinctive so we know it came from next
	})
	handler, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOut)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("User-Agent", "WrongBrowser/1.0")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("log-only mode must forward would-be-blocked requests to next; next was not called")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status: got %d, want %d (next handler's response should win)", rec.Code, http.StatusTeapot)
	}
	out := buf.String()
	if !strings.Contains(out, "Would-Block") {
		t.Errorf("log should contain 'Would-Block' marker in log-only mode, got: %s", out)
	}
	if strings.Contains(out, "Blocked (") {
		t.Errorf("log must NOT use 'Blocked' verb in log-only mode (would confuse operators), got: %s", out)
	}
}
