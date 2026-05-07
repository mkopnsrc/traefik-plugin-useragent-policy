package traefik_plugin_block_useragents

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BlockUserAgents{clientIPHeader: tt.headerName}
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
