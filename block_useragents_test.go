package traefik_plugin_block_useragents

import (
	"context"
	"net/http"
	"net/http/httptest"
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
