package cdp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestChromeHeaders launches a real headless Chrome, navigates to
// httpbin.org/headers, and reads the page body. The returned JSON lists the
// request headers Chrome actually sent — these should be the genuine Chrome
// client-hint headers (sec-ch-ua, sec-ch-ua-platform, sec-ch-ua-mobile, ...),
// proving the fingerprint comes from real Chrome rather than a Go HTTP client.
//
// Run with:
//
//	go test -v -run TestChromeHeaders ./cdp/
func TestChromeHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping chrome launch test in short mode")
	}

	s, err := LaunchChrome("")
	if err != nil {
		t.Fatalf("LaunchChrome: %v\nstderr:\n%s", err, safeStderr(s))
	}
	defer s.Close()

	if err := s.Navigate("https://httpbin.org/headers"); err != nil {
		t.Fatalf("Navigate: %v", err)
	}

	// Give the dynamic JSON a moment to render, then pull the body text.
	deadline := time.Now().Add(15 * time.Second)
	var bodyText string
	for time.Now().Before(deadline) {
		v, err := s.Evaluate("document.body.innerText")
		if err != nil {
			t.Logf("evaluate retry: %v", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			bodyText = s
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if bodyText == "" {
		t.Fatalf("empty body after navigation; stderr:\n%s", safeStderr(s))
	}

	t.Logf("=== httpbin.org/headers (as seen by real Chrome) ===\n%s", bodyText)

	// Parse the JSON and assert on the Chrome-specific client hints.
	var parsed struct {
		Headers map[string]string `json:"headers"`
	}
	if err := json.Unmarshal([]byte(bodyText), &parsed); err != nil {
		t.Fatalf("parse httpbin response: %v\nraw: %s", err, bodyText)
	}

	// sec-ch-ua is the canonical signal that this is genuine Chrome. httpbin
	// lowercases + title-cases header names as "Sec-Ch-Ua".
	want := []string{"Sec-Ch-Ua", "User-Agent"}
	for _, h := range want {
		if _, ok := parsed.Headers[h]; !ok {
			t.Errorf("expected header %q in response, got: %v", h, parsed.Headers)
		} else {
			t.Logf("  %s: %s", h, parsed.Headers[h])
		}
	}

	// The User-Agent must look like real Chrome, not a Go client.
	if ua, ok := parsed.Headers["User-Agent"]; ok {
		if !strings.Contains(ua, "Chrome") {
			t.Errorf("User-Agent does not look like Chrome: %q", ua)
		}
	}
}

// TestChromeFetch exercises FetchViaChrome so the in-page fetch() path is
// also verified end to end.
func TestChromeFetch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping chrome launch test in short mode")
	}

	s, err := LaunchChrome("")
	if err != nil {
		t.Fatalf("LaunchChrome: %v", err)
	}
	defer s.Close()

	// Need a page origin first; navigate somewhere with a real origin so that
	// fetch's relative/absolute URL resolution and CORS behave predictably.
	if err := s.Navigate("https://httpbin.org/get"); err != nil {
		t.Fatalf("Navigate: %v", err)
	}

	status, body, err := FetchViaChrome(s, "https://httpbin.org/headers", "GET", nil, "")
	if err != nil {
		t.Fatalf("FetchViaChrome: %v", err)
	}
	if status != 200 {
		t.Fatalf("expected status 200, got %d (body: %s)", status, body)
	}

	t.Logf("=== FetchViaChrome status=%d ===\n%s", status, body)

	var parsed struct {
		Headers map[string]string `json:"headers"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("parse fetch response: %v", err)
	}
	if ua, ok := parsed.Headers["User-Agent"]; ok {
		t.Logf("fetch User-Agent: %s", ua)
		if !strings.Contains(ua, "Chrome") {
			t.Errorf("fetch User-Agent not Chrome: %q", ua)
		}
	} else {
		t.Errorf("fetch response missing User-Agent: %v", parsed.Headers)
	}
}

func safeStderr(s *ChromeSession) string {
	if s == nil {
		return "(no session)"
	}
	return s.Stderr()
}
