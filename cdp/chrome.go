// Package cdp provides a minimal Chrome DevTools Protocol (CDP) client that
// drives a real, standalone headless Chrome process over its DevTools
// WebSocket.
//
// The point of this package is to obtain the *exact* Chrome TLS / HTTP-2 /
// Client-Hints fingerprint (BoringSSL + Chrome's net stack) for HTTP requests
// made from within the page context via Runtime.evaluate-driven fetch() calls.
// No browser-automation framework (Playwright / Puppeteer / Selenium / chromedp)
// is used: we just spawn the Chrome process and speak the CDP JSON wire protocol
// directly over a single WebSocket connection.
//
// For authorized security testing only.
package cdp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ChromeSession is a live headless Chrome process plus the CDP WebSocket used
// to drive it. A single page target is created and attached (flattened) so
// that Page / Runtime / Network commands run in that page's context.
type ChromeSession struct {
	cmd *exec.Cmd

	ws      *websocket.Conn
	writeMu sync.Mutex // serializes WebSocket writes

	mu        sync.Mutex
	nextID    int
	pending   map[int]chan *cdpResponse
	sessionID string // flattened session bound to the page target

	lastLoadAt time.Time // updated on Page.loadEventFired
	cancel     context.CancelFunc

	stderr bytes.Buffer // retains remaining chrome stderr for debugging
}

// cdpRequest is the outgoing CDP envelope.
type cdpRequest struct {
	ID        int         `json:"id"`
	Method    string      `json:"method"`
	Params    interface{} `json:"params,omitempty"`
	SessionID string      `json:"sessionId,omitempty"`
}

// cdpResponse is the generic incoming CDP envelope (response or event).
type cdpResponse struct {
	ID        int             `json:"id"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *cdpError       `json:"error,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
}

type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

const (
	cdpTimeout    = 60 * time.Second
	launchTimeout = 20 * time.Second
)

// findChrome locates a Chrome/Chromium binary. The Playwright-managed build is
// preferred (newest version first), then falls back to system installs.
func findChrome() (string, error) {
	var candidates []string

	if home, err := os.UserHomeDir(); err == nil {
		matches, _ := filepath.Glob(filepath.Join(home, ".cache", "ms-playwright", "chromium-*", "chrome-linux64", "chrome"))
		sort.Sort(sort.Reverse(sort.StringSlice(matches)))
		candidates = append(candidates, matches...)
	}
	candidates = append(candidates,
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/chromium-browser",
		"/usr/bin/chromium",
	)

	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	return "", errors.New("chrome binary not found (looked in ~/.cache/ms-playwright, /usr/bin/{google-chrome,chromium*})")
}

// LaunchChrome starts a headless Chrome process, connects to its DevTools
// WebSocket, creates a page target, and attaches to it. If proxyURL is empty
// no proxy is configured.
func LaunchChrome(proxyURL string) (*ChromeSession, error) {
	binary, err := findChrome()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	args := []string{
		"--headless=new",
		"--remote-debugging-port=0",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-extensions",
		"--no-first-run",
		"--disable-dev-shm-usage",
	}
	if proxyURL != "" {
		args = append(args, "--proxy-server="+proxyURL)
	}
	args = append(args, "about:blank") // guarantee an initial page exists

	cmd := exec.CommandContext(ctx, binary, args...)

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start chrome (%s): %w", binary, err)
	}

	s := &ChromeSession{
		cmd:     cmd,
		pending: make(map[int]chan *cdpResponse),
		cancel:  cancel,
	}

	// Chrome prints "DevTools listening on ws://127.0.0.1:PORT/devtools/browser/UUID"
	// to stderr. Capture it, then keep draining stderr so Chrome never blocks.
	wsURLCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		found := false
		for scanner.Scan() {
			line := scanner.Text()
			if !found {
				if strings.Contains(line, "DevTools listening on") {
					if i := strings.Index(line, "ws://"); i >= 0 {
						u := strings.TrimSpace(line[i:])
						found = true
						select {
						case wsURLCh <- u:
						default:
						}
						continue
					}
				}
			}
			// Keep recent stderr for diagnostics.
			s.mu.Lock()
			if s.stderr.Len() < 64*1024 {
				s.stderr.WriteString(line)
				s.stderr.WriteByte('\n')
			}
			s.mu.Unlock()
		}
	}()

	var wsURL string
	select {
	case wsURL = <-wsURLCh:
	case <-time.After(launchTimeout):
		s.kill()
		return nil, fmt.Errorf("timed out waiting for Chrome DevTools URL. stderr:\n%s", s.Stderr())
	}

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		s.kill()
		return nil, fmt.Errorf("dial devtools ws %s: %w", wsURL, err)
	}
	s.ws = conn

	// Don't keep the goroutine above alive writing to s.stderr racing; it's fine.
	go s.readLoop()

	// Create a page target and attach with the flattened protocol so all
	// subsequent commands run against that page over the same socket.
	if err := s.initPageTarget(); err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}

// initPageTarget creates a fresh page target and binds a flattened session to it.
func (s *ChromeSession) initPageTarget() error {
	res, err := s.send("Target.createTarget", map[string]string{"url": "about:blank"})
	if err != nil {
		return fmt.Errorf("create target: %w", err)
	}
	var ct struct {
		TargetID string `json:"targetId"`
	}
	if err := json.Unmarshal(res, &ct); err != nil || ct.TargetID == "" {
		return fmt.Errorf("create target: bad response %s", string(res))
	}

	res, err = s.send("Target.attachToTarget", map[string]interface{}{
		"targetId": ct.TargetID,
		"flatten":  true,
	})
	if err != nil {
		return fmt.Errorf("attach target: %w", err)
	}
	var at struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(res, &at); err != nil || at.SessionID == "" {
		return fmt.Errorf("attach target: bad response %s", string(res))
	}

	s.mu.Lock()
	s.sessionID = at.SessionID
	s.mu.Unlock()

	// Enable the domains we use. Errors here are non-fatal for evaluate-only
	// flows, but Page.enable is required to receive load events.
	if _, err := s.send("Page.enable", nil); err != nil {
		return fmt.Errorf("page.enable: %w", err)
	}
	_, _ = s.send("Network.enable", nil)
	_, _ = s.send("Runtime.enable", nil)
	return nil
}

// readLoop drains the WebSocket, routing responses to waiters and tracking
// the page load event.
func (s *ChromeSession) readLoop() {
	for {
		_, data, err := s.ws.ReadMessage()
		if err != nil {
			s.failPending(err)
			return
		}
		var msg cdpResponse
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		// A message with an id is a response to one of our requests.
		if msg.ID != 0 {
			s.mu.Lock()
			ch, ok := s.pending[msg.ID]
			delete(s.pending, msg.ID)
			s.mu.Unlock()
			if ok {
				ch <- &msg
			}
			continue
		}
		// Otherwise it's an event.
		if msg.Method == "Page.loadEventFired" {
			s.mu.Lock()
			s.lastLoadAt = time.Now()
			s.mu.Unlock()
		}
	}
}

// allocID returns a monotonic CDP message id.
func (s *ChromeSession) allocID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	return s.nextID
}

// send issues a CDP command and waits for the matching response. Commands are
// automatically tagged with the page session id when one is bound.
func (s *ChromeSession) send(method string, params interface{}) (json.RawMessage, error) {
	id := s.allocID()
	req := cdpRequest{ID: id, Method: method, Params: params}
	s.mu.Lock()
	if s.sessionID != "" {
		req.SessionID = s.sessionID
	}
	ch := make(chan *cdpResponse, 1)
	s.pending[id] = ch
	s.mu.Unlock()

	data, err := json.Marshal(req)
	if err != nil {
		s.removePending(id)
		return nil, err
	}

	s.writeMu.Lock()
	err = s.ws.WriteMessage(websocket.TextMessage, data)
	s.writeMu.Unlock()
	if err != nil {
		s.removePending(id)
		return nil, err
	}

	select {
	case resp := <-ch:
		if resp == nil {
			return nil, fmt.Errorf("cdp %s: connection closed", method)
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("cdp %s: %d %s", method, resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	case <-time.After(cdpTimeout):
		s.removePending(id)
		return nil, fmt.Errorf("cdp %s: timed out after %s", method, cdpTimeout)
	}
}

func (s *ChromeSession) removePending(id int) {
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
}

func (s *ChromeSession) failPending(err error) {
	s.mu.Lock()
	for id, ch := range s.pending {
		select {
		case ch <- nil:
		default:
		}
		delete(s.pending, id)
	}
	s.mu.Unlock()
}

// Evaluate runs a JavaScript expression in the page context via Runtime.evaluate
// with awaitPromise+returnByValue, returning the decoded JS value.
func (s *ChromeSession) Evaluate(expression string) (interface{}, error) {
	res, err := s.send("Runtime.evaluate", map[string]interface{}{
		"expression":     expression,
		"awaitPromise":    true,
		"returnByValue":   true,
		"includeCommandLineAPI": false,
		"silent":          false,
		"userGesture":     true,
	})
	if err != nil {
		return nil, err
	}

	var ev struct {
		Result struct {
			Type         string          `json:"type"`
			Value        json.RawMessage `json:"value,omitempty"`
			Subtype      string          `json:"subtype,omitempty"`
			Description  string          `json:"description,omitempty"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text       string `json:"text"`
			Exception  struct {
				Type        string `json:"type"`
				Description string `json:"description,omitempty"`
				Value       string `json:"value,omitempty"`
			} `json:"exception"`
		} `json:"exceptionDetails,omitempty"`
	}
	if err := json.Unmarshal(res, &ev); err != nil {
		return nil, fmt.Errorf("runtime.evaluate: bad result %s: %w", string(res), err)
	}
	if ev.ExceptionDetails != nil {
		msg := ev.ExceptionDetails.Text
		if d := ev.ExceptionDetails.Exception.Description; d != "" {
			msg = d
		} else if v := ev.ExceptionDetails.Exception.Value; v != "" {
			msg = v
		}
		return nil, fmt.Errorf("js error: %s", msg)
	}

	// result.Value is JSON; decode into a generic Go value.
	if len(ev.Result.Value) == 0 || string(ev.Result.Value) == "null" {
		return nil, nil
	}
	var v interface{}
	if err := json.Unmarshal(ev.Result.Value, &v); err != nil {
		// Fallback: return the raw string.
		return string(ev.Result.Value), nil
	}
	return v, nil
}

// Navigate sends Page.navigate and waits for the page load event to fire.
func (s *ChromeSession) Navigate(url string) error {
	start := time.Now()
	if _, err := s.send("Page.navigate", map[string]string{"url": url}); err != nil {
		return err
	}
	// Wait for a load event fired after navigation was initiated.
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		loaded := s.lastLoadAt
		s.mu.Unlock()
		if loaded.After(start) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("navigate: timed out waiting for Page.loadEventFired")
}

// GetCookies returns the cookies for the current page URLs via Network.getCookies.
func (s *ChromeSession) GetCookies() ([]map[string]interface{}, error) {
	res, err := s.send("Network.getCookies", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var gc struct {
		Cookies []map[string]interface{} `json:"cookies"`
	}
	if err := json.Unmarshal(res, &gc); err != nil {
		return nil, fmt.Errorf("getcookies: bad result %s: %w", string(res), err)
	}
	return gc.Cookies, nil
}

// Stderr returns any buffered Chrome stderr output (for diagnostics).
func (s *ChromeSession) Stderr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stderr.String()
}

// Close terminates the Chrome process and the WebSocket.
func (s *ChromeSession) Close() error {
	if s.ws != nil {
		_ = s.ws.Close()
	}
	s.kill()
	return nil
}

func (s *ChromeSession) kill() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
	if s.cancel != nil {
		s.cancel()
	}
}
