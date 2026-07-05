package captchafox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// ApiBase is the CaptchaFox challenge/config API origin.
	ApiBase = "https://mam-api.captchafox.com"
	// Pulse is the static X-Pulse header value required by the API.
	Pulse = "2bd77e6f8a17bc0e"
	// TestSiteKey is CaptchaFox's public test site key.
	TestSiteKey = "sk_11111111000000001111111100000000"
	// TestSecret is CaptchaFox's public test organization secret.
	TestSecret = "ok_11111111000000001111111100000000"
	// SiteVerifyURL is the public siteverify endpoint.
	SiteVerifyURL = "https://api.captchafox.com/siteverify"
	// DefaultSite is the default origin/referer site used for solves.
	DefaultSite = "https://signup.mail.com/"
	// DefaultUA is the Chrome 125 Linux User-Agent matched by CF0115 in the
	// captured attestation template.
	DefaultUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

	defaultTimeout = 30 * time.Second
)

// CaptchaFoxConfig wraps the JSON returned by the config endpoint.
type CaptchaFoxConfig struct {
	SiteKey string
	Site    string
	Raw     map[string]interface{}
}

// H returns the config handshake token ("h") used to anchor a challenge.
func (c CaptchaFoxConfig) H() string {
	if v, ok := c.Raw["h"].(string); ok {
		return v
	}
	return ""
}

// CaptchaFoxClient is a minimal direct client for the CaptchaFox protocol.
type CaptchaFoxClient struct {
	HTTP      *http.Client
	UserAgent string
	Timeout   time.Duration
}

// NewCaptchaFoxClient returns a client with sensible defaults.
func NewCaptchaFoxClient() *CaptchaFoxClient {
	return &CaptchaFoxClient{
		HTTP:      &http.Client{Timeout: defaultTimeout},
		UserAgent: DefaultUA,
		Timeout:   defaultTimeout,
	}
}

func (c *CaptchaFoxClient) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	c.HTTP = &http.Client{Timeout: defaultTimeout}
	return c.HTTP
}

func (c *CaptchaFoxClient) ua() string {
	if c.UserAgent != "" {
		return c.UserAgent
	}
	return DefaultUA
}

// FetchConfig fetches the challenge configuration for a site key.
func (c *CaptchaFoxClient) FetchConfig(siteKey, site string) (*CaptchaFoxConfig, error) {
	if site == "" {
		site = DefaultSite
	}
	u := fmt.Sprintf("%s/captcha/%s/config?site=%s", ApiBase, siteKey, url.QueryEscape(site))
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	c.applyHeaders(req, site)
	body, err := c.doRaw(req, "CaptchaFox config")
	if err != nil {
		return nil, err
	}
	raw, err := decodeJSON(body)
	if err != nil {
		return nil, fmt.Errorf("CaptchaFox config: invalid JSON: %w", err)
	}
	return &CaptchaFoxConfig{SiteKey: siteKey, Site: site, Raw: raw}, nil
}

// Challenge requests a challenge for the configured handshake. The body is
// encoded with EncodePayload and sent as text/plain.
func (c *CaptchaFoxClient) Challenge(config *CaptchaFoxConfig, challengeType string, cs map[string]interface{}, k int, lang string) (map[string]interface{}, error) {
	if challengeType == "" {
		challengeType = "slide"
	}
	if lang == "" {
		lang = "en"
	}
	if cs == nil {
		cs = map[string]interface{}{}
	}
	payload := map[string]interface{}{
		"lng":  lang,
		"h":    config.H(),
		"cs":   cs,
		"host": hostname(config.Site),
		"k":    k,
		"type": challengeType,
	}
	body, err := EncodePayload(payload)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("%s/captcha/%s/challenge", ApiBase, config.SiteKey)
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.applyHeaders(req, config.Site)
	req.Header.Set("Content-Type", "text/plain")
	return c.doJSON(req, "CaptchaFox challenge")
}

// Verify submits the solved challenge payload and returns the server result.
func (c *CaptchaFoxClient) Verify(payload map[string]interface{}, site string) (map[string]interface{}, error) {
	if site == "" {
		site = DefaultSite
	}
	body, err := EncodePayload(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, ApiBase+"/captcha/verify", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.applyHeaders(req, site)
	req.Header.Set("Content-Type", "text/plain")
	return c.doJSON(req, "CaptchaFox verify")
}

// VerifyToken verifies a CaptchaFox response token against the public
// siteverify endpoint.
func (c *CaptchaFoxClient) VerifyToken(secret, response, sitekey, remoteIP string) (map[string]interface{}, error) {
	form := url.Values{}
	form.Set("secret", secret)
	form.Set("response", response)
	if sitekey != "" {
		form.Set("sitekey", sitekey)
	}
	if remoteIP != "" {
		form.Set("remoteIp", remoteIP)
	}
	req, err := http.NewRequest(http.MethodPost, SiteVerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.ua())
	return c.doJSON(req, "CaptchaFox siteverify")
}

// GetTestToken mints a token from CaptchaFox's public test site key.
func (c *CaptchaFoxClient) GetTestToken(site string) (string, error) {
	if site == "" {
		site = DefaultSite
	}
	config, err := c.FetchConfig(TestSiteKey, site)
	if err != nil {
		return "", err
	}
	result, err := c.Challenge(config, "slide", nil, 0, "en")
	if err != nil {
		return "", err
	}
	token, _ := result["token"].(string)
	if token == "" {
		return "", fmt.Errorf("CaptchaFox test sitekey did not return a token: %v", result)
	}
	return token, nil
}

func (c *CaptchaFoxClient) applyHeaders(req *http.Request, site string) {
	origin, err := originOf(site)
	if err != nil {
		origin = site
	}
	req.Header.Set("X-Pulse", Pulse)
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", site)
	req.Header.Set("User-Agent", c.ua())
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
}

func (c *CaptchaFoxClient) doRaw(req *http.Request, label string) ([]byte, error) {
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s failed: HTTP %d: %s", label, resp.StatusCode, truncate(string(body), 1000))
	}
	return body, nil
}

func (c *CaptchaFoxClient) doJSON(req *http.Request, label string) (map[string]interface{}, error) {
	body, err := c.doRaw(req, label)
	if err != nil {
		return nil, err
	}
	result, err := decodeJSON(body)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", label, err)
	}
	return result, nil
}

// decodeJSON parses JSON preserving numbers as json.Number so that large
// integer fields (timestamps, PoW seeds) are not coerced to float64.
func decodeJSON(body []byte) (map[string]interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var m map[string]interface{}
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

func originOf(site string) (string, error) {
	p, err := url.Parse(site)
	if err != nil {
		return "", err
	}
	if p.Scheme == "" || p.Host == "" {
		return "", fmt.Errorf("site must be an absolute URL: %s", site)
	}
	return p.Scheme + "://" + p.Host, nil
}

func hostname(site string) string {
	p, err := url.Parse(site)
	if err != nil || p.Hostname() == "" {
		return site
	}
	return p.Hostname()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
