package cdp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FetchViaChrome performs an HTTP request from *inside* the Chrome page
// context using the Fetch API. Because the request is issued by Chrome itself
// (BoringSSL + Chrome's network stack), the TLS / HTTP-2 fingerprint and
// automatic client-hint headers (sec-ch-ua, sec-ch-ua-platform, etc.) are
// Chrome's real ones. credentials:"include" means cookies for the page's
// origin are sent and Set-Cookie responses are stored by Chrome, so the
// session is naturally sticky.
//
// Returns the HTTP status code and the response body as a string.
func FetchViaChrome(session *ChromeSession, url string, method string, headers map[string]string, body string) (int, string, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}

	if headers == nil {
		headers = map[string]string{}
	}

	// Build the fetch options as a plain Go map, then JSON-encode it. Embedding
	// the already-valid JSON literals directly into the JS source avoids any
	// manual string escaping (URLs, header values, bodies with quotes, etc.).
	opts := map[string]interface{}{
		"method":      method,
		"headers":     headers,
		"credentials": "include",
	}
	// fetch() throws if a body is supplied for GET/HEAD.
	if body != "" && method != "GET" && method != "HEAD" {
		opts["body"] = body
	}

	urlJSON, err := json.Marshal(url)
	if err != nil {
		return 0, "", fmt.Errorf("fetch: marshal url: %w", err)
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return 0, "", fmt.Errorf("fetch: marshal options: %w", err)
	}

	// The inner function returns a JSON string so we can carry both status and
	// body out through a single returnByValue result.
	expr := fmt.Sprintf(`(async () => {
  const r = await fetch(%s, %s);
  const t = await r.text();
  return JSON.stringify({status: r.status, body: t});
})()`, string(urlJSON), string(optsJSON))

	v, err := session.Evaluate(expr)
	if err != nil {
		return 0, "", err
	}

	jsonStr, ok := v.(string)
	if !ok {
		return 0, "", fmt.Errorf("fetch: unexpected evaluate result type %T", v)
	}

	var out struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &out); err != nil {
		return 0, "", fmt.Errorf("fetch: decode response %q: %w", jsonStr, err)
	}
	return out.Status, out.Body, nil
}
