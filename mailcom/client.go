package mailcom

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuthPendingAuth holds the PKCE state for an OAuth flow.
type OAuthPendingAuth struct {
	URL          string
	State        string
	CodeVerifier string
}

// BuildAuthorizationURL builds the OAuth authorize URL with PKCE.
// If register is true, appends register=true. If email is non-empty, sets login_hint.
// authcodeContext is a 10-char string required for the SPA's auth code flow.
func BuildAuthorizationURL(register bool, email, authcodeContext string) *OAuthPendingAuth {
	verifier := b64url(randBytes(64))
	state := b64url(randBytes(64))
	challenge := b64url(sha256bytes([]byte(verifier)))

	params := url.Values{}
	params.Set("client_id", ClientID)
	params.Set("redirect_uri", RedirectURI)
	params.Set("response_type", "code")
	params.Set("state", state)
	params.Set("code_challenge", challenge)
	params.Set("login_hint", email)
	params.Set("code_challenge_method", "S256")
	if register {
		params.Set("register", "true")
	}
	if authcodeContext != "" {
		params.Set("authcode_context", authcodeContext)
	}
	return &OAuthPendingAuth{
		URL:          AuthEndpoint + "?" + params.Encode(),
		State:        state,
		CodeVerifier: verifier,
	}
}

// ExchangeAuthorizationCode exchanges the OAuth code for tokens.
func ExchangeAuthorizationCode(code, codeVerifier string) (map[string]interface{}, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", RedirectURI)
	data.Set("client_id", ClientID)
	data.Set("code_verifier", codeVerifier)
	return tokenRequest(data.Encode())
}

// RefreshAccessToken refreshes for a given scope.
func RefreshAccessToken(refreshToken, scope string) (map[string]interface{}, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("scope", scope)
	return tokenRequest(data.Encode())
}

// MailContext holds the runtime context for mailbox API calls.
type MailContext struct {
	BaseURI         string
	MailSubmission  string
	MailAccessToken string
}

// LoadMailContext loads the PAC + mail access token from a refresh token.
func LoadMailContext(refreshToken string) (*MailContext, error) {
	// 1. refresh for context scope
	ctxTok, err := RefreshAccessToken(refreshToken, ContextScope)
	if err != nil {
		return nil, err
	}
	ctxAccess := ctxTok["access_token"].(string)

	// 2. GET PAC
	pacURL := strings.TrimSuffix(ContextEndpoint, "/") + "/http-service-proxy1/service/pacs/" + MobileContextPath
	req, _ := http.NewRequest("GET", pacURL, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+ctxAccess)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var pac map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&pac)

	mailInfo := pac["mailInfo"].(map[string]interface{})
	baseURI := mailInfo["baseURI"].(string)
	mailSubmission, _ := mailInfo["mailSubmissionURI"].(string)
	atHint := mailInfo["at-hint"].(string)
	atScopes := pac["at-scopes"].(map[string]interface{})
	mailScope := ""
	if s, ok := atScopes[atHint].(string); ok {
		mailScope = s
	} else {
		mailScope = atHint
	}

	// 3. refresh for mail scope
	mailTok, err := RefreshAccessToken(refreshToken, mailScope)
	if err != nil {
		return nil, err
	}
	mailAccess := mailTok["access_token"].(string)

	return &MailContext{
		BaseURI:         baseURI,
		MailSubmission:  mailSubmission,
		MailAccessToken: mailAccess,
	}, nil
}

// ListFolders lists mailbox folders.
func ListFolders(ctx *MailContext) (map[string]interface{}, error) {
	return getJSON(ctx.BaseURI+"/folders?absoluteURI=false",
		"application/vnd.ui.trinity.folders-v5+json", ctx.MailAccessToken)
}

// ReadInbox reads inbox message headers.
func ReadInbox(ctx *MailContext, amount int) (map[string]interface{}, error) {
	folders, err := ListFolders(ctx)
	if err != nil {
		return nil, err
	}
	inbox := findFolder(folders, "INBOX")
	if inbox == nil {
		return nil, fmt.Errorf("INBOX folder not found")
	}
	links := inbox["_links"].(map[string]interface{})
	mails := links["mails"].(map[string]interface{})
	href := mails["href"].(string)
	u := ctx.BaseURI + "/" + href + fmt.Sprintf("?absoluteURI=false&orderBy=INTERNALDATE+desc&tagsShowAll=true&amount=%d", amount)
	return getJSON(u, "application/vnd.ui.trinity.messages+json", ctx.MailAccessToken)
}

// SendMail sends an email.
func SendMail(ctx *MailContext, sender string, to []string, subject, body string) error {
	payload := map[string]interface{}{
		"mailHeader": map[string]interface{}{
			"from": sender, "to": to, "cc": []interface{}{}, "bcc": []interface{}{},
			"subject": subject, "date": time.Now().UnixMilli(), "priority": "3",
		},
		"plaintextBody": body, "attachments": []interface{}{},
	}
	bodyBytes, _ := json.Marshal(payload)
	subURL := ctx.MailSubmission
	if ctx.MailSubmission == "" {
		subURL = strings.TrimSuffix(ctx.BaseURI, "/") + "/Mailsubmission"
	}
	req, _ := http.NewRequest("POST", subURL, bytes.NewReader(bodyBytes))
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Content-Type", "application/vnd.ui.trinity.minimalmailmessage+json")
	req.Header.Set("Authorization", "Bearer "+ctx.MailAccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("send mail failed: HTTP %d", resp.StatusCode)
	}
	return nil
}

// --- helpers ---

func tokenRequest(body string) (map[string]interface{}, error) {
	req, _ := http.NewRequest("POST", TokenEndpoint, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(ClientID, ClientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("token request failed: HTTP %d: %s", resp.StatusCode, string(b))
	}
	var result map[string]interface{}
	json.Unmarshal(b, &result)
	return result, nil
}

func getJSON(u, accept, token string) (map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Accept", accept)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func findFolder(folders map[string]interface{}, wanted string) map[string]interface{} {
	var walk func([]interface{}) map[string]interface{}
	walk = func(items []interface{}) map[string]interface{} {
		for _, item := range items {
			f := item.(map[string]interface{})
			attr := f["attribute"].(map[string]interface{})
			for _, v := range []string{fmt.Sprintf("%v", f["folderIdentifier"]), fmt.Sprintf("%v", attr["folderType"]), fmt.Sprintf("%v", attr["folderName"])} {
				if strings.EqualFold(v, wanted) {
					return f
				}
			}
			if sub, ok := f["folders"].([]interface{}); ok {
				if found := walk(sub); found != nil {
					return found
				}
			}
		}
		return nil
	}
	items := folders["folders"].([]interface{})
	return walk(items)
}

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func sha256bytes(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
