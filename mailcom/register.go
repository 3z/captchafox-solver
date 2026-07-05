package mailcom

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/3z/captchafox-solver/captchafox"
	"github.com/3z/captchafox-solver/cdp"
)

// RegistrationResult holds the outcome of a full registration + login.
type RegistrationResult struct {
	Email        string
	Password     string
	RefreshToken string
}

// Register creates a mail.com account via CDP Chrome (real TLS) + captures the
// OAuth authorization code from the SPA's auto-redirect, then exchanges it for
// tokens. The captcha is minted by the pure-Go captchafox solver.
func Register(siteKey, proxy, email, password string) (*RegistrationResult, error) {
	// 1. build OAuth URL with authcode_context (10-char, required for SPA's OAuth flow)
	authcodeCtx := randAlphaNum(10)
	pending := BuildAuthorizationURL(true, "", authcodeCtx)
	log.Printf("oauth url: %s", pending.URL[:80])

	// 2. launch headless Chrome with proxy (via local relay for auth)
	chromeProxy := ""
	if proxy != "" {
		relayAddr, cleanup, err := cdp.StartProxyRelay(proxy)
		if err != nil {
			return nil, fmt.Errorf("proxy relay: %w", err)
		}
		defer cleanup()
		chromeProxy = relayAddr
	}
	session, err := cdp.LaunchChrome(chromeProxy)
	if err != nil {
		return nil, fmt.Errorf("launch chrome: %w", err)
	}
	defer session.Close()

	// 3. navigate to the registration SPA
	if err := session.Navigate(pending.URL); err != nil {
		return nil, fmt.Errorf("navigate: %w", err)
	}
	time.Sleep(4 * time.Second)

	// debug: check page URL + appConfig presence
	pageURL, _ := session.Evaluate("window.location.href")
	log.Printf("page url: %v", pageURL)
	hasConfig, _ := session.Evaluate(`(function(){for(var s of document.querySelectorAll('script')){if(s.id==='application-config')return 'yes';}return 'no';})()`)
	log.Printf("appConfig present: %v", hasConfig)

	// 4. extract appConfig + do the create POST in one evaluate (real Chrome TLS)
	phone := "+1212333" + randDigits(4)
	captchaToken, err := mintCaptcha(siteKey, proxy)
	if err != nil {
		return nil, fmt.Errorf("captcha: %w", err)
	}
	log.Printf("captcha token: %s...", captchaToken[:20])

	createJS := buildCreateJS(captchaToken, email, password, phone)
	result, err := session.Evaluate(createJS)
	if err != nil {
		return nil, fmt.Errorf("create evaluate: %w", err)
	}
	createResult := parseCreateResult(result)
	if createResult.Status != 204 && createResult.Status != 200 {
		return nil, fmt.Errorf("create failed: HTTP %d: %s", createResult.Status, createResult.Body)
	}
	log.Printf("account created (HTTP %d), waiting for OAuth redirect...", createResult.Status)

	// 5. poll for the custom-scheme redirect (SPA auto-submits login form → redirects)
	redirectURL, err := pollForRedirect(session, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("oauth redirect: %w", err)
	}
	log.Printf("captured redirect: %s", redirectURL[:60])

	// 6. extract code from redirect URL + exchange for tokens
	code := extractCode(redirectURL, pending.State)
	if code == "" {
		return nil, fmt.Errorf("no code in redirect: %s", redirectURL)
	}
	tokens, err := ExchangeAuthorizationCode(code, pending.CodeVerifier)
	if err != nil {
		return nil, fmt.Errorf("exchange: %w", err)
	}
	refreshToken, _ := tokens["refresh_token"].(string)
	if refreshToken == "" {
		return nil, fmt.Errorf("no refresh_token in exchange response: %v", tokens)
	}

	return &RegistrationResult{
		Email:        email,
		Password:     password,
		RefreshToken: refreshToken,
	}, nil
}

func mintCaptcha(siteKey, proxy string) (string, error) {
	client := captchafox.NewCaptchaFoxClient()
	solver := captchafox.NewCaptchaFoxSolver(client, siteKey, "https://signup.mail.com/", "slide", "en", nil)
	return solver.Solve(3)
}

func buildCreateJS(captchaToken, email, password, phone string) string {
	return fmt.Sprintf(`(async () => {
		let cfg = {};
		for (const s of document.querySelectorAll('script')) {
			if (s.id === 'application-config') { try { cfg = JSON.parse(s.textContent); } catch(e){} }
		}
		const product = (cfg.products && cfg.products.FREE_LEVEL_ONE && cfg.products.FREE_LEVEL_ONE.name) || 'mailcomFree';
		const body = {
			confirmationCode: null,
			user: {
				givenName: "Trevor", familyName: "Hughes", gender: "MALE", birthDate: "1992-05-22",
				mobileNumber: "%s",
				address: {countryCode:"US", region:"NY", postalCode:"10001", locality:"New York", streetAddress:"123 Main St"},
				credentials: {password: "%s"}
			},
			mailAccount: {email: "%s"},
			product: product,
			mediaCode: null
		};
		const rid = crypto.randomUUID ? crypto.randomUUID() : (Date.now().toString(36)+Math.random().toString(36).slice(2));
		const headers = {
			"Content-Type": "application/vnd.ui.mam.account.creation+json",
			"X-UI-APP": "@mamdev/umreg.registration-app2/8.38.0",
			"X-CCGUID": cfg.clientCredentialGuid,
			"X-REQUEST-ID": rid,
			"Template-Name": cfg.templateName || "B",
			"Authorization": "Bearer " + cfg.accessToken,
			"cf-captcha-response": "%s"
		};
		if (cfg.referrerSource) headers["Source"] = cfg.referrerSource;
		if (cfg.softwareVariant) headers["Software-Variant"] = cfg.softwareVariant;
		const r = await fetch("/account/email-registration", {method:"POST", headers, body: JSON.stringify(body), credentials:"include"});
		let t = ""; try { t = await r.text(); } catch(e){}
		return JSON.stringify({status: r.status, body: t});
	})()`, phone, password, email, captchaToken)
}

type createResp struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

func parseCreateResult(result interface{}) createResp {
	var r createResp
	if s, ok := result.(string); ok {
		json.Unmarshal([]byte(s), &r)
	}
	return r
}

func pollForRedirect(session *cdp.ChromeSession, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		result, err := session.Evaluate("window.location.href")
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		href, _ := result.(string)
		if strings.HasPrefix(href, "com.mail.androidmail.redirect://") {
			return href, nil
		}
		time.Sleep(1 * time.Second)
	}
	return "", fmt.Errorf("timeout waiting for redirect")
}

func extractCode(redirectURL, expectedState string) string {
	u := strings.SplitN(redirectURL, "?", 2)
	if len(u) < 2 {
		return ""
	}
	params := strings.Split(u[1], "&")
	for _, p := range params {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 && kv[0] == "code" {
			return kv[1]
		}
	}
	return ""
}

func randAlphaNum(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[k.Int64()]
	}
	return string(b)
}

func randDigits(n int) string {
	out := ""
	for i := 0; i < n; i++ {
		k, _ := rand.Int(rand.Reader, big.NewInt(10))
		out += fmt.Sprintf("%d", k.Int64())
	}
	return out
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
