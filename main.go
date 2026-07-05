package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/3z/captchafox-solver/captchafox"
	"github.com/3z/captchafox-solver/mailcom"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	switch cmd {
	case "test":
		os.Exit(runTest(args))
	case "solve":
		os.Exit(runSolve(args))
	case "verify":
		os.Exit(runVerify(args))
	case "register":
		os.Exit(runRegister(args))
	case "inbox":
		os.Exit(runInbox(args))
	case "send":
		os.Exit(runSend(args))
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `captchafox-solver - CaptchaFox solver + mail.com registration (Go)

Usage:
  captchafox-solver test [--site URL]
      Mint a CaptchaFox public test token and verify it via siteverify.

  captchafox-solver solve --site-key sk_... [--probe] [--site URL]
      [--type slide|audio|attest] [--lang en] [--max-attempts N]
      Solve end-to-end and print a token, or with --probe only issue a
      challenge to test attestation acceptance.

  captchafox-solver verify --token T --secret S [--sitekey sk] [--site URL]
      Verify a token via the public siteverify endpoint.

  captchafox-solver register [--site-key sk_...] [--proxy URL] [--email E] [--password P]
      Register a mail.com account via headless Chrome (CDP) + CaptchaFox solver,
      then OAuth-login to obtain a refresh_token. --proxy for the residential IP.

  captchafox-solver inbox --refresh-token RT [--amount N]
      Read inbox message headers using a stored refresh token.

  captchafox-solver send --refresh-token RT --from E --to E --subject S --body B
      Send an email using a stored refresh token.
`)
}

func runTest(args []string) int {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	site := fs.String("site", captchafox.DefaultSite, "site URL")
	fs.Parse(args)

	client := captchafox.NewCaptchaFoxClient()
	token, err := client.GetTestToken(*site)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error minting test token: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "CaptchaFox test token minted")
	result, err := client.VerifyToken(captchafox.TestSecret, token, captchafox.TestSiteKey, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error verifying token: %v\n", err)
		return 1
	}
	status := "INVALID"
	if success, _ := result["success"].(bool); success {
		status = "VALID"
	}
	fmt.Fprintf(os.Stderr, "CaptchaFox siteverify: %s\n", status)
	printJSON(map[string]interface{}{"token": token, "verify": result})
	if status == "VALID" {
		return 0
	}
	return 2
}

func runSolve(args []string) int {
	fs := flag.NewFlagSet("solve", flag.ExitOnError)
	siteKey := fs.String("site-key", "", "CaptchaFox site key (required)")
	site := fs.String("site", captchafox.DefaultSite, "site URL")
	challengeType := fs.String("type", "slide", "challenge type (slide|audio|attest)")
	lang := fs.String("lang", "en", "language")
	probe := fs.Bool("probe", false, "only issue a challenge to test attestation acceptance")
	maxAttempts := fs.Int("max-attempts", 5, "maximum solve attempts")
	fs.Parse(args)

	if *siteKey == "" {
		fmt.Fprintln(os.Stderr, "error: --site-key is required")
		return 2
	}

	client := captchafox.NewCaptchaFoxClient()
	solver := captchafox.NewCaptchaFoxSolver(client, *siteKey, *site, *challengeType, *lang, nil)

	if *probe {
		fmt.Fprintf(os.Stderr, "CaptchaFox probe with replayed attestation (sitekey %s...)\n", safePrefix(*siteKey, 8))
		result, err := solver.Probe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "CaptchaFox challenge rejected: %v\n", err)
			printJSON(map[string]interface{}{"error": err.Error()})
			return 2
		}
		_, hasToken := result["token"]
		_, hasChallenge := result["challenge"]
		accepted := hasToken || hasChallenge
		status := "not solved"
		if accepted {
			status = "ACCEPTED"
		}
		fmt.Fprintf(os.Stderr, "CaptchaFox challenge %s: %s\n", status, sortedKeys(result))
		printJSON(result)
		return 0
	}

	token, err := solver.Solve(*maxAttempts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	printJSON(map[string]interface{}{"token": token})
	return 0
}

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	token := fs.String("token", "", "token to verify (default: mint a public test token)")
	secret := fs.String("secret", captchafox.TestSecret, "organization secret")
	sitekey := fs.String("sitekey", captchafox.TestSiteKey, "site key")
	site := fs.String("site", captchafox.DefaultSite, "site URL")
	fs.Parse(args)

	client := captchafox.NewCaptchaFoxClient()
	t := *token
	if t == "" {
		var err error
		t, err = client.GetTestToken(*site)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error minting test token: %v\n", err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "CaptchaFox test token minted")
	}
	result, err := client.VerifyToken(*secret, t, *sitekey, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error verifying token: %v\n", err)
		return 1
	}
	status := "INVALID"
	if success, _ := result["success"].(bool); success {
		status = "VALID"
	}
	fmt.Fprintf(os.Stderr, "CaptchaFox siteverify: %s\n", status)
	printJSON(map[string]interface{}{"token": t, "verify": result})
	if status == "VALID" {
		return 0
	}
	return 2
}

func printJSON(v interface{}) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error encoding JSON:", err)
		return
	}
	fmt.Println(string(b))
}

func tglog(msg string) {
	exec.Command("tglog", msg).Run()
}

func runRegister(args []string) int {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	siteKey := fs.String("site-key", "sk_ILKWNruBBVKDOM7dZs50WPNUuCUKR", "CaptchaFox site key")
	proxy := fs.String("proxy", "", "HTTP proxy URL (e.g. http://user:pass@host:port)")
	email := fs.String("email", "", "email (default: random)")
	password := fs.String("password", "", "password (default: random)")
	fs.Parse(args)

	if *email == "" {
		*email = "trevor" + randHexStr(3) + "@mail.com"
	}
	if *password == "" {
		*password = "Mc1!" + randHexStr(8)
	}

	log.SetFlags(log.Ltime)
	tglog("mail.com registration starting (Go)")
	result, err := mailcom.Register(*siteKey, *proxy, *email, *password)
	if err != nil {
		log.Printf("error: %v", err)
		tglog("mail.com registration FAILED: " + err.Error())
		return 1
	}
	tglog("mail.com registration COMPLETE: " + result.Email)
	printJSON(map[string]interface{}{
		"email":         result.Email,
		"password":       result.Password,
		"refresh_token": result.RefreshToken,
	})
	return 0
}

func runInbox(args []string) int {
	fs := flag.NewFlagSet("inbox", flag.ExitOnError)
	refreshToken := fs.String("refresh-token", "", "refresh token (required)")
	amount := fs.Int("amount", 10, "number of messages")
	fs.Parse(args)
	if *refreshToken == "" {
		fmt.Fprintln(os.Stderr, "error: --refresh-token is required")
		return 2
	}
	ctx, err := mailcom.LoadMailContext(*refreshToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	result, err := mailcom.ReadInbox(ctx, *amount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	printJSON(result)
	return 0
}

func runSend(args []string) int {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	refreshToken := fs.String("refresh-token", "", "refresh token (required)")
	from := fs.String("from", "", "sender email (required)")
	to := fs.String("to", "", "recipient (required)")
	subject := fs.String("subject", "", "subject (required)")
	body := fs.String("body", "", "body (required)")
	fs.Parse(args)
	if *refreshToken == "" || *from == "" || *to == "" || *subject == "" || *body == "" {
		fmt.Fprintln(os.Stderr, "error: --refresh-token, --from, --to, --subject, --body all required")
		return 2
	}
	ctx, err := mailcom.LoadMailContext(*refreshToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if err := mailcom.SendMail(ctx, *from, []string{*to}, *subject, *body); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "mail sent")
	return 0
}

func randHexStr(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sortedKeys(m map[string]interface{}) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// stable-ish ordering for display
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return "[" + strings.Join(keys, ",") + "]"
}

func safePrefix(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
