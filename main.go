package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/3z/captchafox-solver/captchafox"
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
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `captchafox-solver - A pure-Go CaptchaFox challenge solver

Usage:
  captchafox-solver test [--site URL]
      Mint a CaptchaFox public test token and verify it via siteverify.

  captchafox-solver solve --site-key sk_... [--probe] [--site URL]
      [--type slide|audio|attest] [--lang en] [--max-attempts N]
      Solve end-to-end and print a token, or with --probe only issue a
      challenge to test attestation acceptance.

  captchafox-solver verify --token T --secret S [--sitekey sk] [--site URL]
      Verify a token via the public siteverify endpoint.

For authorized security testing only.
`)
}

func tglog(msg string) {
	exec.Command("tglog", msg).Run()
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

func sortedKeys(m map[string]interface{}) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
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
