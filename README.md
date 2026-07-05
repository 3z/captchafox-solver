# captchafox-solver (Go)

A pure-Go CaptchaFox challenge solver + mail.com registration tool.

## Features
- **CaptchaFox solver** (pure Go): attestation replay, SHA-256 PoW, slide gap detection, trail synthesis
- **CDP-based create** (headless Chrome): real Chrome TLS for mail.com's bot-detection bypass
- **Registration + OAuth login**: create account → capture OAuth code → exchange for bearer tokens
- **Mailbox API**: list folders, read inbox, send mail

## Build
```bash
go build -o captchafox-solver .
```

## Usage
```
captchafox-solver test                                    # mint + verify test token
captchafox-solver solve --site-key sk_... [--probe]       # solve or probe
captchafox-solver register --proxy http://user:pass@h:p   # register + login
captchafox-solver inbox --refresh-token RT                # read inbox
captchafox-solver send --refresh-token RT --from E --to E --subject S --body B
```

For authorized security testing only.
