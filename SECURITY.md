# Security Policy

## Authorized use only

`captchafox-solver` is intended **exclusively for authorized security testing** —
red-team and resilience engagements where you have written authorization from
**both** the site operator and CaptchaFox (Scoria Labs GmbH) to test the
target. By using this software you represent that your use complies with all
applicable laws and the terms of the systems you test.

Do **not** use this library to:

- automate account creation, credential stuffing, or abuse on services you do
  not own or are not authorized to test;
- bypass bot-protection on third-party systems without authorization;
- facilitate fraud, spam, or mass registration.

## Scope

This project reproduces observed CaptchaFox protocol behavior (attestation
replay, proof-of-work, slide solving) for the purpose of evaluating the
strength of the protection. It is offensive-security tooling; treat its output
as a finding that the protection can be bypassed under the tested conditions,
and report it through responsible disclosure.

## Reporting a vulnerability or finding

If you identify a weakness in this library, or if your testing reveals a
bypass that affects CaptchaFox or a downstream service, do **not** publish it
publicly before the vendor has been notified and had a reasonable window to
respond. Coordinate disclosure with:

1. The site operator (for service-specific findings).
2. CaptchaFox / Scoria Labs GmbH security contact (for product-level findings).

Feel free to open a **private** GitHub Security Advisory on this repository for
issues in the library itself.
