from __future__ import annotations

import argparse
import json
import sys

from .attestation import random_attestation_profile
from .client import (
    CAPTCHAFOX_TEST_SECRET,
    CAPTCHAFOX_TEST_SITE_KEY,
    DEFAULT_CAPTCHAFOX_SITE,
    CaptchaFoxClient,
)
from .exceptions import CaptchaFoxError
from .solver import CaptchaFoxSolver


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="captchafox-solver",
        description="Solve CaptchaFox challenges in pure Python (authorized testing only).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("test", help="Mint the public test token and validate it via siteverify")
    p.add_argument("--site", default=DEFAULT_CAPTCHAFOX_SITE)

    p = sub.add_parser("solve", help="Solve CaptchaFox end-to-end and print a token")
    p.add_argument("--site-key", required=True, help="CaptchaFox sitekey to solve")
    p.add_argument("--site", default=DEFAULT_CAPTCHAFOX_SITE, help="Page site URL")
    p.add_argument("--type", choices=("slide", "audio", "attest"), default="slide")
    p.add_argument(
        "--probe",
        action="store_true",
        help="Only issue the challenge to test attestation acceptance",
    )

    p = sub.add_parser("verify", help="Validate a token via the public siteverify endpoint")
    p.add_argument("--token", required=True)
    p.add_argument("--secret", required=True, help="Organization secret")
    p.add_argument("--sitekey")

    args = parser.parse_args(argv)

    try:
        if args.command == "test":
            client = CaptchaFoxClient()
            token = client.get_test_token(args.site)
            result = client.verify_token(CAPTCHAFOX_TEST_SECRET, token, sitekey=CAPTCHAFOX_TEST_SITE_KEY)
            print(json.dumps({"token": token, "verify": result}, indent=2))
            return 0 if result.get("success") else 2

        if args.command == "solve":
            solver = CaptchaFoxSolver(
                client=CaptchaFoxClient(),
                site_key=args.site_key,
                site=args.site,
                challenge_type=args.type,
            )
            if args.probe:
                result = solver.probe()
                print(json.dumps(result, indent=2, default=str))
                return 0 if ("token" in result or "challenge" in result) else 2
            token = solver.solve()
            print(json.dumps({"token": token, "site_key": args.site_key}, indent=2))
            return 0

        if args.command == "verify":
            client = CaptchaFoxClient()
            result = client.verify_token(args.secret, args.token, sitekey=args.sitekey)
            print(json.dumps(result, indent=2))
            return 0 if result.get("success") else 2
    except CaptchaFoxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
