from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import requests

from .encoding import encode_captchafox_payload
from .exceptions import CaptchaFoxError

DEFAULT_TIMEOUT = 30

# mail.com ships a UICDN-hosted CaptchaFox build that talks to a private API host
# and carries a build-bound X-Pulse header. These are observed constants, not
# secrets.
CAPTCHAFOX_API_BASE = "https://mam-api.captchafox.com"
CAPTCHAFOX_PULSE = "2bd77e6f8a17bc0e"
CAPTCHAFOX_SITEVERIFY_URL = "https://api.captchafox.com/siteverify"

# Public test keys published by CaptchaFox for integration testing. They always
# succeed and provide no protection.
CAPTCHAFOX_TEST_SITE_KEY = "sk_11111111000000001111111100000000"
CAPTCHAFOX_TEST_SECRET = "ok_11111111000000001111111100000000"

DEFAULT_CAPTCHAFOX_SITE = "https://signup.mail.com/"
DEFAULT_CAPTCHAFOX_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)


@dataclass(frozen=True)
class CaptchaFoxConfig:
    """Resolved widget config for a sitekey."""

    site_key: str
    site: str
    raw: dict[str, Any]

    @property
    def h(self) -> str:
        return self.raw["h"]


class CaptchaFoxClient:
    """Minimal direct client for the CaptchaFox protocol.

    Handles config fetch, the binary-encoded challenge/verify POSTs, and the
    public ``siteverify`` token-validation endpoint. The HTTP ``User-Agent``
    must match the ``CF0115`` field embedded in the attestation object sent with
    challenge/verify calls; the default UA matches the captured Chrome template.
    """

    def __init__(
        self,
        http: requests.Session | None = None,
        user_agent: str = DEFAULT_CAPTCHAFOX_USER_AGENT,
    ) -> None:
        self.http = http or requests.Session()
        self.user_agent = user_agent

    def fetch_config(self, site_key: str, site: str = DEFAULT_CAPTCHAFOX_SITE) -> CaptchaFoxConfig:
        response = self.http.get(
            f"{CAPTCHAFOX_API_BASE}/captcha/{site_key}/config",
            params={"site": site},
            headers=self._headers(site),
            timeout=DEFAULT_TIMEOUT,
        )
        _raise_captchafox(response, "CaptchaFox config")
        return CaptchaFoxConfig(site_key=site_key, site=site, raw=response.json())

    def challenge(
        self,
        config: CaptchaFoxConfig,
        challenge_type: str = "slide",
        cs: dict[str, Any] | None = None,
        k: int = 0,
        lang: str = "en",
    ) -> dict[str, Any]:
        payload = {
            "lng": lang,
            "h": config.h,
            "cs": cs or {},
            "host": _hostname(config.site),
            "k": k,
            "type": challenge_type,
        }
        response = self.http.post(
            f"{CAPTCHAFOX_API_BASE}/captcha/{config.site_key}/challenge",
            data=encode_captchafox_payload(payload),
            headers={**self._headers(config.site), "Content-Type": "text/plain"},
            timeout=DEFAULT_TIMEOUT,
        )
        _raise_captchafox(response, "CaptchaFox challenge")
        return response.json()

    def verify(
        self,
        payload: dict[str, Any],
        site: str = DEFAULT_CAPTCHAFOX_SITE,
    ) -> dict[str, Any]:
        response = self.http.post(
            f"{CAPTCHAFOX_API_BASE}/captcha/verify",
            data=encode_captchafox_payload(payload),
            headers={**self._headers(site), "Content-Type": "text/plain"},
            timeout=DEFAULT_TIMEOUT,
        )
        _raise_captchafox(response, "CaptchaFox verify")
        return response.json()

    def verify_token(
        self,
        secret: str,
        response: str,
        sitekey: str | None = None,
        remote_ip: str | None = None,
    ) -> dict[str, Any]:
        """Verify a response token against the public ``siteverify`` endpoint."""
        data: dict[str, str] = {"secret": secret, "response": response}
        if sitekey:
            data["sitekey"] = sitekey
        if remote_ip:
            data["remoteIp"] = remote_ip
        http_response = self.http.post(
            CAPTCHAFOX_SITEVERIFY_URL,
            data=data,
            headers={"User-Agent": self.user_agent},
            timeout=DEFAULT_TIMEOUT,
        )
        _raise_captchafox(http_response, "CaptchaFox siteverify")
        return http_response.json()

    def get_test_token(self, site: str = DEFAULT_CAPTCHAFOX_SITE) -> str:
        """Mint a token from CaptchaFox's public always-succeed test sitekey."""
        config = self.fetch_config(CAPTCHAFOX_TEST_SITE_KEY, site)
        result = self.challenge(config)
        token = result.get("token")
        if not token:
            raise CaptchaFoxError(f"CaptchaFox test sitekey did not return a token: {result}")
        return str(token)

    def _headers(self, site: str) -> dict[str, str]:
        return {
            "X-Pulse": CAPTCHAFOX_PULSE,
            "Origin": _origin(site),
            "Referer": site,
            "User-Agent": self.user_agent,
            "Accept-Language": "en-US,en;q=0.9",
        }


def _origin(site: str) -> str:
    parsed = urlsplit(site)
    if not parsed.scheme or not parsed.netloc:
        raise CaptchaFoxError(f"CaptchaFox site must be an absolute URL: {site}")
    return f"{parsed.scheme}://{parsed.netloc}"


def _hostname(site: str) -> str:
    parsed = urlsplit(site)
    if not parsed.hostname:
        raise CaptchaFoxError(f"CaptchaFox site must include a hostname: {site}")
    return parsed.hostname


def _raise_captchafox(response: requests.Response, label: str) -> None:
    if response.ok:
        return
    raise CaptchaFoxError(f"{label} failed: HTTP {response.status_code}: {response.text[:1000]}")
