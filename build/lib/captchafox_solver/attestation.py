from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .client import DEFAULT_CAPTCHAFOX_SITE

_ATTESTATION_TEMPLATE_PATH = Path(__file__).resolve().parent / "data" / "cf_attestation_template.json"
_attestation_template: dict[str, Any] | None = None


def _load_attestation_template() -> dict[str, Any]:
    global _attestation_template
    if _attestation_template is None:
        _attestation_template = json.loads(_ATTESTATION_TEMPLATE_PATH.read_text(encoding="utf-8"))
    return _attestation_template


# Per-user attestation variation pools. The Chrome-version-bound fields (UA,
# platform, property inventories CF0130/0131/0132, plugin/mimeType sets, plugin
# integrity booleans) stay constant from the captured template; only genuine
# per-user signals are varied so each solve yields a distinct fingerprint while
# remaining internally consistent and Chrome-plausible.
_PROFILE_SCREEN_POOL: tuple[tuple[int, int, int], ...] = (
    (1920, 1080, 1), (2560, 1440, 1), (1366, 768, 1), (3840, 2160, 1),
    (1920, 1200, 1), (1680, 1050, 1), (1280, 800, 2), (1440, 900, 1),
    (1600, 900, 1), (2880, 1800, 2),
)
_PROFILE_WEBGL_POOL: tuple[tuple[str, str], ...] = (
    ("Google Inc. (Google)", "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)"),
    ("Google Inc. (Google)", "ANGLE (Google, Vulkan 1.3.0 (Intel(R) UHD Graphics 630 (0x00003E9B)), Intel-open-source Mesa)"),
    ("Google Inc. (Google)", "ANGLE (Google, Vulkan 1.3.0 (Intel(R) Iris(R) Xe Graphics (0x00009A49)), Intel-open-source Mesa)"),
    ("Google Inc. (Google)", "ANGLE (Google, Vulkan 1.3.0 (NVIDIA GeForce GTX 1660), NVIDIA proprietary driver)"),
    ("Google Inc. (Google)", "ANGLE (Google, Vulkan 1.3.0 (AMD Radeon RX 580 (0x000067DF)), AMD open-source Mesa)"),
)
_PROFILE_TIMEZONE_POOL: tuple[int, ...] = (
    0, -480, -300, 240, 300, 480, -60, 360, 420, 600, -330,
)
_PROFILE_CORES_POOL: tuple[int, ...] = (4, 8, 12, 16, 32)
_PROFILE_LANGUAGES_POOL: tuple[tuple[str, ...], ...] = (
    ("en-US",), ("en-US", "en"), ("en-GB",), ("de-DE", "de", "en"),
    ("fr-FR", "fr", "en"), ("en-US", "en", "es"), ("pt-BR", "pt", "en"),
)


@dataclass(frozen=True)
class AttestationProfile:
    """A self-consistent per-user Chrome attestation profile.

    Varies only per-user signals (screen, GPU, timezone, core count, languages,
    dark mode). UA / platform / property inventories / plugin integrity stay
    constant from the captured Chrome template so the fingerprint remains
    Chrome-plausible and consistent with the HTTP User-Agent header.
    """

    dark_mode: bool
    hardware_concurrency: int
    timezone_offset: int
    languages: tuple[str, ...]
    webgl_vendor: str
    webgl_renderer: str
    screen_width: int
    screen_height: int
    pixel_ratio: int

    def screen_payload(self) -> dict[str, Any]:
        return {
            "width": self.screen_width,
            "height": self.screen_height,
            "availW": self.screen_width,
            "availH": self.screen_height,
            "clrDepth": 24,
            "pxDepth": 24,
            "pxRatio": self.pixel_ratio,
            "outerW": self.screen_width,
            "outerH": self.screen_height,
        }

    def webgl_payload(self) -> list[str]:
        return [
            self.webgl_vendor,
            self.webgl_renderer,
            "WebKit",
            "WebKit WebGL",
            "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        ]


def random_attestation_profile(rng: random.Random | None = None) -> AttestationProfile:
    """Build a randomized but self-consistent attestation profile."""
    r = rng or random.Random()
    width, height, ratio = r.choice(_PROFILE_SCREEN_POOL)
    vendor, renderer = r.choice(_PROFILE_WEBGL_POOL)
    return AttestationProfile(
        dark_mode=r.choice([True, False]),
        hardware_concurrency=r.choice(_PROFILE_CORES_POOL),
        timezone_offset=r.choice(_PROFILE_TIMEZONE_POOL),
        languages=r.choice(_PROFILE_LANGUAGES_POOL),
        webgl_vendor=vendor,
        webgl_renderer=renderer,
        screen_width=width,
        screen_height=height,
        pixel_ratio=ratio,
    )


def build_attestation(
    site: str = DEFAULT_CAPTCHAFOX_SITE,
    profile: AttestationProfile | None = None,
    now_ms: int | None = None,
) -> dict[str, Any]:
    """Build a Chrome-consistent browser attestation object (CaptchaFox ``cs``).

    Without a profile this replays the captured Chrome template (only ``CF0106``
    timestamp and ``CF0148`` site are fresh). With a profile it additionally
    overrides the per-user signal fields (screen, GPU, timezone, core count,
    languages, dark mode) so each call yields a distinct fingerprint.

    The static ``CF0100``-``CF0148`` field values were captured once from a real
    Chromium running the genuine ``paint.js`` attestation module; the runtime
    solver replays them in pure Python (no browser in the runtime path). The
    HTTP ``User-Agent`` of the request must match the embedded ``CF0115``; the
    default ``CaptchaFoxClient`` user agent does.
    """
    cs = json.loads(json.dumps(_load_attestation_template()))  # deep copy
    cs["CF0106"] = int(now_ms if now_ms is not None else time.time() * 1000)
    cs["CF0148"] = site
    if profile is not None:
        cs["CF0101"] = profile.dark_mode
        cs["CF0105"] = profile.hardware_concurrency
        cs["CF0108"] = profile.timezone_offset
        cs["CF0111"] = list(profile.languages)
        cs["CF0114"] = profile.webgl_payload()
        cs["CF0120"] = profile.screen_payload()
        cs["CF0121"] = [profile.webgl_vendor, profile.webgl_renderer]
    return cs
