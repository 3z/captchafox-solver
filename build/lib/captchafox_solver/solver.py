from __future__ import annotations

import base64
import io
import math
import random as _random
from typing import Any
from urllib.parse import urlsplit

from .attestation import AttestationProfile, build_attestation, random_attestation_profile
from .client import (
    CAPTCHAFOX_TEST_SITE_KEY,
    DEFAULT_CAPTCHAFOX_SITE,
    CaptchaFoxClient,
    CaptchaFoxConfig,
)
from .exceptions import CaptchaFoxError
from .pow import solve_pow


class CaptchaFoxSolver:
    """End-to-end CaptchaFox solver (pure Python, no browser in the runtime path).

    Replays a real-Chrome attestation object as ``cs`` and solves the slide
    challenge by detecting the puzzle gap in the background image, then verifies
    the answer to obtain a response token.
    """

    SLIDE_TRACK_WIDTH_CSS = 300
    SLIDE_PIECE_SIZE_CSS = 50
    SLIDE_TRACK_HEIGHT_CSS = 60

    def __init__(
        self,
        client: CaptchaFoxClient | None = None,
        site_key: str = CAPTCHAFOX_TEST_SITE_KEY,
        site: str = DEFAULT_CAPTCHAFOX_SITE,
        challenge_type: str = "slide",
        lang: str = "en",
        profile: AttestationProfile | None = None,
    ) -> None:
        self.client = client or CaptchaFoxClient()
        self.site_key = site_key
        self.site = site
        self.challenge_type = challenge_type
        self.lang = lang
        self.profile = profile

    def _new_profile(self) -> AttestationProfile | None:
        # A fixed profile (if set) is reused; otherwise each solve mints a fresh
        # random per-user fingerprint.
        return self.profile or random_attestation_profile()

    def probe(self) -> dict[str, Any]:
        """Fetch config and issue a challenge with a synthesized attestation.

        Returns the raw challenge response. A response containing ``challenge``
        or ``token`` means the attestation (``cs``) was accepted by the server.
        """
        config = self.client.fetch_config(self.site_key, self.site)
        cs = build_attestation(self.site, profile=self._new_profile())
        k = self._pow_nonce(config.raw.get("m"))
        return self.client.challenge(
            config, challenge_type=self.challenge_type, cs=cs, k=k, lang=self.lang
        )

    def solve(self, max_attempts: int = 1) -> str:
        """Run the full flow and return a verified response token.

        Retries up to ``max_attempts`` times on any failure (e.g. ``solved:
        False`` from a missed slide gap, or a transient proxy/network error).
        Each attempt mints a fresh attestation profile and challenge.
        """
        last_error: Exception | None = None
        for _ in range(max_attempts):
            try:
                return self._solve_once()
            except Exception as exc:  # noqa: BLE001 - retry on any failure
                last_error = exc
        assert last_error is not None
        raise last_error

    def _solve_once(self) -> str:
        """Single attempt of the full solve flow."""
        config = self.client.fetch_config(self.site_key, self.site)
        cs = build_attestation(self.site, profile=self._new_profile())
        h: str = config.h
        k = self._pow_nonce(config.raw.get("m"))
        challenge = self.client.challenge(
            config, challenge_type=self.challenge_type, cs=cs, k=k, lang=self.lang
        )
        if challenge.get("token"):
            return str(challenge["token"])
        if challenge.get("h"):
            h = challenge["h"]
        if challenge.get("j"):
            k = self._pow_nonce(challenge["j"])
        mv, elapsed, position = self._solve_slide(challenge.get("challenge") or {})
        verify_payload = {
            "sk": self.site_key,
            "mv": mv,
            "t": elapsed,
            "p": position,
            "h": h,
            "cs": cs,
            "k": k,
            "type": self.challenge_type,
            "host": _hostname(self.site),
        }
        result = self.client.verify(verify_payload)
        token = result.get("token")
        if not token:
            raise CaptchaFoxError(f"verify did not return a token: {result}")
        return str(token)

    def _pow_nonce(self, pow_input: Any) -> int:
        # config.m / challenge.j is the worker message:
        # [tag, seed, difficulty_binary_string]. The tag (index 0) is ignored by
        # the worker; index 1 is the seed, index 2 is the difficulty parsed from a
        # binary string (e.g. "101" -> 5 leading hex zeros).
        if isinstance(pow_input, (list, tuple)) and len(pow_input) == 3:
            seed = str(pow_input[1])
            difficulty = int(str(pow_input[2]), 2)
            return solve_pow(seed, difficulty)
        return 0

    def _solve_slide(self, challenge: dict[str, Any]) -> tuple[list[float], float, float]:
        bg_url = challenge.get("bg")
        if not bg_url:
            raise CaptchaFoxError(f"slide challenge missing bg image: {challenge}")
        gap_x_css = self._detect_gap_x(bg_url)
        position = float(
            max(0.0, min(gap_x_css, self.SLIDE_TRACK_WIDTH_CSS - self.SLIDE_PIECE_SIZE_CSS))
        )
        mv, elapsed = self._synthesize_trail(position)
        return mv, elapsed, position

    def _detect_gap_x(self, bg_url: str) -> float:
        """Detect the slide target (gap) left-edge x in CSS pixels (0..300)."""
        try:
            from PIL import Image
            import numpy as np
        except ImportError as exc:  # pragma: no cover - dependency guarded by install extra
            raise CaptchaFoxError("Pillow/numpy required for slide gap detection") from exc

        if bg_url.startswith("data:"):
            _, b64 = bg_url.split(",", 1)
            raw = base64.b64decode(b64)
        else:
            raw = self.client.http.get(bg_url, timeout=30).content
        img = Image.open(io.BytesIO(raw)).convert("RGB")
        arr = np.asarray(img).astype(int)
        h, w = arr.shape[:2]
        # Background reference: median color per column, then global median, so a
        # large foreground object does not skew the reference.
        col_median = np.median(arr.reshape(h, w, 3), axis=0)
        bg_color = np.median(col_median, axis=0)
        coldist = np.abs(arr - bg_color).mean(axis=(0, 2))
        search_start = int(w * 0.15)
        threshold = coldist.mean() + 1.5 * coldist.std()
        above = coldist > threshold
        # Find contiguous runs; pick the one with the largest total deviation.
        best_left = int(np.argmax(coldist))
        best_score = 0.0
        i = search_start
        while i < w:
            if not above[i]:
                i += 1
                continue
            j = i
            while j < w and above[j]:
                j += 1
            score = float(coldist[i:j].sum())
            if score > best_score:
                best_score = score
                best_left = i
            i = j
        return best_left / w * self.SLIDE_TRACK_WIDTH_CSS

    def _synthesize_trail(self, solution: float, duration: float = 1.35) -> tuple[list[float], float]:
        """Synthesize a human-like slide trail.

        Returns ``(mv, elapsed)`` where ``mv`` is a flat list
        ``[dy0, dx0, dy1, dx1, ...]`` of cumulative offsets (max 80 numbers /
        40 samples) whose final dx equals ``solution``, and elapsed is the drag
        time in seconds (2dp).
        """
        samples = 34
        mv: list[float] = []
        last_x = 0.0
        for i in range(1, samples + 1):
            progress = i / samples
            eased = 0.5 * (1 - math.cos(math.pi * progress))
            x = round(solution * eased, 2)
            dy = round(_random.uniform(-1.2, 1.2), 2)
            mv.append(dy)
            mv.append(x)
            last_x = x
        mv = mv[:80]
        if mv:
            mv[-1] = round(last_x, 2)
        return mv, round(duration, 2)


def _hostname(site: str) -> str:
    parsed = urlsplit(site)
    if not parsed.hostname:
        raise CaptchaFoxError(f"CaptchaFox site must include a hostname: {site}")
    return parsed.hostname
