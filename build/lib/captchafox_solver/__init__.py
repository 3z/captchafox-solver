"""captchafox_solver — a pure-Python CaptchaFox challenge solver.

A standalone library and CLI that replays a real-Chrome browser attestation,
solves the proof-of-work, and solves the slide challenge against the CaptchaFox
API to obtain a verified response token. No browser is used in the runtime path.

For authorized security testing only.
"""

from .attestation import AttestationProfile, build_attestation, random_attestation_profile
from .client import (
    CAPTCHAFOX_TEST_SECRET,
    CAPTCHAFOX_TEST_SITE_KEY,
    CaptchaFoxClient,
    CaptchaFoxConfig,
)
from .encoding import encode_captchafox_payload
from .exceptions import CaptchaFoxError
from .pow import solve_pow
from .solver import CaptchaFoxSolver

__version__ = "0.1.0"

__all__ = [
    "AttestationProfile",
    "build_attestation",
    "random_attestation_profile",
    "CaptchaFoxClient",
    "CaptchaFoxConfig",
    "CaptchaFoxError",
    "CaptchaFoxSolver",
    "encode_captchafox_payload",
    "solve_pow",
    "CAPTCHAFOX_TEST_SITE_KEY",
    "CAPTCHAFOX_TEST_SECRET",
    "__version__",
]
