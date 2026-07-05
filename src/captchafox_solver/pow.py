from __future__ import annotations

import hashlib


def solve_pow(seed: str, difficulty: int) -> int:
    """Solve a CaptchaFox proof-of-work puzzle.

    Returns the smallest non-negative integer ``nonce`` such that the lowercase
    hex digest of ``sha256(seed + str(nonce))`` starts with ``difficulty`` leading
    ``0`` characters. This mirrors the embedded Web Worker in ``w.Shqqe3Mz.js``,
    which hashes ``seed + nonce.toString()`` with standard SHA-256 and accepts a
    hash whose hex begins with the requested number of zeros.
    """
    target = "0" * difficulty
    nonce = 0
    while True:
        digest = hashlib.sha256(f"{seed}{nonce}".encode("utf-8")).hexdigest()
        if digest.startswith(target):
            return nonce
        nonce += 1
