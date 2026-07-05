from __future__ import annotations

import gzip
import json
from typing import Any


def encode_captchafox_payload(payload: dict[str, Any]) -> bytes:
    """Encode the ``text/plain`` POST body used by CaptchaFox challenge/verify calls.

    Pipeline: ``json.dumps`` (compact) -> UTF-8 -> gzip -> prefix ``[0x01, 0x04]``
    -> XOR each byte with ``(index + 0x04) & 0xFF``.
    """
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    compressed = gzip.compress(raw)
    return bytes([0x01, 0x04]) + bytes(
        byte ^ ((index + 0x04) & 0xFF) for index, byte in enumerate(compressed)
    )
