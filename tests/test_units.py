import hashlib
import json

from captchafox_solver import (
    AttestationProfile,
    build_attestation,
    encode_captchafox_payload,
    random_attestation_profile,
    solve_pow,
)


def test_solve_pow_finds_valid_nonce():
    seed = "ed7ae2ffc6925a88"
    difficulty = 5
    nonce = solve_pow(seed, difficulty)
    digest = hashlib.sha256(f"{seed}{nonce}".encode("utf-8")).hexdigest()
    assert digest.startswith("0" * difficulty)
    # nonce is the smallest such integer
    for n in range(nonce):
        d = hashlib.sha256(f"{seed}{n}".encode("utf-8")).hexdigest()
        assert not d.startswith("0" * difficulty)


def test_encode_captchafox_payload_roundtrips_through_gzip_xor():
    payload = {"lng": "en", "k": 0, "type": "slide"}
    body = encode_captchafox_payload(payload)
    assert body[:2] == bytes([0x01, 0x04])
    deobfuscated = bytes(b ^ ((i + 0x04) & 0xFF) for i, b in enumerate(body[2:]))
    import gzip

    raw = gzip.decompress(deobfuscated)
    assert json.loads(raw) == payload


def test_build_attestation_without_profile_replays_template():
    cs = build_attestation(site="https://example.com/")
    # template carries CF0100-CF0148
    assert set(cs) >= {f"CF0{i:02d}" for i in range(100, 149)}
    assert cs["CF0148"] == "https://example.com/"
    assert isinstance(cs["CF0106"], int)


def test_build_attestation_with_profile_overrides_per_user_fields():
    profile = AttestationProfile(
        dark_mode=True,
        hardware_concurrency=12,
        timezone_offset=-300,
        languages=("en-US", "en"),
        webgl_vendor="Google Inc. (Google)",
        webgl_renderer="ANGLE (Google, Vulkan 1.3.0 (Intel(R) UHD Graphics 630 (0x00003E9B)), Intel-open-source Mesa)",
        screen_width=2560,
        screen_height=1440,
        pixel_ratio=1,
    )
    cs = build_attestation(site="https://example.com/", profile=profile)
    assert cs["CF0101"] is True
    assert cs["CF0105"] == 12
    assert cs["CF0108"] == -300
    assert cs["CF0111"] == ["en-US", "en"]
    assert cs["CF0120"]["width"] == 2560 and cs["CF0120"]["height"] == 1440
    assert cs["CF0121"][1].startswith("ANGLE (Google, Vulkan")
    # UA stays constant (matches HTTP header)
    assert cs["CF0115"].startswith("Mozilla/5.0 (X11; Linux x86_64)")


def test_random_profiles_are_consistent_and_varied():
    p1 = random_attestation_profile()
    p2 = random_attestation_profile()
    cs1 = build_attestation(profile=p1)
    assert cs1["CF0120"]["width"] == p1.screen_width
    # the per-user fields are within the documented pools
    assert p1.hardware_concurrency in (4, 8, 12, 16, 32)
