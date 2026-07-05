#!/usr/bin/env python3
"""Stress-test the CaptchaFox solver at scale against the live API.

Solves N captchas concurrently through an HTTP proxy (e.g. a residential
rotating proxy to avoid IP-based rate limiting), then reports the success rate,
latency distribution, and a categorized failure breakdown.

For authorized security testing only. Hits the live CaptchaFox API.

Usage:
    CAPTCHAFOX_PROXY='http://user:pass@proxy.resi.gg:12321' \
        python3 scripts/stress_test.py --site-key sk_... --total 100 --workers 8
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
import concurrent.futures

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from captchafox_solver import CaptchaFoxClient, CaptchaFoxSolver  # noqa: E402
from captchafox_solver.client import DEFAULT_CAPTCHAFOX_SITE  # noqa: E402


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * (pct / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def _categorize(error: str) -> str:
    e = error.lower()
    if "proxy" in e or "connection" in e or "timed out" in e or "max retries" in e:
        return "network/proxy"
    if "429" in e or "rate" in e:
        return "rate-limited"
    if "400" in e or "badrequest" in e:
        return "attestation-rejected"
    if "verify did not return" in e:
        return "solve-failed"
    return "other"


def _make_client(proxy: str | None, timeout: int) -> CaptchaFoxClient:
    session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return CaptchaFoxClient(http=session, timeout=timeout)


def _solve_one(site_key: str, site: str, proxy: str | None, timeout: int) -> dict:
    solver = CaptchaFoxSolver(client=_make_client(proxy, timeout), site_key=site_key, site=site)
    t0 = time.time()
    try:
        token = solver.solve()
        return {"ok": True, "token": token, "elapsed": time.time() - t0}
    except Exception as exc:  # noqa: BLE001 - record any failure
        return {"ok": False, "error": str(exc)[:200], "elapsed": time.time() - t0}


def _tglog(message: str) -> None:
    binary = shutil.which("tglog")
    if binary:
        subprocess.run([binary, message], check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--total", type=int, default=100, help="Total solves to attempt (default 100)")
    parser.add_argument("--workers", type=int, default=8, help="Concurrent workers (default 8)")
    parser.add_argument("--site-key", required=True, help="CaptchaFox sitekey to solve")
    parser.add_argument("--site", default=DEFAULT_CAPTCHAFOX_SITE, help="Page site URL")
    parser.add_argument("--proxy", default=os.getenv("CAPTCHAFOX_PROXY"), help="HTTP proxy URL (or env CAPTCHAFOX_PROXY)")
    parser.add_argument("--request-timeout", type=int, default=20, help="Per-request timeout seconds (default 20)")
    parser.add_argument("--output", default=None, help="Write JSON summary to this path")
    parser.add_argument("--tglog", action="store_true", help="Send the summary to tglog")
    args = parser.parse_args()

    print(f"stress test: total={args.total} workers={args.workers} proxy={'yes' if args.proxy else 'no'}")
    results: list[dict] = []
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(_solve_one, args.site_key, args.site, args.proxy, args.request_timeout)
            for _ in range(args.total)
        ]
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            r = fut.result()
            results.append(r)
            tag = "OK" if r["ok"] else f"FAIL[{_categorize(r['error'])}]"
            extra = r["token"][:18] + "..." if r["ok"] else r["error"][:50]
            print(f"[{i:>3}/{args.total}] {r['elapsed']:5.1f}s  {tag}  {extra}")

    wall = time.time() - start
    ok = [r for r in results if r["ok"]]
    fail = [r for r in results if not r["ok"]]
    elapsed = [r["elapsed"] for r in ok]
    failure_cats: dict[str, int] = {}
    for r in fail:
        failure_cats[_categorize(r["error"])] = failure_cats.get(_categorize(r["error"]), 0) + 1

    summary = {
        "total": args.total,
        "success": len(ok),
        "failed": len(fail),
        "success_rate": round(len(ok) / args.total, 4),
        "workers": args.workers,
        "wall_time_s": round(wall, 1),
        "throughput_solves_per_s": round(len(ok) / wall, 2) if wall else 0,
        "latency_s": {
            "min": round(min(elapsed), 2) if elapsed else None,
            "median": round(statistics.median(elapsed), 2) if elapsed else None,
            "p95": round(_percentile(elapsed, 95), 2) if elapsed else None,
            "max": round(max(elapsed), 2) if elapsed else None,
            "mean": round(statistics.mean(elapsed), 2) if elapsed else None,
        },
        "failure_breakdown": failure_cats,
    }
    print("\n=== summary ===")
    print(json.dumps(summary, indent=2))

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(summary, fh, indent=2)
        print(f"\nwrote {args.output}")

    if args.tglog:
        _tglog(
            f"<b>CaptchaFox stress test</b>: {summary['success']}/{summary['total']} "
            f"({summary['success_rate']*100:.1f}%) in {summary['wall_time_s']}s "
            f"@ {summary['throughput_solves_per_s']}/s. failures={summary['failure_breakdown']}"
        )
    return 0 if summary["success_rate"] >= 1.0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
