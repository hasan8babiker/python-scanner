#!/usr/bin/env python3
"""Look up known CVEs for detected service versions using the NVD API 2.0.

Usage:
    python3 cve_lookup.py "Apache httpd" 2.4.49
    python3 cve_lookup.py OpenSSH 8.2p1 --min-score 7 --top 5
    python3 cve_lookup.py --scan scan.json          # output of scanner.py --json

Optional: export NVD_API_KEY=... (free from nvd.nist.gov) for ~10x higher rate limits.

Results are LEADS, not proof: banners can be spoofed, and distros (Ubuntu, Debian,
RHEL) backport security fixes without changing the version string.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = Path(__file__).with_name(".cve_cache.json")
CACHE_TTL = 24 * 3600

# product name from scanner.py -> (CPE vendor, CPE product)
CPE_MAP = {
    "OpenSSH": ("openbsd", "openssh"),
    "Apache httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "vsFTPd": ("beasts", "vsftpd"),
    "ProFTPD": ("proftpd", "proftpd"),
    "Exim": ("exim", "exim"),
    "Postfix": ("postfix", "postfix"),
    "Dovecot": ("dovecot", "dovecot"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "Microsoft IIS": ("microsoft", "internet_information_services"),
    "MySQL": ("oracle", "mysql"),
    "MariaDB": ("mariadb", "mariadb"),
    "Dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "": 4}


def build_cpe(product: str, version: str):
    """cpe:2.3 string for a known product/version, or None if we can't map it."""
    if product not in CPE_MAP:
        return None
    m = re.match(r"(\d+(?:\.\d+)*)(p\d+)?", version)  # OpenSSH '8.2p1' -> 8.2 + update p1
    if not m:
        return None
    base, update = m.groups()
    vendor, prod = CPE_MAP[product]
    fields = [base, update or "*"] + ["*"] * 6
    return f"cpe:2.3:a:{vendor}:{prod}:" + ":".join(fields)


def load_cache() -> dict:
    try:
        return json.loads(CACHE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def save_cache(cache: dict) -> None:
    try:
        CACHE_FILE.write_text(json.dumps(cache))
    except OSError:
        pass


_last_request = 0.0


def nvd_get(params: dict, api_key: str | None) -> dict:
    """GET from NVD, respecting its rate limit (5 req/30s without key, 50 with)."""
    global _last_request
    gap = 0.7 if api_key else 6.5
    wait = gap - (time.time() - _last_request)
    if wait > 0:
        time.sleep(wait)
    url = f"{NVD_URL}?{urllib.parse.urlencode(params, safe=':*')}"
    headers = {"User-Agent": "cve-lookup/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    for attempt in range(3):
        _last_request = time.time()
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503) and attempt < 2:
                time.sleep(10 * (attempt + 1))
                continue
            raise
    return {}


def best_cvss(cve: dict):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            entry = metrics[key][0]
            data = entry["cvssData"]
            return data.get("baseScore"), (data.get("baseSeverity") or entry.get("baseSeverity") or "").upper()
    return None, ""


def parse_cves(payload: dict) -> list[dict]:
    out = []
    for item in payload.get("vulnerabilities", []):
        cve = item["cve"]
        score, sev = best_cvss(cve)
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        out.append({
            "id": cve["id"],
            "score": score,
            "severity": sev,
            "published": cve.get("published", "")[:10],
            "kev": "cisaExploitAdd" in cve,  # on CISA's Known Exploited Vulnerabilities list
            "description": " ".join(desc.split()),
        })
    out.sort(key=lambda c: (-(c["score"] or 0), c["id"]))
    return out


def lookup(product: str, version: str, api_key: str | None, cache: dict) -> list[dict]:
    cpe = build_cpe(product, version)
    if cpe:
        params = {"cpeName": cpe, "isVulnerable": "", "resultsPerPage": 2000}
        key = cpe
    else:
        params = {"keywordSearch": f"{product} {version}", "resultsPerPage": 200}
        key = f"kw:{product} {version}"
    hit = cache.get(key)
    if hit and time.time() - hit["t"] < CACHE_TTL:
        return hit["cves"]
    cves = parse_cves(nvd_get(params, api_key))
    cache[key] = {"t": time.time(), "cves": cves}
    return cves


def show(product: str, version: str, cves: list[dict], top: int, min_score: float) -> None:
    shown = [c for c in cves if (c["score"] or 0) >= min_score]
    print(f"\n== {product} {version}: {len(cves)} CVEs found, {len(shown)} at CVSS >= {min_score} ==")
    for c in shown[:top]:
        score = f"{c['score']:.1f}" if c["score"] is not None else " n/a"
        flag = " [KEV]" if c["kev"] else ""
        print(f"{c['id']:<16}{score:>5} {c['severity']:<9}{c['published']}{flag}")
        print(f"    {c['description'][:150]}")
    if len(shown) > top:
        print(f"    ... {len(shown) - top} more (use --top N)")
    if any(c["kev"] for c in shown):
        print("    [KEV] = listed in CISA's Known Exploited Vulnerabilities catalog: patch first.")


def main() -> int:
    ap = argparse.ArgumentParser(description="CVE lookup for detected service versions (NVD API 2.0)")
    ap.add_argument("product", nargs="?", help='e.g. "Apache httpd", OpenSSH, nginx')
    ap.add_argument("version", nargs="?", help="e.g. 2.4.49, 8.2p1")
    ap.add_argument("--scan", metavar="FILE", help="JSON from scanner.py --json")
    ap.add_argument("--min-score", type=float, default=0.0, help="hide CVEs below this CVSS score")
    ap.add_argument("--top", type=int, default=10, help="CVEs to show per service (default 10)")
    ap.add_argument("--json", metavar="FILE", help="save full results as JSON")
    args = ap.parse_args()

    targets = []
    if args.scan:
        data = json.load(open(args.scan))
        for p in data["ports"]:
            if p.get("product") and p.get("version"):
                targets.append((p["product"], p["version"]))
        if not targets:
            print("No product/version pairs in scan file (nothing to look up).")
            return 0
    elif args.product and args.version:
        targets.append((args.product, args.version))
    else:
        ap.error("give PRODUCT VERSION, or --scan FILE")

    api_key = os.environ.get("NVD_API_KEY")
    cache = load_cache()
    report = {}
    for product, version in dict.fromkeys(targets):  # de-duplicate, keep order
        try:
            cves = lookup(product, version, api_key, cache)
        except (urllib.error.URLError, OSError, ValueError) as e:
            print(f"\n{product} {version}: lookup failed ({e})", file=sys.stderr)
            continue
        report[f"{product} {version}"] = cves
        show(product, version, cves, args.top, args.min_score)
    save_cache(cache)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON saved to {args.json}")
    print("\nNote: matches are leads. Verify against the real package version (backports) before reporting.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
