#!/usr/bin/env python3
# xdr_ioc_upsert_from_sources.py
# Upload indicators to Cortex XDR using /public_api/v1/indicators/insert_jsons
# - Reads SOURCES (comma-separated file paths) from env
# - Parses domains, IPs, hashes (MD5/SHA1/SHA256), filenames
# - Adds vendor/severity/comment
# - Batches uploads and prints rich error info (status + response body) on failures
# - Writes parse rejects & API errors to artifacts/rejects.json (for GH Actions upload)

import os, re, sys, json, time, pathlib, ipaddress, hashlib
from typing import List, Dict, Tuple
import requests

# -------- Config from env --------
BASE   = os.environ["XDR_BASE_URL"].rstrip("/")
API_ID = os.environ["XDR_API_ID"]
APIKEY = os.environ["XDR_API_KEY"]

SOURCES = [s.strip() for s in os.environ.get(
    "SOURCES", "fqdnlist.txt,iplist.txt,hashlist.txt"
).split(",") if s.strip()]

VENDOR       = os.environ.get("VENDOR", "ONO-RBL")
SEVERITY     = os.environ.get("SEVERITY", "high").upper()  # INFO|LOW|MEDIUM|HIGH|CRITICAL
COMMENT_TAG  = os.environ.get("COMMENT_TAG", "Imported from GitHub")
BATCH_SIZE   = max(1, int(os.environ.get("BATCH_SIZE", "1000")))
FAIL_ON_ERROR = os.environ.get("FAIL_ON_ERROR", "1") == "1"

ARTIFACT_DIR = pathlib.Path("artifacts"); ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
REJECTS_PATH = ARTIFACT_DIR / "rejects.json"

# -------- HTTP helpers --------
HEADERS = {
    "Authorization": APIKEY,
    "x-xdr-auth-id": str(API_ID),
    "Content-Type": "application/json",
    "Accept": "application/json",
}
INSERT_URL = f"{BASE}/public_api/v1/indicators/insert_jsons"

def post_with_debug(url: str, payload: dict, timeout: int = 120, max_retries: int = 6) -> dict:
    """POST with verbose debug on error (status, json/text body), retrying throttles/5xx/599."""
    backoff = 2
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(url, headers=HEADERS, json=payload, timeout=timeout)
            if resp.status_code in (429, 500, 502, 503, 504, 599):
                ra = resp.headers.get("Retry-After")
                sleep = int(ra) if ra and ra.isdigit() else backoff
                print(f"[retry] HTTP {resp.status_code} sleeping {sleep}s (attempt {attempt}/{max_retries})")
                time.sleep(sleep)
                backoff = min(int(backoff * 2), 90)
                continue

            if resp.status_code >= 400:
                print(f"[HTTP] {resp.status_code} {resp.reason}")
                try:
                    print("[API JSON]:", json.dumps(resp.json(), indent=2)[:4000])
                except Exception:
                    print("[API TEXT]:", resp.text[:4000])
                resp.raise_for_status()

            # OK
            try:
                js = resp.json()
            except Exception:
                print("[WARN] Non-JSON response body:")
                print(resp.text[:4000])
                js = {}
            return js

        except requests.RequestException as e:
            # network/timeout/parsing
            if attempt == max_retries:
                print(f"[error] {e}")
                raise
            print(f"[retry] {e}; backoff {backoff}s")
            time.sleep(backoff)
            backoff = min(int(backoff * 2), 90)

    # Should never hit here
    raise RuntimeError("unreachable")

# -------- parsing helpers --------
RE_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_FQDN   = re.compile(r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$")
RE_FILENAME = re.compile(r"[\\/]?[^\\/:*?\"<>|\r\n]+$")  # very loose

def classify_indicator(s: str) -> Tuple[str, str]:
    """
    Returns (type, normalized_value) or ("", "") if unsupported.
    - DOMAIN_NAME
    - IP
    - HASH  (MD5/SHA1/SHA256)
    - FILENAME
    """
    t = s.strip().strip(",;")
    if not t: return "", ""
    # common garbage
    if t.lower() in ("null", "none", "n/a", "-"): return "", ""

    # strip scheme/path/query for domain-like lines
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    t = t.split("?", 1)[0]

    # IP (no CIDR)
    try:
        ip = ipaddress.ip_address(t)
        return "IP", str(ip)
    except Exception:
        pass
    if "/" in t:
        # CIDR is not supported by XDR indicators
        return "", ""

    # Hashes
    if RE_MD5.match(t):    return "HASH", t.lower()
    if RE_SHA1.match(t):   return "HASH", t.lower()
    if RE_SHA256.match(t): return "HASH", t.lower()

    # Domain
    if RE_FQDN.match(t):
        return "DOMAIN_NAME", t.lower()

    # Filename (last resort – only if it looks like a bare name, not a URL)
    if RE_FILENAME.match(t) and "." in t and " " not in t and "://" not in t:
        return "FILENAME", t

    return "", ""

def read_lines(path: pathlib.Path) -> List[str]:
    try:
        return [ln.rstrip("\n") for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines()]
    except FileNotFoundError:
        print(f"[warn] missing source: {path}")
        return []

def parse_sources(paths: List[str]) -> Tuple[List[dict], List[dict]]:
    parsed: List[dict] = []
    rejects: List[dict] = []
    total_lines = 0

    for p in paths:
        pth = pathlib.Path(p)
        lines = read_lines(pth)
        total_lines += len(lines)
        print(f"[src] {pth.name}")
        for raw in lines:
            s = raw.strip()
            if not s: continue
            ioc_type, value = classify_indicator(s)
            if not value:
                rejects.append({"source": pth.name, "line": s, "reason": "unsupported/unknown"})
                continue
            parsed.append({
                "indicator": value,
                "type": ioc_type,
                "severity": SEVERITY,
                "reputation": "BAD",
                "comment": COMMENT_TAG,
                "vendor": {"name": VENDOR},
            })

    # de-duplicate by (type, indicator)
    seen = set()
    unique: List[dict] = []
    for it in parsed:
        key = (it["type"], it["indicator"])
        if key in seen: continue
        seen.add(key)
        unique.append(it)

    print(f"[parse] files={len(paths)} lines_total={total_lines} parsed={len(unique)} rejected={len(rejects)}")
    return unique, rejects

# -------- main --------
def main():
    indicators, rejects = parse_sources(SOURCES)

    uploaded = 0
    api_errors: List[dict] = []

    print("Using endpoint:", INSERT_URL)
    # Batch
    for i in range(0, len(indicators), BATCH_SIZE):
        chunk = indicators[i:i+BATCH_SIZE]
        body = {"request_data": {"indicators": chunk}}

        # The friend’s idea: show detailed server response on error
        try:
            js = post_with_debug(INSERT_URL, body, timeout=120, max_retries=6)
        except Exception as e:
            api_errors.append({"batch_from": i+1, "batch_to": i+len(chunk), "error": str(e)})
            print(f"[batch] ERROR on {i+1}-{i+len(chunk)}: {e}")
            continue

        # Some tenants return {"reply": true}, others include more details
        ok = bool(js.get("reply", True))
        if not ok:
            api_errors.append({"batch_from": i+1, "batch_to": i+len(chunk), "error": js})
            print(f"[batch] server replied not-ok on {i+1}-{i+len(chunk)}: {json.dumps(js)[:4000]}")
            continue

        uploaded += len(chunk)
        print(f"[batch] {i+1}-{i+len(chunk)} / {len(indicators)}")

    # Write rejects for GH artifact
    with open(REJECTS_PATH, "w", encoding="utf-8") as f:
        json.dump({"parse_rejects": rejects, "api_errors": api_errors}, f, indent=2)

    print(f"[done] uploaded={uploaded} rejected_parse={len(rejects)} api_errors={len(api_errors)}")
    if FAIL_ON_ERROR and (uploaded == 0 or api_errors):
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
