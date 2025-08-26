#!/usr/bin/env python3
"""
Push indicators from simple flat files to Cortex XDR:
 - SOURCES env: comma-separated list of files (e.g. "fqdnlist.txt,iplist.txt,hashlist.txt")
 - Accepts: domains, IPs (single IP; '/32' normalized to IP), hashes (MD5/SHA1/SHA256)
 - Skips CIDR/ranges that XDR does not support
 - Uses /public_api/v1/indicators/insert_jsons with proper headers
 - Retries on 429/5xx/599
 - Writes parse rejects to artifacts/rejects.json (picked up by workflow)
"""

import os, re, json, time, sys
from typing import List, Tuple, Dict, Set
import requests

BASE   = os.environ["XDR_BASE_URL"].rstrip("/")
AUTHID = os.environ["XDR_API_ID"]
APIKEY = os.environ["XDR_API_KEY"]

SOURCES = [s.strip() for s in (os.getenv("SOURCES","fqdnlist.txt,iplist.txt,hashlist.txt")).split(",") if s.strip()]
VENDOR  = os.getenv("VENDOR","ONO-RBL")
SEV     = os.getenv("SEVERITY","high").strip().upper()      # INFO/LOW/MEDIUM/HIGH/CRITICAL
COMMENT = os.getenv("COMMENT_TAG","Imported from GitHub")
BATCH   = max(1, min(1000, int(os.getenv("BATCH_SIZE","1000"))))

HEADERS = {
  "Authorization": APIKEY,
  "x-xdr-auth-id": AUTHID,
  "Content-Type": "application/json",
  "Accept": "application/json",
}

os.makedirs("artifacts", exist_ok=True)
rejects_path = "artifacts/rejects.json"

# ---------- parsers ----------
HEX = re.compile(r'^[0-9a-fA-F]+$')
DOMAIN = re.compile(r'^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$')
IPV4 = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')

def normalize_domain(s: str) -> str:
    s = s.strip().strip(",;")
    # strip protocol/URL if present
    if "://" in s or "/" in s:
        try:
            from urllib.parse import urlparse
            u = urlparse(s if "://" in s else "http://" + s)
            host = (u.hostname or "").strip().strip(".")
            return host
        except Exception:
            pass
    return s.strip().strip(".")

def parse_line(line: str) -> Tuple[str,str]:
    """
    Returns (indicator, type) where type in {DOMAIN_NAME, IP, HASH}
    Raises ValueError for unsupported/invalid.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        raise ValueError("empty/comment")

    # CIDR?
    if "/" in s:
        # allow /32 as just IP
        base, mask = s.split("/", 1)
        if mask == "32" and IPV4.match(base):
            return (base, "IP")
        raise ValueError("CIDR not supported")

    # IP
    if IPV4.match(s):
        return (s, "IP")

    # Hash (md5/sha1/sha256)
    if HEX.match(s):
        n = len(s)
        if n in (32, 40, 64):
            return (s.lower(), "HASH")
        raise ValueError("unknown hash length")

    # Domain
    d = normalize_domain(s)
    if DOMAIN.match(d):
        return (d.lower(), "DOMAIN_NAME")

    raise ValueError("unknown format")

def load_sources(files: List[str]) -> Tuple[List[Tuple[str,str]], Dict[str,List[str]]]:
    parsed: List[Tuple[str,str]] = []
    rejects: Dict[str,List[str]] = {}
    total_lines = 0
    for path in files:
        if not os.path.isfile(path):
            print(f"[warn] missing source file: {path}")
            continue
        print(f"[src] {path}")
        rej_local: List[str] = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                total_lines += 1
                s = line.strip()
                if not s or s.startswith("#"): continue
                try:
                    ind, typ = parse_line(s)
                    parsed.append((ind, typ))
                except ValueError as e:
                    msg = str(e)
                    if msg not in ("empty/comment",):
                        print(f"[skip] {msg}: {s}")
                        rej_local.append(s)
        if rej_local:
            rejects[path] = rej_local
    print(f"[parse] files={len(files)} lines_total={total_lines} parsed={len(parsed)} rejected={sum(len(v) for v in rejects.values())}")
    return parsed, rejects

# ---------- uploader ----------
def post(uri: str, body: dict, max_retries=6, timeout=120) -> dict:
    backoff = 2
    for attempt in range(1, max_retries+1):
        try:
            r = requests.post(uri, headers=HEADERS, json=body, timeout=timeout)
            if r.status_code in (429,500,502,503,504,599):
                ra = r.headers.get("Retry-After")
                sleep = int(ra) if ra and ra.isdigit() else backoff
                print(f"[retry] HTTP {r.status_code} sleeping {sleep}s (attempt {attempt}/{max_retries})")
                time.sleep(sleep)
                backoff = min(int(backoff*2.2), 90)
                continue
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            if attempt == max_retries: raise
            print(f"[retry] {e}; backoff {backoff}s")
            time.sleep(backoff)
            backoff = min(int(backoff*2.2), 90)
    return {}

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]

def main():
    items, rejects = load_sources(SOURCES)
    # de-duplicate by (indicator, type)
    dedup: List[Tuple[str,str]] = list(dict.fromkeys(items))
    if rejects:
        with open(rejects_path, "w", encoding="utf-8") as f:
            json.dump(rejects, f, ensure_ascii=False, indent=2)

    total = len(dedup)
    if total == 0:
        print("[done] nothing to upload")
        return

    print("Using endpoint: {}/public_api/v1/indicators/insert_jsons".format(BASE))
    uploaded = 0
    for i, batch in enumerate(chunks(dedup, BATCH), start=1):
        inds = []
        for ind, typ in batch:
            inds.append({
                "indicator": ind,
                "type": typ,                  # HASH | IP | DOMAIN_NAME
                "severity": SEV,              # INFO/LOW/MEDIUM/HIGH/CRITICAL
                "reputation": "BAD",
                "comment": COMMENT,
                "vendor": {"name": VENDOR},
                "default_expiration_enabled": True
            })
        body = {"request_data": {"indicators": inds}}
        a = (i-1)*BATCH + 1
        b = min(i*BATCH, total)
        print(f"[batch] {a}-{b} / {total}")
        js = post(f"{BASE}/public_api/v1/indicators/insert_jsons", body)
        if not js.get("reply", False):
            print(f"[batch] server reply was false for {a}-{b}")

        uploaded += len(batch)

    print(f"[done] uploaded={uploaded} rejected_parse={sum(len(v) for v in (rejects or {}).values())}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[fatal] {e}")
        sys.exit(1)
