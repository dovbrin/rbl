#!/usr/bin/env python3
"""
Push indicators from flat files to Cortex XDR via public API.

Env:
  XDR_BASE_URL   (e.g. https://api-ono.xdr.eu.paloaltonetworks.com)
  XDR_API_ID     (e.g. 16)
  XDR_API_KEY    (the long API key string)
  SOURCES        comma-separated file list, e.g. "fqdnlist.txt,iplist.txt,hashlist.txt"
  VENDOR         e.g. "ONO-RBL"
  SEVERITY       one of INFO/LOW/MEDIUM/HIGH/CRITICAL (default HIGH)
  COMMENT_TAG    e.g. "Imported from GitHub"
  BATCH_SIZE     default 1000
  FAIL_ON_ERROR  default '0' (do not fail the workflow if some batches error)

Writes rejects to artifacts/rejects.json
"""

import os, sys, re, json, time, pathlib
from typing import List, Tuple, Dict
import requests

BASE   = os.environ["XDR_BASE_URL"].rstrip("/")
API_ID = str(os.environ["XDR_API_ID"])
APIKEY = os.environ["XDR_API_KEY"]

SOURCES     = [s.strip() for s in os.environ.get("SOURCES","").split(",") if s.strip()]
VENDOR      = os.environ.get("VENDOR","ONO-RBL")
SEVERITY    = os.environ.get("SEVERITY","HIGH").upper()
COMMENT_TAG = os.environ.get("COMMENT_TAG","Imported from GitHub")
BATCH_SIZE  = max(1, int(os.environ.get("BATCH_SIZE","1000")))
FAIL_ON_ERR = os.environ.get("FAIL_ON_ERROR","0") == "1"

HEADERS = {
    "Authorization": APIKEY,
    "x-xdr-auth-id": API_ID,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

ALLOWED_SEV = {"INFO","LOW","MEDIUM","HIGH","CRITICAL"}

# ---------- parsing helpers ----------
_re_ipv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_re_md5  = re.compile(r"^[A-Fa-f0-9]{32}$")
_re_sha1 = re.compile(r"^[A-Fa-f0-9]{40}$")
_re_sha256 = re.compile(r"^[A-Fa-f0-9]{64}$")
# lenient domain (no protocol, no spaces)
_re_domain = re.compile(r"^(?=.{1,253}$)(?!\-)([A-Za-z0-9\-]{1,63}\.)+[A-Za-z0-9\-]{2,63}$")

def classify(line: str) -> Tuple[str,str]:
    """
    Returns (type, indicator) or ("","") if reject.
    - Skips CIDR (contains '/')
    - Skips obvious URLs (contains '://')
    - Skips lines with spaces or leading '#'
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return "",""
    # common junk at end
    s = s.rstrip(",;")
    # reject URL/CIDR
    if "://" in s or "/" in s:
        return "",""
    # unicode oddities: normalize dot or chars
    s = s.replace("ọ","o").replace("’","'").replace("`","'").strip()

    # IP?
    if _re_ipv4.match(s):
        # light bound check
        parts = [int(p) for p in s.split(".")]
        if all(0 <= p <= 255 for p in parts):
            return "IP", s
        return "",""

    # HASH?
    if _re_md5.match(s) or _re_sha1.match(s) or _re_sha256.match(s):
        return "HASH", s.lower()

    # DOMAIN?
    # allow leading '*.' by stripping it (XDR expects bare FQDNs)
    s_dom = s[2:] if s.startswith("*.") else s
    if _re_domain.match(s_dom):
        return "DOMAIN_NAME", s_dom.lower()

    return "",""

def parse_sources(files: List[str]) -> Tuple[List[dict], List[dict]]:
    indicators: List[dict] = []
    rejects: List[dict] = []

    for path in files:
        print(f"[src] {path}")
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for ln, raw in enumerate(f, 1):
                    t, ind = classify(raw)
                    if not t:
                        rejects.append({"source": path, "line": ln, "value": raw.strip(), "reason": "unknown/unsupported"})
                        continue
                    indicators.append({
                        "indicator": ind,
                        "type": t,
                        "severity": SEVERITY if SEVERITY in ALLOWED_SEV else "HIGH",
                        "comment": COMMENT_TAG,
                        "vendor": {"name": VENDOR},
                    })
        except FileNotFoundError:
            print(f"[warn] file not found: {path}")
        except Exception as e:
            print(f"[warn] error reading {path}: {e}")

    # de-dup by (type,indicator)
    seen = set()
    uniq = []
    for d in indicators:
        k = (d["type"], d["indicator"])
        if k in seen: continue
        seen.add(k)
        uniq.append(d)

    print(f"[parse] files={len(files)} lines_total={len(indicators)+len(rejects)} parsed={len(uniq)} rejected={len(rejects)}")
    return uniq, rejects

# ---------- HTTP with retries ----------
def post_json(url: str, payload: dict, session: requests.Session, max_retries=6, timeout=120) -> requests.Response:
    back = 2
    for i in range(1, max_retries+1):
        r = None
        try:
            r = session.post(url, headers=HEADERS, json=payload, timeout=timeout)
            if r.status_code in (429,500,502,503,504,599):
                ra = r.headers.get("Retry-After")
                sleep = int(ra) if ra and ra.isdigit() else back
                print(f"[retry] HTTP {r.status_code} sleeping {sleep}s (attempt {i}/{max_retries})")
                time.sleep(sleep); back = min(int(back*2.2), 90)
                continue
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            if i == max_retries:
                raise
            print(f"[retry] {e}; backoff {back}s")
            time.sleep(back); back = min(int(back*2.2), 90)
    return r  # type: ignore

# ---------- main ----------
def main():
    if not SOURCES:
        print("No SOURCES specified.")
        sys.exit(1)

    items, rejects = parse_sources(SOURCES)
    pathlib.Path("artifacts").mkdir(exist_ok=True)
    if rejects:
        with open("artifacts/rejects.json","w",encoding="utf-8") as f:
            json.dump(rejects, f, ensure_ascii=False, indent=2)

    url = f"{BASE}/public_api/v1/indicators/insert_jsons"
    print(f"Using endpoint: {url}")

    uploaded = 0
    api_errors = 0
    with requests.Session() as s:
        for i in range(0, len(items), BATCH_SIZE):
            chunk = items[i:i+BATCH_SIZE]
            body = {"request_data": {"indicators": chunk}}
            lo = i+1; hi = i+len(chunk)
            print(f"[batch] {lo}-{hi} / {len(items)}")
            try:
                r = post_json(url, body, s, max_retries=6, timeout=180)
                js = {}
                try:
                    js = r.json()
                except Exception:
                    pass
                # XDR returns {"reply": true} on success
                if not js or not js.get("reply", True):
                    api_errors += len(chunk)
            except Exception as e:
                api_errors += len(chunk)
                print(f"[batch] ERROR: {e}")

            uploaded += len(chunk)

    print(f"[done] uploaded={uploaded} rejected_parse={len(rejects)} api_errors={api_errors}")
    if api_errors and FAIL_ON_ERR:
        sys.exit(2)
    sys.exit(0)

if __name__ == "__main__":
    main()
