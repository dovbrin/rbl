# xdr_ioc_upsert_from_sources.py
# Push IOCs from flat text files to Cortex XDR using /indicators/insert_jsons
# - Reads SOURCES env (comma-separated file names in repo root)
# - Supports DOMAIN_NAME, IP (single IP only), HASH (md5/sha1/sha256)
# - Skips CIDR/ranges and malformed lines, emits a rejects JSONL file
# - Uses small batches + keep-alive + backoff; retries 429/5xx/599

import os, re, sys, json, time, hashlib, ipaddress, random
from typing import List, Tuple, Dict
import requests

BASE   = os.environ["XDR_BASE_URL"].rstrip("/")
API_ID = os.environ["XDR_API_ID"]
APIKEY = os.environ["XDR_API_KEY"]

SOURCES = [s.strip() for s in os.environ.get("SOURCES","").split(",") if s.strip()]
VENDOR  = os.environ.get("VENDOR","ONO-RBL")
SEVERITY= os.environ.get("SEVERITY","high").upper()       # INFO/LOW/MEDIUM/HIGH/CRITICAL
COMMENT = os.environ.get("COMMENT_TAG","Imported from GitHub")
BATCH_SIZE = max(50, min( int(os.environ.get("BATCH_SIZE","200")), 1000 ))

OUT_REJECTS = os.environ.get("REJECTS_PATH","artifacts/rejects.json")
os.makedirs(os.path.dirname(OUT_REJECTS), exist_ok=True)

# ---------- helpers ----------
_dom_re = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
_hex_re = re.compile(r"^[0-9a-fA-F]+$")

def is_hash(s: str) -> Tuple[bool,str]:
    n = len(s)
    if n == 32 and _hex_re.match(s):   return True, "HASH"     # md5
    if n == 40 and _hex_re.match(s):   return True, "HASH"     # sha1
    if n == 64 and _hex_re.match(s):   return True, "HASH"     # sha256
    return False, ""

def to_record(line: str) -> Tuple[Dict, str]:
    """Return (record, reject_reason). record is None when reject_reason set."""
    raw = line.strip()
    if not raw: return None, "empty"
    # remove trailing commas/spaces
    raw = raw.strip(", ").strip()
    # reject obvious junk
    if any(c in raw for c in [" ", "\t", "/", "\\", "http://", "https://"]):
        # CIDR or URL or path — not supported
        # but allow a single IPv6 which contains ":" — handle separately
        if ":" in raw and "://" not in raw and "/" not in raw:
            # try IPv6 ip
            try:
                ipaddress.ip_address(raw)
                return {
                    "indicator": raw,
                    "type": "IP",
                    "severity": SEVERITY,
                    "reputation": "BAD",
                    "vendor": {"name": VENDOR},
                    "comment": COMMENT
                }, ""
            except Exception:
                return None, "unknown format"
        return None, "unknown format"

    # IP (v4)
    try:
        ipaddress.ip_address(raw)
        return {
            "indicator": raw,
            "type": "IP",
            "severity": SEVERITY,
            "reputation": "BAD",
            "vendor": {"name": VENDOR},
            "comment": COMMENT
        }, ""
    except Exception:
        pass

    # Domain
    if _dom_re.match(raw):
        # basic ASCII domains only; non-ASCII will be skipped
        try:
            raw.encode("ascii")
        except Exception:
            return None, "non-ascii domain"
        return {
            "indicator": raw.lower(),
            "type": "DOMAIN_NAME",
            "severity": SEVERITY,
            "reputation": "BAD",
            "vendor": {"name": VENDOR},
            "comment": COMMENT
        }, ""

    # Hash
    ok, typ = is_hash(raw)
    if ok:
        return {
            "indicator": raw.lower(),
            "type": "HASH",
            "severity": SEVERITY,
            "reputation": "BAD",
            "vendor": {"name": VENDOR},
            "comment": COMMENT
        }, ""

    return None, "unknown format"

def parse_sources(files: List[str]) -> Tuple[List[Dict], List[Dict]]:
    recs, rejects = [], []
    total_lines = 0
    for fn in files:
        print(f"[src] {fn}")
        try:
            with open(fn, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    total_lines += 1
                    rec, why = to_record(line)
                    if rec:
                        recs.append(rec)
                    else:
                        rejects.append({"line": line.strip(), "reason": why, "source": fn})
        except FileNotFoundError:
            print(f"[warn] missing file: {fn}")
    print(f"[parse] lines={total_lines} parsed={len(recs)} rejected={len(rejects)}")
    return recs, rejects

def dedupe(recs: List[Dict]) -> List[Dict]:
    seen = set()
    out = []
    for r in recs:
        key = (r["indicator"], r["type"])
        if key in seen: continue
        seen.add(key); out.append(r)
    return out

# ---------- HTTP ----------
S = requests.Session()
S.headers.update({
    "Authorization": APIKEY,
    "x-xdr-auth-id": API_ID,
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Connection": "keep-alive",
})
INSERT_URI = f"{BASE}/public_api/v1/indicators/insert_jsons"  # <- force the stable endpoint

def post_json(uri: str, payload: Dict, retries: int = 6) -> Dict:
    backoff = 2.0
    for attempt in range(1, retries+1):
        try:
            r = S.post(uri, json=payload, timeout=120)
            if r.status_code in (429, 500, 502, 503, 504, 599):
                ra = r.headers.get("Retry-After")
                sleep = int(ra) if ra and ra.isdigit() else backoff
                print(f"[retry] HTTP {r.status_code} sleeping {sleep}s (attempt {attempt}/{retries})")
                time.sleep(sleep)
                backoff = min(backoff * 2.0, 90.0)
                continue
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            if attempt == retries:
                raise
            sleep = backoff + random.random()
            print(f"[retry] {e}; backoff {sleep:.1f}s (attempt {attempt}/{retries})")
            time.sleep(sleep)
            backoff = min(backoff * 2.0, 90.0)
    return {}

# ---------- main ----------
def main():
    if not SOURCES:
        print("No SOURCES provided.")
        sys.exit(1)

    recs, rejects = parse_sources(SOURCES)
    recs = dedupe(recs)
    print(f"Total after dedupe: {len(recs)}")
    print(f"Using endpoint: {INSERT_URI}")

    uploaded = 0
    failed   = 0
    # small batches reduce 5xx/599 probability
    for i in range(0, len(recs), BATCH_SIZE):
        chunk = recs[i:i+BATCH_SIZE]
        print(f"[batch] {i+1}-{i+len(chunk)} / {len(recs)}")
        body = {"request_data": {"indicators": chunk}}
        try:
            js = post_json(INSERT_URI, body)
            # Success path: reply true OR per-item result array (both patterns appear)
            ok = False
            if isinstance(js, dict):
                if js.get("reply") is True:
                    ok = True
                elif isinstance(js.get("reply"), list):
                    # Some tenants return an array of result dicts
                    ok = all(x.get("succeeded", True) for x in js["reply"])
            if not ok:
                # treat as soft failure; capture detail
                failed += len(chunk)
                rejects.append({"batch_start": i+1, "reason": f"server_reply={js}"})
            else:
                uploaded += len(chunk)
        except Exception as e:
            failed += len(chunk)
            rejects.append({"batch_start": i+1, "error": str(e)})
        # gentle pacing
        time.sleep(0.35)

    # write rejects (if any)
    if rejects:
        with open(OUT_REJECTS, "w", encoding="utf-8") as f:
            for r in rejects:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"[rejects] saved to {OUT_REJECTS}")

    print(f"[done] uploaded={uploaded} rejected_parse={sum(1 for r in rejects if 'line' in r)}")
    # consider non-zero exit only if zero were uploaded AND we had network errors
    if uploaded == 0:
        # keep non-zero so the Summary shows attention, but your workflow can choose to continue
        sys.exit(1)

if __name__ == "__main__":
    main()
