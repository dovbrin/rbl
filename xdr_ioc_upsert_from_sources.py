# xdr_ioc_upsert_from_sources.py
import os, re, json, time, pathlib, ipaddress, base64
from typing import List, Dict
from urllib.parse import urlparse
import requests
from ftplib import FTP
try:
    import paramiko  # optional for sftp:// sources
except Exception:
    paramiko = None

# --- tiny env loader (for local runs; Actions will pass env) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
def load_env(path: str):
    if not os.path.exists(path): return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s: continue
            k, v = s.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
load_env(os.path.join(BASE_DIR, ".env"))

# --- config ---
BASE    = os.environ["XDR_BASE_URL"].rstrip("/")
APIID   = os.environ["XDR_API_ID"]
APIKEY  = os.environ["XDR_API_KEY"]
SOURCES = [s.strip() for s in os.environ.get("SOURCES","").split(",") if s.strip()]
if not SOURCES:
    raise SystemExit("Set SOURCES (comma-separated paths/URLs)")

VENDOR     = os.environ.get("VENDOR", "Custom-RBL")
SEVERITY   = os.environ.get("SEVERITY", "high").lower()
BATCH_SIZE = max(1, int(os.environ.get("BATCH_SIZE", "1000")))
COMMENT    = os.environ.get("COMMENT_TAG", "Imported via GitHub")

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")  # only if you use gh:// private paths

# --- XDR API helpers ---
def headers():
    return {"Authorization": APIKEY, "x-xdr-auth-id": APIID, "Content-Type": "application/json"}

CANDIDATE_ENDPOINTS = [
    f"{BASE}/public_api/v1/indicators/insert",
    f"{BASE}/public_api/v1/indicators/upsert",
    f"{BASE}/public_api/v1/indicators/insert_simple",
]

def post_with_retry(url: str, payload: dict):
    r = requests.post(url, headers=headers(), json=payload, timeout=120)
    if r.status_code == 429:
        ra = int(r.headers.get("Retry-After","5") or "5"); time.sleep(ra)
        r = requests.post(url, headers=headers(), json=payload, timeout=120)
    r.raise_for_status()
    return r.json()

def pick_endpoint(sample: dict) -> str:
    last = None
    for ep in CANDIDATE_ENDPOINTS:
        try:
            _ = post_with_retry(ep, sample)
            return ep
        except Exception as e:
            last = str(e)
            # Some tenants error on duplicates—still usable. Use first candidate.
            return ep
    raise SystemExit(f"No working IOC endpoint; last error: {last}")

# --- indicator parsing ---
MD5_RE     = re.compile(r"^[a-fA-F0-9]{32}$")
SHA256_RE  = re.compile(r"^[a-fA-F0-9]{64}$")
URL_RE     = re.compile(r"^https?://", re.I)
DOMAIN_RE  = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

def detect_type(s: str):
    s = s.strip()
    if not s: return None
    if URL_RE.match(s): return "url"
    try:
        ip = ipaddress.ip_address(s)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    try:
        ipaddress.ip_network(s, strict=False)
        return "cidr"  # not supported in XDR IOC; skip
    except ValueError:
        pass
    if MD5_RE.match(s): return "md5"
    if SHA256_RE.match(s): return "sha256"
    if DOMAIN_RE.match(s): return "domain"
    return None

def to_iocs(text: str) -> List[Dict]:
    out: List[Dict] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"): continue
        t = detect_type(s)
        if t in (None, "cidr"):
            if t == "cidr": print(f"[skip] CIDR not supported: {s}")
            else: print(f"[skip] unknown format: {s}")
            continue
        out.append({"indicator": s, "type": t, "severity": SEVERITY,
                    "vendor": VENDOR, "comment": COMMENT})
    return out

# --- source fetchers (repo paths / http / ftp / sftp / gh://) ---
def fetch_local(path: str) -> str:
    p = pathlib.Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Local file not found: {p}")
    return p.read_text(encoding="utf-8")

def fetch_http(url: str) -> str:
    r = requests.get(url, timeout=90); r.raise_for_status(); return r.text

def fetch_ftp(url: str) -> str:
    from ftplib import FTP
    u = urlparse(url); host, port = u.hostname, u.port or 21
    user, pwd, path = u.username or "anonymous", u.password or "anon@", u.path
    buf = []
    with FTP() as ftp:
        ftp.connect(host, port, timeout=30); ftp.login(user, pwd); ftp.retrlines(f"RETR {path}", buf.append)
    return "\n".join(buf)

def fetch_sftp(url: str) -> str:
    if paramiko is None:
        raise RuntimeError("SFTP requires paramiko (pip install paramiko)")
    u = urlparse(url); host, port = u.hostname, u.port or 22
    user, pwd, path = u.username or "", u.password or "", u.path
    t = paramiko.Transport((host, port)); t.connect(username=user, password=pwd)
    sftp = paramiko.SFTPClient.from_transport(t)
    try:
        with sftp.open(path, "r") as f: return f.read().decode("utf-8")
    finally:
        sftp.close(); t.close()

def fetch_github_api(gh: str) -> str:
    # gh://owner/repo/path/to/file@branch
    spec = gh[5:]; ref=None
    if "@" in spec: spec, ref = spec.split("@",1)
    owner, repo, path = spec.split("/",2)
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    hdrs = {"Accept":"application/vnd.github.v3.raw"}
    if GITHUB_TOKEN: hdrs["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    r = requests.get(url, headers=hdrs, params={"ref":ref} if ref else None, timeout=60)
    if r.ok and r.headers.get("Content-Type","").startswith("application/vnd.github.v3.raw"):
        return r.text
    r.raise_for_status()
    j = r.json()
    if j.get("encoding")=="base64": return base64.b64decode(j["content"]).decode("utf-8")
    raise RuntimeError("Unexpected GitHub response")

def fetch_source(src: str) -> str:
    s = src.lower()
    if s.startswith("http://") or s.startswith("https://"): return fetch_http(src)
    if s.startswith("ftp://"):  return fetch_ftp(src)
    if s.startswith("sftp://"): return fetch_sftp(src)
    if s.startswith("gh://"):   return fetch_github_api(src)
    return fetch_local(src)

# --- upload ---
def dedupe(inds: List[Dict]) -> List[Dict]:
    seen=set(); out=[]
    for i in inds:
        key=(i["type"], i["indicator"])
        if key in seen: continue
        seen.add(key); out.append(i)
    return out

def batches(items: List[Dict], n: int):
    for i in range(0, len(items), n):
        yield items[i:i+n]

def upload(inds: List[Dict]):
    if not inds:
        print("Nothing to upload."); return
    ep = pick_endpoint({"request_data":{"indicators": inds[:1]}})
    print(f"Using endpoint: {ep}")
    sent=0; failed=0
    for chunk in batches(inds, BATCH_SIZE):
        payload={"request_data":{"indicators":chunk}}
        try:
            resp = post_with_retry(ep, payload)
            reply = resp.get("reply", resp) if isinstance(resp, dict) else {}
            ok   = len(reply.get("success_list", [])) if isinstance(reply, dict) else len(chunk)
            fail = len(reply.get("failure_list", [])) if isinstance(reply, dict) else 0
            sent += ok; failed += fail
            print(f"[batch] uploaded={ok} failed={fail}")
        except Exception as e:
            failed += len(chunk)
            print(f"[batch] ERROR: {e}")
    print(f"Done. Uploaded={sent} Failed={failed}")

def main():
    all_inds=[]
    for src in SOURCES:
        try:
            print(f"[src] {src}")
            text = fetch_source(src)
            inds = to_iocs(text)
            print(f"[src] parsed {len(inds)} indicators")
            all_inds.extend(inds)
        except Exception as e:
            print(f"[src] ERROR: {e}")
    all_inds = dedupe(all_inds)
    print(f"Total after dedupe: {len(all_inds)}")
    upload(all_inds)

if __name__ == "__main__":
    main()
