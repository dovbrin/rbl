import os, re, json, time, pathlib, ipaddress, base64
from typing import List, Dict, Tuple
from urllib.parse import urlparse
import requests
from ftplib import FTP

# Optional SFTP support (paramiko). If missing, SFTP sources are skipped with a note.
try:
    import paramiko  # type: ignore
except Exception:
    paramiko = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# -------- tiny .env loader (no external deps) --------
def load_env(path: str):
    if not os.path.exists(path): return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s: continue
            k, v = s.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
load_env(os.path.join(BASE_DIR, ".env"))

# -------- config --------
BASE    = os.environ["XDR_BASE_URL"].rstrip("/")
APIID   = os.environ["XDR_API_ID"]
APIKEY  = os.environ["XDR_API_KEY"]

SOURCES = [s.strip() for s in os.environ.get("SOURCES","").split(",") if s.strip()]
if not SOURCES:
    raise SystemExit("Set SOURCES in .env (comma-separated local/HTTP/FTP/SFTP/gh://…)")

VENDOR     = os.environ.get("VENDOR", "Custom-RBL")
SEVERITY   = os.environ.get("SEVERITY", "high").lower()
BATCH_SIZE = max(1, int(os.environ.get("BATCH_SIZE", "1000")))
COMMENT    = os.environ.get("COMMENT_TAG", "Imported via API")

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")  # for gh://private

# -------- XDR API helpers --------
def headers():
    return {
        "Authorization": APIKEY,
        "x-xdr-auth-id": APIID,
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip",
    }

IOC_ENDPOINTS = [
    f"{BASE}/public_api/v1/indicators/insert",
    f"{BASE}/public_api/v1/indicators/upsert",
    f"{BASE}/public_api/v1/indicators/insert_simple",
]

def try_post(url: str, payload: dict):
    r = requests.post(url, headers=headers(), json=payload, timeout=120)
    if r.status_code == 429:
        ra = int(r.headers.get("Retry-After","5") or "5")
        print(f"[throttle] 429; sleeping {ra}s")
        time.sleep(ra)
        r = requests.post(url, headers=headers(), json=payload, timeout=120)
    r.raise_for_status()
    return r.json()

def find_working_endpoint(sample_payload: dict) -> str:
    last = None
    for ep in IOC_ENDPOINTS:
        try:
            resp = try_post(ep, sample_payload)
            if isinstance(resp, dict):
                return ep
        except Exception as e:
            last = str(e)
            # Some tenants error on duplicates; accept and proceed with this ep
            return ep
    raise SystemExit(f"No working indicators endpoint. Last error: {last}")

# -------- indicator parsing --------
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
        return "ipv4" if isinstance(ip, ipaddress.IPv4Address) else "ipv6"
    except ValueError:
        pass
    try:  # CIDR (not supported by XDR IOC)
        ipaddress.ip_network(s, strict=False)
        return "cidr"
    except ValueError:
        pass
    if MD5_RE.match(s): return "md5"
    if SHA256_RE.match(s): return "sha256"
    if DOMAIN_RE.match(s): return "domain"
    return None

def lines_to_indicators(text: str) -> List[Dict]:
    inds: List[Dict] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        t = detect_type(s)
        if t in (None, "cidr"):
            if t == "cidr":
                print(f"[skip] CIDR not supported in XDR IOC: {s}")
            else:
                print(f"[skip] Unknown indicator format: {s}")
            continue
        inds.append({
            "indicator": s,
            "type": t,
            "severity": SEVERITY,
            "vendor": VENDOR,
            "comment": COMMENT
        })
    return inds

# -------- source fetchers --------
def fetch_local(path: str) -> str:
    p = pathlib.Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Local file not found: {p}")
    return p.read_text(encoding="utf-8")

def fetch_http(url: str) -> str:
    r = requests.get(url, timeout=90)
    r.raise_for_status()
    return r.text

def fetch_ftp(url: str) -> str:
    u = urlparse(url)
    host, port = u.hostname, u.port or 21
    user = u.username or "anonymous"
    pwd  = u.password or "anonymous@"
    path = u.path
    buf = []
    with FTP() as ftp:
        ftp.connect(host, port, timeout=30)
        ftp.login(user, pwd)
        ftp.retrlines(f"RETR {path}", buf.append)
    return "\n".join(buf)

def fetch_sftp(url: str) -> str:
    if paramiko is None:
        raise RuntimeError("SFTP source requires 'paramiko' (pip install paramiko)")
    u = urlparse(url)
    host, port = u.hostname, u.port or 22
    user = u.username or ""
    pwd  = u.password or ""
    path = u.path
    t = paramiko.Transport((host, port))
    t.connect(username=user, password=pwd)
    sftp = paramiko.SFTPClient.from_transport(t)
    try:
        with sftp.open(path, "r") as f:
            return f.read().decode("utf-8")
    finally:
        sftp.close()
        t.close()

def fetch_github_api(gh_spec: str) -> str:
    """
    gh://owner/repo/path/to/file@branch
    Requires GITHUB_TOKEN in .env for private repos. Works for public too.
    """
    if not gh_spec.startswith("gh://"):
        raise ValueError("bad gh spec")
    spec = gh_spec[5:]
    at = spec.find("@")
    ref = None
    if at != -1:
        ref = spec[at+1:]
        spec = spec[:at]
    parts = spec.split("/", 2)
    if len(parts) != 3:
        raise ValueError("gh://owner/repo/path[@ref]")
    owner, repo, path = parts
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    params = {"ref": ref} if ref else None
    hdrs = {"Accept": "application/vnd.github.v3.raw"}
    if GITHUB_TOKEN:
        hdrs["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    r = requests.get(url, headers=hdrs, params=params, timeout=60)
    if r.status_code == 200 and r.headers.get("Content-Type","").startswith("application/vnd.github.v3.raw"):
        return r.text
    # If not served raw, decode base64
    r.raise_for_status()
    j = r.json()
    if j.get("encoding") == "base64":
        return base64.b64decode(j["content"]).decode("utf-8")
    raise RuntimeError("Unexpected GitHub API response")

def fetch_source(src: str) -> str:
    if src.lower().startswith("http://") or src.lower().startswith("https://"):
        return fetch_http(src)
    if src.lower().startswith("ftp://"):
        return fetch_ftp(src)
    if src.lower().startswith("sftp://"):
        return fetch_sftp(src)
    if src.lower().startswith("gh://"):
        return fetch_github_api(src)
    # else treat as local path
    return fetch_local(src)

# -------- uploader --------
def dedupe(inds: List[Dict]) -> List[Dict]:
    seen = set()
    out: List[Dict] = []
    for i in inds:
        key = (i["type"], i["indicator"])
        if key in seen: continue
        seen.add(key)
        out.append(i)
    return out

def chunks(lst: List[Dict], n: int):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]

def upsert_iocs(inds: List[Dict]):
    if not inds:
        print("Nothing to upload.")
        return
    sample = {"request_data": {"indicators": inds[:1]}}
    endpoint = find_working_endpoint(sample)
    print(f"Using endpoint: {endpoint}")

    sent = 0
    failures = 0
    for batch in chunks(inds, BATCH_SIZE):
        payload = {"request_data": {"indicators": batch}}
        try:
            resp = try_post(endpoint, payload)
            reply = resp.get("reply", resp)
            ok = len(reply.get("success_list", [])) if isinstance(reply, dict) else None
            fail = len(reply.get("failure_list", [])) if isinstance(reply, dict) else 0
            sent += ok if ok is not None else len(batch)
            failures += fail
            print(f"[batch] uploaded={ok if ok is not None else len(batch)} failed={fail}")
        except Exception as e:
            failures += len(batch)
            print(f"[batch] ERROR: {e}")

    print(f"Done. Uploaded={sent} Failed={failures}")

# -------- main --------
def main():
    all_inds: List[Dict] = []
    for src in SOURCES:
        try:
            print(f"[src] fetching: {src}")
            text = fetch_source(src)
            inds = lines_to_indicators(text)
            print(f"[src] parsed {len(inds)} indicators from {src}")
            all_inds.extend(inds)
        except Exception as e:
            print(f"[src] ERROR fetching {src}: {e}")

    all_inds = dedupe(all_inds)
    print(f"Total indicators after dedupe: {len(all_inds)}")
    upsert_iocs(all_inds)

if __name__ == "__main__":
    main()
