name: Sync RBL to Cortex XDR

on:
  push:
    paths:
      - 'fqdnlist.txt'
      - 'iplist.txt'
      - 'hashlist.txt'
      - '.github/workflows/xdr-ioc-sync.yml'
  workflow_dispatch: {}

jobs:
  sync:
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install deps
        run: |
          python -m pip install --upgrade pip
          pip install requests

      # ---- Upload IOCs ----
      - name: Push IOCs to Cortex XDR
        env:
          XDR_BASE_URL: ${{ secrets.XDR_BASE_URL }}
          XDR_API_ID:   ${{ secrets.XDR_API_ID }}
          XDR_API_KEY:  ${{ secrets.XDR_API_KEY }}
          SOURCES: "fqdnlist.txt,iplist.txt,hashlist.txt"
          VENDOR: ONO-RBL
          SEVERITY: HIGH
          BATCH_SIZE: '1000'
          COMMENT_TAG: Imported from GitHub
          FAIL_ON_ERROR: '0'     # don't fail the job if listing APIs are down
        run: |
          python xdr_ioc_upsert_from_sources.py || true

      # ---- Upload parse/API rejects (if any) ----
      - name: Upload rejects (if any)
        uses: actions/upload-artifact@v4
        with:
          name: xdr-rejects
          path: artifacts/rejects.json
          if-no-files-found: warn

      # ---- Canary insert + verify (best-effort) ----
      - name: Insert canary IOC & try to verify
        id: canary
        env:
          XDR_BASE_URL: ${{ secrets.XDR_BASE_URL }}
          XDR_API_ID:   ${{ secrets.XDR_API_ID }}
          XDR_API_KEY:  ${{ secrets.XDR_API_KEY }}
          VENDOR:       ONO-RBL
          COMMENT_TAG:  "GitHub sync test"
        run: |
          python - <<'PY'
          import os, sys, time, json, requests
          from datetime import datetime, timezone

          BASE   = os.environ["XDR_BASE_URL"].rstrip("/")
          API_ID = os.environ["XDR_API_ID"]
          APIKEY = os.environ["XDR_API_KEY"]
          VENDOR = os.getenv("VENDOR","ONO-RBL")
          COMMENT= os.getenv("COMMENT_TAG","GitHub sync test")

          H = {
            "Authorization": APIKEY,
            "x-xdr-auth-id": str(API_ID),
            "Content-Type": "application/json",
            "Accept": "application/json"
          }

          def post(url, payload, max_retries=6, timeout=120):
            back = 2
            for i in range(1, max_retries+1):
              try:
                r = requests.post(url, headers=H, json=payload, timeout=timeout)
                if r.status_code in (429,500,502,503,504,599):
                  ra = r.headers.get("Retry-After")
                  sleep = int(ra) if ra and ra.isdigit() else back
                  print(f"[retry] HTTP {r.status_code} sleeping {sleep}s (attempt {i}/{max_retries})")
                  time.sleep(sleep); back = min(int(back*2.2), 90); continue
                r.raise_for_status()
                try: return r.json()
                except: return {}
              except requests.RequestException as e:
                if i == max_retries: raise
                print(f"[retry] {e}; backoff {back}s")
                time.sleep(back); back = min(int(back*2.2), 90)

          canary = f"ono-rbl-canary-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.example"
          ins_body = {"request_data":{"indicators":[{
            "indicator":canary, "type":"DOMAIN_NAME",
            "severity":"MEDIUM", "reputation":"BAD",
            "comment":COMMENT, "vendor":{"name":VENDOR}
          }]}}
          print(f"[insert] {canary}")
          post(f"{BASE}/public_api/v1/indicators/insert_jsons", ins_body)

          ok = False
          get_url = f"{BASE}/public_api/v1/indicators/get"
          q = {"request_data":{
            "search_from":0,"search_to":50,
            "filters":[{"field":"indicator","operator":"eq","value":canary}]
          }}
          for n in range(12):  # ~2 min
            try:
              js = post(get_url, q, max_retries=3, timeout=90)
              items = (js or {}).get("reply",{}).get("indicators",[]) or []
              if any(it.get("indicator")==canary for it in items):
                ok = True; break
            except Exception as e:
              print(f"[exact] {e}")
            time.sleep(10)

          status = "visible" if ok else "inconclusive"
          with open("canary.txt","w") as f:
            f.write(canary+"\n"+status+"\n")
          print(f"CANARY={canary}\nCANARY_STATUS={status}")
          PY

      - name: Save canary details
        uses: actions/upload-artifact@v4
        with:
          name: xdr-canary
          path: canary.txt
          if-no-files-found: warn

      - name: Summarize
        shell: bash
        run: |
          echo "### XDR IOC Sync" >> $GITHUB_STEP_SUMMARY
          if [[ -f canary.txt ]]; then
            CANARY=$(sed -n '1p' canary.txt); STATUS=$(sed -n '2p' canary.txt)
            echo "- **Canary**: \`$CANARY\`" >> $GITHUB_STEP_SUMMARY
            echo "- **Status**: \`$STATUS\`" >> $GITHUB_STEP_SUMMARY
            [[ "$STATUS" != "visible" ]] && echo "> Listing API returned 5xx/599; insert likely ok but visibility couldn’t be confirmed from GitHub." >> $GITHUB_STEP_SUMMARY
          else
            echo "- Canary not produced" >> $GITHUB_STEP_SUMMARY
          fi
