"""
test_sse_wire.py
Spins up the REAL FastAPI + uvicorn on port 18765, does an actual HTTP POST
to /api/v1/scan/upload with a tiny ZAP JSON, reads the raw SSE wire bytes,
and prints exactly what the browser would receive.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import asyncio, json, threading, time, urllib.request, urllib.parse

# ── 1. Start the app in a background thread ──────────────────────────────────
def start_server():
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=18765, log_level="error")

t = threading.Thread(target=start_server, daemon=True)
t.start()
time.sleep(2)  # wait for startup

# ── 2. Build a minimal multipart/form-data POST ──────────────────────────────
zap_json = json.dumps({
    "site": [{"alerts": [{"alert": "Test Vuln", "riskdesc": "High (Medium)", "desc": "desc",
               "solution": "fix", "reference": "", "cweid": "79", "wascid": "8",
               "instances": [{"uri": "http://example.com", "method": "GET", "param": "q",
                              "attack": "xss", "evidence": "<script>"}],
               "count": "1", "confidence": "High", "sourceid": "3"}]}]
})

boundary = "----FormBoundaryTEST123"
body = (
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="zap_file"; filename="test.json"\r\n'
    f"Content-Type: application/json\r\n\r\n"
    f"{zap_json}\r\n"
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="zap_format"\r\n\r\nauto\r\n'
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="asset_criticality"\r\n\r\nunknown\r\n'
    f"--{boundary}--\r\n"
).encode()

req = urllib.request.Request(
    "http://127.0.0.1:18765/api/v1/scan/upload",
    data=body,
    headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
             "Accept": "text/event-stream"},
    method="POST"
)

# ── 3. Read raw wire bytes ────────────────────────────────────────────────────
print("=== RAW SSE WIRE BYTES (first 2000 bytes) ===")
with urllib.request.urlopen(req, timeout=30) as resp:
    raw = resp.read(2000)

print(repr(raw))
print()
print("=== DECODED ===")
print(raw.decode("utf-8", errors="replace"))
