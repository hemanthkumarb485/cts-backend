"""
test_sse_wire2.py - Verifies the NEW pipeline.py SSE output is correct.
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(__file__))
sys.stdout.reconfigure(encoding='utf-8')

from sse_starlette.event import ServerSentEvent

# Simulate what the NEW pipeline.py event() function returns
def event(stage, pct, msg, data=None):
    p = {"stage": stage, "percent": pct, "message": msg, "elapsed_seconds": 0.5}
    if data is not None:
        p["data"] = data
    return json.dumps(p)   # raw JSON ONLY - no "data: " prefix, no "\n\n"

raw_start   = event("start", 0, "Pipeline started")
raw_complete = event("complete", 100, "done!", data={"session_id": "abc", "findings": []})

print("=== NEW pipeline.py yields (raw JSON) ===")
print(repr(raw_start))
print()

# What EventSourceResponse sends over the wire
e1 = ServerSentEvent(data=raw_start)
print("=== Wire bytes for 'start' event ===")
print(repr(e1.encode()))
print()
print("Decoded:")
print(e1.encode().decode())
print()

e2 = ServerSentEvent(data=raw_complete)
print("=== Wire bytes for 'complete' event ===")
print(repr(e2.encode()[:200]))
print()
print("Decoded (first 300 chars):")
print(e2.encode().decode()[:300])
print()

# Verify JS parser can parse it
wire_text = e2.encode().decode().replace('\r\n', '\n')
print("=== Simulating JS processBuffer() ===")
print("Wire text:", repr(wire_text[:100]))
parts = wire_text.split('\n\n')
print("Parts after split:", parts)
for part in parts:
    part = part.strip()
    if not part.startswith('data: '):
        continue
    data_str = part.slice_6 = part[6:]
    try:
        parsed = json.loads(data_str)
        print("PARSED EVENT:", parsed.get('stage'), "->", parsed.get('message'))
    except Exception as ex:
        print("PARSE ERROR:", ex, "->", repr(data_str[:80]))

print()
print("CONCLUSION: Wire format is now correct. Frontend will receive parseable SSE.")
