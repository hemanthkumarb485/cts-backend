import sys, os, json
sys.path.insert(0, os.path.dirname(__file__))
from sse_starlette.event import ServerSentEvent

def event(stage, pct, msg, data=None):
    p = {"stage": stage, "percent": pct, "message": msg, "elapsed_seconds": 0.5}
    if data is not None:
        p["data"] = data
    return json.dumps(p)

raw_complete = event("complete", 100, "done!", data={"session_id": "abc", "findings": []})
e = ServerSentEvent(data=raw_complete)
wire = e.encode().decode().replace('\r\n', '\n')

print("WIRE:", repr(wire[:120]))
parts = wire.split('\n\n')
for part in parts:
    part = part.strip()
    if not part.startswith('data: '):
        continue
    data_str = part[6:]
    try:
        parsed = json.loads(data_str)
        print("OK - stage:", parsed.get('stage'), "| message:", parsed.get('message'))
    except Exception as ex:
        print("PARSE ERROR:", ex)
