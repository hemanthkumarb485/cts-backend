"""
test_sse_output.py — Reveals EXACTLY what bytes the browser receives from the SSE stream.
"""
import json
from sse_starlette.event import ServerSentEvent

# Simulate what pipeline.py yields:
# event("start", 0, "Pipeline started")
payload_small = json.dumps({"stage": "start", "percent": 0, "message": "Pipeline started", "elapsed_seconds": 0.0})
# event("complete", 100, "done", data=session.model_dump())
payload_complete = json.dumps({"stage": "complete", "percent": 100, "message": "done", "elapsed_seconds": 1.5, "data": {"session_id": "abc123", "findings": []}})

# Case 1: Pipeline yields raw "data: ...\n\n" string
# EventSourceResponse sees this as content and wraps it in ANOTHER data: field
raw_str = f"data: {payload_small}\n\n"
wrapped = ServerSentEvent(data=raw_str)
print("=== CASE 1: pipeline yields raw 'data: ...\\n\\n' string ===")
print("Pipeline yields:  ", repr(raw_str[:80]))
print("Browser receives: ", repr(wrapped.encode()[:120]))
print()

# Case 2: Pipeline yields just the JSON string (no 'data: ' prefix)
raw_json_only = payload_small
wrapped2 = ServerSentEvent(data=raw_json_only)
print("=== CASE 2: pipeline yields raw JSON string ===")
print("Pipeline yields:  ", repr(raw_json_only[:80]))
print("Browser receives: ", repr(wrapped2.encode()[:120]))
print()

# Case 3: Pipeline yields dict directly
wrapped3 = ServerSentEvent(data=payload_small)
print("=== CASE 3: ServerSentEvent(data=json_string) ===")
print("Browser receives: ", repr(wrapped3.encode()[:150]))
print()

print("DEFAULT_SEPARATOR:", repr(ServerSentEvent.__module__))
