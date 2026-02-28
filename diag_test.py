"""Quick diagnostic: upload synthetic_test.img and stream the result. Show full error body."""
import json
import sys
import urllib.request
import os

BASE = "http://localhost:8000"
IMG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "synthetic_test.img")

if not os.path.exists(IMG):
    print("synthetic_test.img not found — run: py generate_synthetic.py")
    sys.exit(1)

# Upload
boundary = "----pyDiagBoundary"
with open(IMG, "rb") as f:
    file_data = f.read()

parts = []
parts.append((
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="file"; filename="synthetic_test.img"\r\n'
    f"Content-Type: application/octet-stream\r\n\r\n"
).encode() + file_data)
parts.append((
    f"\r\n--{boundary}\r\n"
    f'Content-Disposition: form-data; name="cluster_size"\r\n\r\n4096'
).encode())
parts.append((
    f"\r\n--{boundary}\r\n"
    f'Content-Disposition: form-data; name="step"\r\n\r\n1'
    f"\r\n--{boundary}--\r\n"
).encode())
body = b"".join(parts)

req = urllib.request.Request(
    f"{BASE}/api/upload",
    data=body,
    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    method="POST"
)
with urllib.request.urlopen(req, timeout=30) as r:
    meta = json.loads(r.read())
    scan_id = meta["scan_id"]
    print(f"Uploaded OK — scan_id={scan_id}, size={meta['size_mb']}MB")

# Stream
url = f"{BASE}/api/scan/{scan_id}/stream"
print(f"Streaming {url} ...")
try:
    with urllib.request.urlopen(url, timeout=120) as resp:
        for line in resp:
            text = line.decode("utf-8").strip()
            if text.startswith("data: "):
                event = json.loads(text[6:])
                t = event.get("type", "?")
                if t not in ("progress", "cluster_batch"):
                    print(f"  Event: {t}", flush=True)
                if t == "complete":
                    print(f"  Score={event.get('evidence_score')} Wipes={event.get('wipe_count')}")
                    print("PASS — scan completed")
                    sys.exit(0)
                elif t == "error":
                    print(f"  Scan error: {event.get('message')}")
                    sys.exit(1)
except urllib.error.HTTPError as e:
    body = e.read().decode("utf-8", errors="replace")
    print(f"HTTP {e.code}: {body[:2000]}")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
