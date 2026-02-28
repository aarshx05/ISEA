"""
End-to-end test: Upload a fresh image, then stream the SSE scan endpoint
and verify we receive the 'complete' event.
"""
import sys
import json
import urllib.request
import urllib.parse

BASE = "http://localhost:8000"

def upload_image(path: str) -> str:
    """Upload an image file and return the scan_id."""
    import io, mimetypes
    boundary = "----pyTestBoundary"
    with open(path, "rb") as f:
        file_data = f.read()
    filename = path.split("\\")[-1].split("/")[-1]
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + file_data + (
        f"\r\n--{boundary}\r\n"
        f'Content-Disposition: form-data; name="cluster_size"\r\n\r\n4096'
        f"\r\n--{boundary}\r\n"
        f'Content-Disposition: form-data; name="step"\r\n\r\n1'
        f"\r\n--{boundary}--\r\n"
    ).encode()

    req = urllib.request.Request(
        f"{BASE}/api/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
        return result["scan_id"]


def test():
    # Upload synthetic test image
    import os
    img = os.path.join(os.path.dirname(__file__), "synthetic_test.img")
    if not os.path.exists(img):
        print(f"Test image not found: {img}")
        print("Run: py generate_synthetic.py  first")
        sys.exit(1)

    print(f"Uploading {img}...")
    scan_id = upload_image(img)
    print(f"Uploaded → scan_id={scan_id}")

    # Stream the SSE endpoint
    url = f"{BASE}/api/scan/{scan_id}/stream"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            for line in resp:
                line_str = line.decode("utf-8").strip()
                if line_str.startswith("data: "):
                    event = json.loads(line_str[6:])
                    t = event.get("type")
                    if t not in ["progress", "cluster_batch"]:
                        print(f"Event: {t}", flush=True)
                    if t == "complete":
                        score = event.get("evidence_score", "?")
                        wipes = event.get("wipe_count", "?")
                        print(f"✓ Scan complete — evidence_score={score}, wipe_regions={wipes}")
                        sys.exit(0)
                    elif t == "error":
                        print(f"✗ Scan error: {event.get('message')}")
                        sys.exit(1)
    except Exception as e:
        print(f"HTTP Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    test()
