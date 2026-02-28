import sys, json, urllib.request

def test():
    req = urllib.request.Request('http://localhost:8000/api/scan/8543ce7d/stream')
    try:
        resp = urllib.request.urlopen(req, timeout=60)
        for line in resp:
            line_str = line.decode('utf-8').strip()
            if line_str.startswith('data: '):
                event = json.loads(line_str[6:])
                t = event.get('type')
                if t not in ['progress', 'cluster_batch']:
                    print(f"Event: {t}")
                if t == 'complete':
                    print("Test passed: Scan Completed Successfully")
                    sys.exit(0)
                elif t == 'error':
                    print(f"Test failed: {event.get('message')}")
                    sys.exit(1)
    except Exception as e:
        print(f"HTTP Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    test()
