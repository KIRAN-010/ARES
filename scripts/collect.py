"""Bounded local process observer. Explicit host registration required.

Run: python scripts/collect.py TARGET_ID --seconds 60
Uses MJ_DATA_DIR/operator-token, never prints the token. No command-line or env capture.
"""
import argparse
import os
import time
from pathlib import Path
import httpx
import psutil


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target_id")
    parser.add_argument("--seconds", type=int, default=60, choices=range(1, 3601), metavar="1..3600")
    args = parser.parse_args()
    token = os.getenv("MJ_TOKEN") or (Path(os.getenv("MJ_DATA_DIR", "data")) / "operator-token").read_text().strip()
    port = int(os.getenv("MJ_PORT", "8765"))
    with httpx.Client(base_url=f"http://127.0.0.1:{port}/api", headers={"Authorization": "Bearer " + token},
                      trust_env=False, timeout=5) as client:
        response = client.get("/targets")
        response.raise_for_status()
        target = next((t for t in response.json() if t["id"] == args.target_id), None)
        if not target or target["kind"] != "host" or not target["active"]:
            raise SystemExit("Register an active local host target first")
        seen = set()
        end = time.monotonic() + args.seconds
        sent = 0
        while time.monotonic() < end and sent < 500:
            for proc in psutil.process_iter(["pid", "name", "create_time", "exe"]):
                info = proc.info
                key = (info["pid"], info["create_time"])
                if key in seen:
                    continue
                seen.add(key)
                result = client.post("/events", json={"target_id": args.target_id, "source": "collector",
                                     "kind": "process", "process": (info["name"] or "unknown")[:200],
                                     "path": (info["exe"] or "")[:500]})
                result.raise_for_status()
                sent += 1
                if sent >= 500:
                    break
            time.sleep(1)
    print(f"Recorded {sent} process observations (maximum 500). No process was terminated.")


if __name__ == "__main__":
    main()
