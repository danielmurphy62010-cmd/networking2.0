"""Example client for examples/server.py."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import backend


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="127.0.0.1", help="server IP/hostname")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    client = backend.Client(args.host, args.port)
    try:
        client.connect()
        client.send(b"HELLO?")
        challenge = client.recv(timeout=10)
        if challenge != b"CHALLENGE":
            raise RuntimeError(f"unexpected challenge: {challenge!r}")

        client.send(b"PROOF")
        confirmation = client.recv(timeout=10)
        if confirmation != b"AUTH_OK":
            raise RuntimeError(f"authentication failed: {confirmation!r}")
        client.auth_finished(b"example-client")

        # The first authenticated client message tells the server the client has switched modes.
        ready_eid = client.send(b"READY")
        if client.recv(eid=ready_eid, timeout=10) != b"READY_ACK":
            raise RuntimeError("server did not acknowledge READY")

        eid = client.send(b"Hello from the Python client")
        print("Server says:", client.recv(eid=eid, timeout=10))
        client.forget_exchange(ready_eid)
        client.forget_exchange(eid)
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
