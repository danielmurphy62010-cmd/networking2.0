"""Example server. Run this in one terminal, then examples/client.py in another."""
from __future__ import annotations

import threading
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import backing

HOST = "0.0.0.0"
PORT = 8765
CLIENT_ID = b"example-client"
server: backing.Server


def handshake_worker(temp_cid: bytes) -> None:
    """The first unauthenticated payload is queued before this runs."""
    try:
        hello = server.recv_handshake(temp_cid, timeout=15)
        if hello != b"HELLO":
            print(f"Rejecting handshake with unexpected greeting: {hello!r}")
            return

        server.send_handshake(temp_cid, b"CHALLENGE")
        proof = server.recv_handshake(temp_cid, timeout=15)
        if proof != b"PROOF":
            print("Rejecting handshake: invalid proof")
            return

        # The server switches its parser to authenticated mode before sending this final
        # unauthenticated confirmation. The client waits for it before switching its mode.
        server.auth_finished(temp_cid, CLIENT_ID, confirmation_payload=b"AUTH_OK")
        print(f"Authenticated client as {CLIENT_ID!r}")
    except Exception as exc:
        print(f"Handshake error: {exc}")


def on_exchange(cid: bytes, eid: bytes) -> None:
    """One invocation per newly observed EID; every message is separately queued."""
    try:
        request = server.recv(cid, eid=eid, timeout=30)
        if request is None:
            return
        if request == b"READY":
            response = b"READY_ACK"
        else:
            response = b"ECHO:" + request
        server.send(response, cid, eid=eid)
        server.forget_exchange(cid, eid)  # This example treats each request/reply as one-shot.
    except Exception as exc:
        print(f"Exchange error for {cid!r}/{eid.hex()}: {exc}")


def main() -> None:
    global server
    server = backing.Server(
        HOST,
        PORT,
        handshake_worker=handshake_worker,
        on_exchange=on_exchange,
        simult_handshakes=4,
        simult_exchanges=4,
    )
    server.start()
    print(f"Listening on {HOST}:{PORT}; press Ctrl+C to stop")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
