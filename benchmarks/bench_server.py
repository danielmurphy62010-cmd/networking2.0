#!/usr/bin/env python3
"""network2 authenticated-protocol benchmark server."""
from __future__ import annotations

import argparse
import signal
import threading
import time

import network2

_buffers: dict[int, bytes] = {}
_buffers_lock = threading.Lock()


def download_buffer(size: int) -> bytes:
    # Reuse immutable buffers so download tests measure transport, not allocation.
    with _buffers_lock:
        value = _buffers.get(size)
        if value is None:
            value = bytes((i * 31 + 7) & 0xFF for i in range(size))
            _buffers[size] = value
        return value


def on_exchange(server, eid: bytes, payload: bytes, client_id: bytes) -> None:
    try:
        if not payload:
            return
        op = payload[0:1]
        if op == b"P":
            # Ping: reflect exactly 1 KiB.
            response = payload
        elif op == b"U":
            # Upload: the request carries the measured body; reply with a tiny ACK.
            response = b"ACK"
        elif op == b"D" and len(payload) == 9:
            size = int.from_bytes(payload[1:9], "big")
            if size < 1 or size > 16 * 1024 * 1024:
                response = b"ERR"
            else:
                response = download_buffer(size)
        else:
            response = b"ERR"
        server.send(response, eid=eid, client_id=client_id)
    except Exception as exc:
        print(f"exchange failed: {exc}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--password", required=True)
    parser.add_argument("--workers", type=int, default=16,
                        help="network2 exchange callback workers (1-64)")
    parser.add_argument("--new-totp", action="store_true")
    args = parser.parse_args()

    server = network2.TCPServer(
        args.host, args.port, args.password,
        newTOTP=args.new_totp,
        on_exchange=on_exchange,
        simult_exchanges=args.workers,
    )
    stopped = threading.Event()

    def stop(*_):
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)

    print(f"network2 benchmark server listening on {args.host}:{args.port}", flush=True)
    try:
        while not stopped.wait(0.5):
            pass
    finally:
        server.close()
        print("server stopped", flush=True)


if __name__ == "__main__":
    main()
