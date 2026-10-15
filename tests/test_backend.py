"""Loopback integration test for the queued backing extension."""
from __future__ import annotations

import importlib
import socket
import threading
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
backing = importlib.import_module("backing")


HOST = "127.0.0.1"


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


def main() -> None:
    assert backing.MAX_UNAUTH_PAYLOAD == 65535
    assert backing.MAX_AUTH_PAYLOAD == 33554431
    port = available_port()
    server_box: dict[str, backing.Server] = {}
    handshake_done = threading.Event()
    exchange_done = threading.Event()
    callback_errors: list[str] = []

    def handshake_worker(temp_cid: bytes) -> None:
        try:
            server = server_box["server"]
            first_message = server.recv_handshake(temp_cid, timeout=5)
            if first_message != b"client hello\x00\xff":
                raise AssertionError(f"unexpected first handshake message: {first_message!r}")

            server.send_handshake(temp_cid, b"server challenge")
            proof = server.recv_handshake(temp_cid, timeout=5)
            if proof != b"client proof":
                raise AssertionError(f"unexpected proof: {proof!r}")

            # The optional final confirmation is framed as an unauthenticated message, but the
            # server switches its receive side first. That prevents the client from sending an
            # authenticated frame before the server is ready to parse it.
            server.auth_finished(temp_cid, b"client-A", confirmation_payload=b"AUTH_OK")
        except BaseException as exc:  # retain errors for assertion on the main thread
            callback_errors.append(repr(exc))
        finally:
            handshake_done.set()

    def on_exchange(cid: bytes, eid: bytes) -> None:
        try:
            server = server_box["server"]
            message = server.recv(cid, eid=eid, timeout=5)
            if message != b"exchange request":
                raise AssertionError(f"unexpected exchange payload: {message!r}")
            server.send(b"exchange response", cid, eid=eid)
        except BaseException as exc:
            callback_errors.append(repr(exc))
        finally:
            exchange_done.set()

    server = backing.Server(
        HOST,
        port,
        handshake_worker=handshake_worker,
        on_exchange=on_exchange,
        simult_handshakes=4,
        simult_exchanges=4,
    )
    server_box["server"] = server
    client = backing.Client(HOST, port)

    try:
        server.start()
        client.connect()
        assert len(server.MAGIC1) == 8 and len(server.MAGIC2) == 8
        assert client.MAGIC1 == server.MAGIC1 and client.MAGIC2 == server.MAGIC2

        client.send_handshake(b"client hello\x00\xff")
        assert client.recv_handshake(timeout=5) == b"server challenge"
        client.send_handshake(b"client proof")

        confirmation = client.recv_handshake(timeout=5)
        assert confirmation == b"AUTH_OK", confirmation
        if not handshake_done.wait(5):
            raise AssertionError("handshake callback did not finish")
        if callback_errors:
            raise AssertionError("callback error(s): " + "; ".join(callback_errors))
        client.auth_finished(b"client-A")
        assert client.is_authed
        assert server.is_authed(b"client-A")

        # Pausing the local reader does not discard the response; it remains in TCP buffers
        # until the backpressure flag is lifted.
        client.set_backpressure(True)
        eid = client.send(b"exchange request")
        assert isinstance(eid, bytes) and len(eid) == 8
        assert client.recv(eid=eid, timeout=0.1) is None
        client.set_backpressure(False)
        response = client.recv(eid=eid, timeout=5)
        assert response == b"exchange response", response
        if not exchange_done.wait(5):
            raise AssertionError("exchange callback did not finish")
        if callback_errors:
            raise AssertionError("callback error(s): " + "; ".join(callback_errors))

        # Start an exchange in the reverse direction and send multiple messages on one EID.
        server_eid = server.send(b"server-initiated exchange", b"client-A")
        assert isinstance(server_eid, bytes) and len(server_eid) == 8
        assert client.recv(eid=server_eid, timeout=5) == b"server-initiated exchange"
        client.send(b"client reply on existing exchange", eid=server_eid)
        assert server.recv(b"client-A", eid=server_eid, timeout=5) == b"client reply on existing exchange"

        server.forget_exchange(b"client-A", eid)
        client.forget_exchange(eid)
        server.forget_exchange(b"client-A", server_eid)
        client.forget_exchange(server_eid)
        print("Networking v2.0 integration test passed.")
    finally:
        client.disconnect()
        server.stop()


if __name__ == "__main__":
    main()
