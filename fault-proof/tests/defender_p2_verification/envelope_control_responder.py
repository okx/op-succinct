#!/usr/bin/env python3
"""A fixed-response HTTP service used as a control for the known-ID lookup probe.

The probe that drives the known-ID leg of the mutation proof has to be able to fail: it must
reject a non-200 status, a missing envelope field and a wrong field value, and it must accept the
one correct envelope. None of that can be demonstrated against the real Defender, which only ever
answers correctly. So this service answers every request with an operator-chosen status line and
body, and the real probe is pointed at it.

It deliberately sends exactly what it is told to send: no Content-Length fix-ups, no JSON
validation. A control that silently repaired its own defect would prove nothing.

Usage: envelope_control_responder.py <port> <http-status> <body>
Binds 127.0.0.1 only and serves one connection at a time until terminated.
"""

import socket
import sys

REASONS = {
    200: "OK",
    400: "Bad Request",
    405: "Method Not Allowed",
    500: "Internal Server Error",
}


def build_response(status: int, body: str) -> bytes:
    payload = body.encode("utf-8")
    head = (
        f"HTTP/1.1 {status} {REASONS.get(status, 'Status')}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return head.encode("ascii") + payload


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <port> <http-status> <body>", file=sys.stderr)
        return 2
    port = int(sys.argv[1])
    response = build_response(int(sys.argv[2]), sys.argv[3])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(8)
    print(f"envelope control responder listening on 127.0.0.1:{port}", flush=True)

    while True:
        try:
            conn, _ = server.accept()
        except OSError:
            return 0
        with conn:
            conn.settimeout(5)
            try:
                conn.recv(8192)
            except OSError:
                pass
            try:
                conn.sendall(response)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
