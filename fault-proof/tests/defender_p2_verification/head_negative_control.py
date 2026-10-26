#!/usr/bin/env python3
"""A deliberately wrong HEAD responder, used as a negative control for the HEAD assertion.

The acceptance helper asserts three things about a HEAD on the lookup route: HTTP 405, an `Allow`
header advertising GET, and a zero-byte body. A check that cannot fail is worthless, so this
service answers HEAD with the two defects the helper has to catch:

  - no `Allow` header at all, and
  - a non-empty body (5 bytes), which `curl -I` can never observe because it does not read one.

Run it, point the helper at it, and the helper must report FAIL. If it reports PASS, the check is
not actually constraining anything.

Usage: head_negative_control.py <port>
Binds 127.0.0.1 only and serves one connection at a time until terminated.
"""

import socket
import sys

RESPONSE = (
    b"HTTP/1.1 405 Method Not Allowed\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 5\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"WRONG"
)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <port>", file=sys.stderr)
        return 2
    port = int(sys.argv[1])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(8)
    print(f"head negative control listening on 127.0.0.1:{port}", flush=True)

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
                conn.sendall(RESPONSE)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
