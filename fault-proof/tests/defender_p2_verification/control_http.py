#!/usr/bin/env python3
"""Request/response timing shared by the local control services in this directory.

Both controls answer a single HTTP request per connection with a fixed, deliberately chosen
response. Getting that response *delivered* is the whole point of a control, and a naive
``recv`` once / ``sendall`` / ``close`` sequence does not deliver it reliably:

  - one ``recv`` returns as soon as any bytes arrive, so the request headers are often still
    incomplete (measured on this host: 18 of 20 connections, one of them holding only the
    44-byte request line);
  - closing a socket that still has unread received data makes the kernel send RST instead of
    FIN, and the RST discards whatever the client has not yet read — so the client reports
    "could not read a raw response" and the control proves nothing.

So the request head is read to completion first, and the response is followed by a write
shutdown and a bounded wait for the peer's own close. A control that cannot read its request is
reported as a failure and answers nothing: responding early is what made the defect invisible,
and a silent early answer would reintroduce it.

The logic lives here once because the same single-``recv`` defect was present in both control
services; a second copy is a second chance to diverge.
"""

import socket
import time

HEADER_TERMINATOR = b"\r\n\r\n"
DEFAULT_READ_TIMEOUT = 5.0
DEFAULT_MAX_HEAD_BYTES = 65536
DEFAULT_LINGER = 2.0


class IncompleteRequest(Exception):
    """The request head never arrived in full, so no response may be sent."""


def read_request_head(
    conn: socket.socket,
    timeout: float = DEFAULT_READ_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_HEAD_BYTES,
) -> bytes:
    """Read until the CRLFCRLF header terminator and return everything read.

    Raises `IncompleteRequest` on timeout, on EOF before the terminator, or when the head grows
    past `max_bytes`. The timeout is a deadline for the whole head, not per `recv`, so a peer
    dribbling one byte at a time cannot hold the control open indefinitely.
    """
    deadline = time.monotonic() + timeout
    buf = bytearray()
    while HEADER_TERMINATOR not in buf:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise IncompleteRequest(
                f"no header terminator within {timeout:g}s ({len(buf)} byte(s) read)"
            )
        conn.settimeout(remaining)
        try:
            chunk = conn.recv(4096)
        except socket.timeout as exc:
            raise IncompleteRequest(
                f"timed out after {len(buf)} byte(s) with no header terminator"
            ) from exc
        except OSError as exc:
            raise IncompleteRequest(f"read error after {len(buf)} byte(s): {exc}") from exc
        if not chunk:
            raise IncompleteRequest(f"peer closed after {len(buf)} byte(s), head incomplete")
        buf += chunk
        if len(buf) > max_bytes:
            raise IncompleteRequest(f"request head exceeded {max_bytes} byte(s)")
    return bytes(buf)


def respond_and_finish(
    conn: socket.socket,
    response: bytes,
    linger: float = DEFAULT_LINGER,
) -> None:
    """Send `response`, signal end-of-response, and let the peer close first.

    `shutdown(SHUT_WR)` gives the client EOF so it stops reading, and draining until the peer's
    own close means the socket is never closed with unread data queued — the condition that
    turns a FIN into an RST and loses the response.
    """
    conn.sendall(response)
    try:
        conn.shutdown(socket.SHUT_WR)
    except OSError:
        return
    deadline = time.monotonic() + linger
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        conn.settimeout(remaining)
        try:
            if not conn.recv(4096):
                return
        except OSError:
            return
