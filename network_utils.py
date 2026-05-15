"""
network_utils.py — Transport Layer
====================================
Length-prefixed framing over TCP so that arbitrary-size blobs can be
sent and received reliably regardless of TCP segment boundaries.

Wire format (per message):
    [4-byte big-endian total-length] [msgpack/pickle payload]

We use Python's built-in pickle for serialisation.  In production you
would replace this with a schema-validated format (protobuf, msgpack, …).
"""

import pickle
import socket
import struct
import logging
from typing import Any

logger = logging.getLogger(__name__)

HEADER_SIZE = 4   # bytes — carries the payload length as uint32


def send_packet(sock: socket.socket, obj: Any) -> None:
    """
    Serialise *obj* and send it over *sock* with a 4-byte length prefix.

    Raises
    ------
    ConnectionError  if the socket is closed or broken.
    """
    payload = pickle.dumps(obj)
    header  = struct.pack(">I", len(payload))
    try:
        sock.sendall(header + payload)
        logger.debug("send_packet: sent %d bytes", len(payload))
    except (BrokenPipeError, ConnectionResetError) as exc:
        raise ConnectionError(f"send_packet failed: {exc}") from exc


def recv_packet(sock: socket.socket) -> Any:
    """
    Receive one length-prefixed packet from *sock* and deserialise it.

    Returns
    -------
    The original Python object.

    Raises
    ------
    ConnectionError  if the peer disconnected.
    """
    header = _recv_exactly(sock, HEADER_SIZE)
    if not header:
        raise ConnectionError("recv_packet: peer disconnected (no header).")

    length  = struct.unpack(">I", header)[0]
    payload = _recv_exactly(sock, length)
    if not payload:
        raise ConnectionError("recv_packet: peer disconnected mid-payload.")

    obj = pickle.loads(payload)
    logger.debug("recv_packet: received %d bytes", length)
    return obj


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*, looping over partial reads."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


def make_server_socket(host: str, port: int, backlog: int = 5) -> socket.socket:
    """Create, bind, and listen on a TCP server socket."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(backlog)
    logger.info("Listening on %s:%d", host, port)
    return srv


def make_client_socket(host: str, port: int) -> socket.socket:
    """Create and connect a TCP client socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    logger.info("Connected to %s:%d", host, port)
    return s
