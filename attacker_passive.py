"""
attacker_passive.py — Passive MITM Proxy
=========================================
Behaviour
---------
* Listens for the sender's connection on ATTACKER_LISTEN_PORT.
* Opens its own connection to the real receiver.
* Forwards EVERY packet transparently in both directions.
* Logs full packet contents (ciphertext, encrypted AES key, digest)
  to INTERCEPT_LOG and to stdout — but does NOT modify anything.

Educational note
----------------
Without the receiver's private RSA key the attacker cannot decrypt the
AES key and therefore cannot read the plaintext.  All they see is:
    • Opaque ciphertext blobs
    • An encrypted symmetric key
    • A SHA-256 digest of the original plaintext
The intercepted audio, if saved and replayed as raw PCM, sounds like noise.

Usage
-----
    python attacker_passive.py [--listen-host 0.0.0.0] [--listen-port 9000]
                               [--recv-host 127.0.0.1]  [--recv-port 9001]
"""

import os
import json
import base64
import logging
import argparse
import threading
import datetime

import config
from network_utils import make_server_socket, make_client_socket, send_packet, recv_packet

# ── logging ───────────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(config.INTERCEPT_LOG), exist_ok=True)

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s [PASSIVE-MITM] %(levelname)s  %(message)s",
)
logger = logging.getLogger(__name__)

intercept_logger = logging.getLogger("intercept")
intercept_logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(config.INTERCEPT_LOG)
fh.setFormatter(logging.Formatter("%(asctime)s  %(message)s"))
intercept_logger.addHandler(fh)


# ─────────────────────────────────────────────────────────────────────────────
# Intercept helper
# ─────────────────────────────────────────────────────────────────────────────

def log_packet(packet: dict, direction: str = "SENDER→RECEIVER") -> None:
    """
    Dump intercepted packet to the log file and to stdout.
    All binary fields are base64-encoded for readability.
    """
    entry = {
        "timestamp":     datetime.datetime.utcnow().isoformat() + "Z",
        "direction":     direction,
        "msg_type":      packet.get("msg_type", "unknown"),
        "ciphertext_b64": base64.b64encode(packet.get("ciphertext", b"")).decode(),
        "encrypted_key_b64": base64.b64encode(packet.get("encrypted_key", b"")).decode(),
        "digest_hex":    packet.get("digest", b"").hex(),
        "ciphertext_len": len(packet.get("ciphertext", b"")),
        "encrypted_key_len": len(packet.get("encrypted_key", b"")),
    }

    intercept_logger.debug(json.dumps(entry, indent=2))

    # ── console summary ───────────────────────────────────────────────────
    print(f"\n{'═'*60}")
    print(f"  [INTERCEPTED] {direction}  |  type={entry['msg_type']}")
    print(f"  Ciphertext   : {entry['ciphertext_len']} bytes  "
          f"(first 32 B: {packet.get('ciphertext', b'')[:32].hex()}…)")
    print(f"  Encrypted Key: {entry['encrypted_key_len']} bytes")
    print(f"  Digest (hex) : {entry['digest_hex']}")
    print(f"  ↳ Logged to  : {config.INTERCEPT_LOG}")
    print(f"{'═'*60}")


# ─────────────────────────────────────────────────────────────────────────────
# Proxy threads
# ─────────────────────────────────────────────────────────────────────────────

def forward_sender_to_receiver(sender_sock, receiver_sock):
    """Read from sender, log, forward to receiver."""
    try:
        while True:
            packet = recv_packet(sender_sock)
            log_packet(packet, direction="SENDER→RECEIVER")
            send_packet(receiver_sock, packet)
            logger.info("Forwarded packet (%d B ciphertext) to receiver.",
                        len(packet.get("ciphertext", b"")))
    except ConnectionError as exc:
        logger.info("Sender→Receiver forwarder stopped: %s", exc)


def forward_receiver_to_sender(receiver_sock, sender_sock):
    """Forward any receiver→sender traffic (e.g. ACKs) transparently."""
    try:
        while True:
            packet = recv_packet(receiver_sock)
            log_packet(packet, direction="RECEIVER→SENDER")
            send_packet(sender_sock, packet)
    except ConnectionError as exc:
        logger.info("Receiver→Sender forwarder stopped: %s", exc)


def handle_connection(sender_conn, sender_addr, recv_host, recv_port):
    """Proxy one sender↔receiver session."""
    logger.info("Sender connected from %s:%d — proxying to %s:%d",
                *sender_addr, recv_host, recv_port)
    try:
        receiver_conn = make_client_socket(recv_host, recv_port)
    except ConnectionRefusedError:
        logger.error("Cannot reach receiver at %s:%d", recv_host, recv_port)
        sender_conn.close()
        return

    t1 = threading.Thread(
        target=forward_sender_to_receiver,
        args=(sender_conn, receiver_conn),
        daemon=True,
    )
    t2 = threading.Thread(
        target=forward_receiver_to_sender,
        args=(receiver_conn, sender_conn),
        daemon=True,
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    sender_conn.close()
    receiver_conn.close()
    logger.info("Session with %s:%d closed.", *sender_addr)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def run(listen_host, listen_port, recv_host, recv_port):
    print("\n╔══════════════════════════════════════╗")
    print("║    Passive MITM Proxy — Attacker      ║")
    print("╚══════════════════════════════════════╝")
    print(f"  Listening : {listen_host}:{listen_port}")
    print(f"  Forwarding: {recv_host}:{recv_port}")
    print(f"  Log file  : {config.INTERCEPT_LOG}\n")
    print("  All traffic is logged but NOT modified.\n")

    srv = make_server_socket(listen_host, listen_port)
    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=handle_connection,
                args=(conn, addr, recv_host, recv_port),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        logger.info("Passive MITM shutting down.")
    finally:
        srv.close()


def parse_args():
    p = argparse.ArgumentParser(description="Passive MITM Proxy")
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--listen-port", type=int, default=config.ATTACKER_LISTEN_PORT)
    p.add_argument("--recv-host",   default=config.RECEIVER_HOST)
    p.add_argument("--recv-port",   type=int, default=config.RECEIVER_PORT)
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(args.listen_host, args.listen_port, args.recv_host, args.recv_port)
