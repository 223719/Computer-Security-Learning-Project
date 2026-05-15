"""
receiver.py — Secure Message Receiver (Client B)
=================================================
Responsibilities
----------------
1. Generate (or load) its own RSA key-pair; publish the public key.
2. Listen on a TCP port for incoming encrypted packets.
3. Decrypt each packet with hybrid_decrypt.
4. Verify SHA-256 integrity.
5. Display text messages or play back audio messages.

Usage
-----
    python receiver.py [--host 0.0.0.0] [--port 9001]

Run this BEFORE starting the sender.
"""

import os
import sys
import logging
import argparse
import threading

import config
from crypto_utils import generate_rsa_keypair, hybrid_decrypt
from network_utils import make_server_socket, recv_packet

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s [RECEIVER] %(levelname)s  %(message)s",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Key management
# ─────────────────────────────────────────────────────────────────────────────

def ensure_keys() -> bytes:
    """
    Load existing keys or generate a fresh pair and persist them.

    Returns
    -------
    private_pem : bytes
    """
    os.makedirs(config.KEY_DIR, exist_ok=True)
    priv_path = config.RECEIVER_PRIV_KEY
    pub_path  = config.RECEIVER_PUB_KEY

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        logger.info("Loading existing RSA key-pair from '%s'.", config.KEY_DIR)
        with open(priv_path, "rb") as f:
            return f.read()

    logger.info("Generating new 2048-bit RSA key-pair …")
    priv_pem, pub_pem = generate_rsa_keypair()
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    logger.info("Keys written to '%s'.", config.KEY_DIR)
    return priv_pem


# ─────────────────────────────────────────────────────────────────────────────
# Audio playback
# ─────────────────────────────────────────────────────────────────────────────

def play_audio(raw_pcm: bytes) -> None:
    """Play raw int16 PCM audio.  Gracefully degrades if sounddevice absent."""
    try:
        import sounddevice as sd
        import numpy as np

        samples = np.frombuffer(raw_pcm, dtype=np.int16)
        logger.info("Playing audio (%d samples)…", len(samples))
        sd.play(samples, samplerate=config.AUDIO_SAMPLE_RATE, blocking=True)
        logger.info("Playback complete.")
    except ImportError:
        logger.warning(
            "sounddevice not installed — cannot play audio. "
            "Raw payload is %d bytes.",
            len(raw_pcm),
        )
    except Exception as exc:
        logger.error("Audio playback error: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Connection handler
# ─────────────────────────────────────────────────────────────────────────────

def handle_client(conn: object, addr: tuple, private_pem: bytes) -> None:
    """Handle a single sender connection in its own thread."""
    logger.info("Connection from %s:%d", *addr)
    try:
        while True:
            try:
                packet = recv_packet(conn)
            except ConnectionError:
                logger.info("Sender %s:%d disconnected.", *addr)
                break

            msg_type = packet.get("msg_type", "text")
            logger.info(
                "Received encrypted %s packet — ciphertext %d B, key %d B",
                msg_type,
                len(packet["ciphertext"]),
                len(packet["encrypted_key"]),
            )

            # ── decrypt & verify ─────────────────────────────────────────
            try:
                plaintext = hybrid_decrypt(private_pem, packet)
            except ValueError as exc:
                # Integrity failure — likely tampered (active MITM)
                logger.error("⚠  INTEGRITY FAILURE: %s", exc)
                print(f"\n⚠  INTEGRITY CHECK FAILED — message discarded.\n   ({exc})")
                continue
            except Exception as exc:
                logger.error("Decryption error: %s", exc)
                print(f"\n✗  Decryption failed: {exc}")
                continue

            # ── deliver ──────────────────────────────────────────────────
            print("\n" + "─" * 50)
            if msg_type == "text":
                print(f"📨  Text message received:\n    {plaintext.decode('utf-8', errors='replace')}")
            elif msg_type == "audio":
                print(f"🔊  Audio message received ({len(plaintext)} bytes PCM) — playing…")
                play_audio(plaintext)
            else:
                print(f"?   Unknown message type '{msg_type}' — {len(plaintext)} bytes.")
            print("─" * 50)

    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def run(host: str, port: int) -> None:
    private_pem = ensure_keys()

    print("\n╔══════════════════════════════════════╗")
    print("║      Secure Receiver — Client B       ║")
    print("╚══════════════════════════════════════╝")
    print(f"  Listening on {host}:{port} …\n")

    srv = make_server_socket(host, port)
    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, private_pem),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        logger.info("Receiver shutting down.")
    finally:
        srv.close()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Secure Receiver")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=config.RECEIVER_PORT)
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(args.host, args.port)
