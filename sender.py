"""
sender.py — Secure Message Sender (Client A)
=============================================
Responsibilities
----------------
1. Load the receiver's RSA public key.
2. Prompt the user for a text message OR record a short audio clip.
3. Encrypt the payload with hybrid RSA+AES (via crypto_utils).
4. Send the encrypted packet to either the receiver directly or
   through the attacker proxy (controlled by config.py / env vars).

Usage
-----
    # Direct mode (no attacker):
    RECEIVER_HOST=192.168.1.10 RECEIVER_PORT=9001 python sender.py

    # Via MITM proxy:
    RECEIVER_HOST=192.168.1.20 RECEIVER_PORT=9000 python sender.py
"""

import os
import sys
import logging
import argparse

import numpy as np

import config
from crypto_utils import hybrid_encrypt
from network_utils import make_client_socket, send_packet

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s [SENDER] %(levelname)s  %(message)s",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Key management
# ─────────────────────────────────────────────────────────────────────────────

def load_receiver_public_key() -> bytes:
    """Read the receiver's RSA public key from disk."""
    path = config.RECEIVER_PUB_KEY
    if not os.path.exists(path):
        logger.error(
            "Receiver public key not found at '%s'. "
            "Run keygen.py first.",
            path,
        )
        sys.exit(1)
    with open(path, "rb") as f:
        return f.read()


# ─────────────────────────────────────────────────────────────────────────────
# Audio recording
# ─────────────────────────────────────────────────────────────────────────────

def record_audio(duration: float = config.AUDIO_DURATION) -> bytes:
    """
    Record *duration* seconds from the default microphone.

    Returns raw PCM bytes (int16, mono, 44 100 Hz).
    Falls back to synthetic noise if sounddevice is unavailable.
    """
    try:
        import sounddevice as sd  # optional dependency

        logger.info("Recording %.1f second(s)… speak now!", duration)
        samples = sd.rec(
            int(duration * config.AUDIO_SAMPLE_RATE),
            samplerate=config.AUDIO_SAMPLE_RATE,
            channels=config.AUDIO_CHANNELS,
            dtype="int16",
        )
        sd.wait()
        logger.info("Recording complete.")
        return samples.tobytes()

    except ImportError:
        logger.warning(
            "sounddevice not installed — using synthetic noise as demo audio."
        )
        rng    = np.random.default_rng()
        noise  = rng.integers(-32768, 32767, size=int(duration * config.AUDIO_SAMPLE_RATE), dtype=np.int16)
        return noise.tobytes()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def run(host: str, port: int) -> None:
    pub_key = load_receiver_public_key()
    logger.info("Receiver public key loaded (%d bytes).", len(pub_key))

    print("\n╔══════════════════════════════════════╗")
    print("║        Secure Sender — Client A       ║")
    print("╚══════════════════════════════════════╝")
    print("  Connecting to %s:%d …", host, port)

    sock = make_client_socket(host, port)
    logger.info("Connected to %s:%d", host, port)

    try:
        while True:
            print("\n[1] Send text message")
            print("[2] Send audio message")
            print("[q] Quit")
            choice = input("Choice: ").strip().lower()

            if choice == "q":
                break

            elif choice == "1":
                text     = input("Message: ")
                payload  = text.encode("utf-8")
                msg_type = "text"

            elif choice == "2":
                payload  = record_audio()
                msg_type = "audio"
                logger.info("Audio payload: %d bytes", len(payload))

            else:
                print("Invalid choice.")
                continue

            # ── encrypt ──────────────────────────────────────────────────
            packet = hybrid_encrypt(pub_key, payload, msg_type=msg_type)
            logger.info(
                "Encrypted %s (%d plaintext bytes) → "
                "ciphertext %d bytes, key %d bytes, digest %s",
                msg_type,
                len(payload),
                len(packet["ciphertext"]),
                len(packet["encrypted_key"]),
                packet["digest"].hex()[:16] + "…",
            )

            # ── transmit ─────────────────────────────────────────────────
            send_packet(sock, packet)
            logger.info("Packet sent.")
            print("✓  Message sent successfully.")

    except ConnectionError as exc:
        logger.error("Connection error: %s", exc)
    finally:
        sock.close()
        logger.info("Sender disconnected.")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Secure Sender")
    p.add_argument("--host", default=config.RECEIVER_HOST)
    p.add_argument("--port", type=int, default=config.RECEIVER_PORT)
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(args.host, args.port)
