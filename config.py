"""
config.py — Shared Configuration
==================================
All IP / port / path settings live here so every component reads from
one source of truth.  Override via environment variables for deployment.
"""

import os

# ── Network topology ──────────────────────────────────────────────────────────
#
#   Sender  ──►  MITM proxy  ──►  Receiver
#
#   When running WITHOUT an attacker:
#       Sender connects directly to RECEIVER_HOST:RECEIVER_PORT
#
#   When running WITH an attacker:
#       Sender connects to ATTACKER_HOST:ATTACKER_LISTEN_PORT
#       Attacker forwards to RECEIVER_HOST:RECEIVER_PORT

RECEIVER_HOST = os.getenv("RECEIVER_HOST", "127.0.0.1")
RECEIVER_PORT = int(os.getenv("RECEIVER_PORT", "9001"))

ATTACKER_HOST         = os.getenv("ATTACKER_HOST", "127.0.0.1")
ATTACKER_LISTEN_PORT  = int(os.getenv("ATTACKER_LISTEN_PORT", "9000"))

# ── Key / certificate paths ───────────────────────────────────────────────────
KEY_DIR           = os.getenv("KEY_DIR", "./keys")
RECEIVER_PRIV_KEY = os.path.join(KEY_DIR, "receiver_private.pem")
RECEIVER_PUB_KEY  = os.path.join(KEY_DIR, "receiver_public.pem")

# ── Audio settings ────────────────────────────────────────────────────────────
AUDIO_SAMPLE_RATE = int(os.getenv("AUDIO_SAMPLE_RATE", "44100"))
AUDIO_CHANNELS    = int(os.getenv("AUDIO_CHANNELS",    "1"))
AUDIO_DURATION    = float(os.getenv("AUDIO_DURATION",  "3.0"))   # seconds

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL        = os.getenv("LOG_LEVEL", "INFO")
INTERCEPT_LOG    = os.getenv("INTERCEPT_LOG", "./logs/intercept.log")
