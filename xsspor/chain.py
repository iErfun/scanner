#!/usr/bin/env python3
"""
xomlsx Chain module (AES-GCM + PBKDF2-SHA256)
- Password derivation: PBKDF2-HMAC-SHA256 (100k iterations)
- All cryptographic hashes strictly SHA-256
- Proper sliding-window replay protection (deque)
- Cleaner padding handling for AES-GCM
- Better error messages + type safety
- Minor performance & safety improvements
"""

import hashlib
import hmac
import os
import json
import base64
import time
import zlib
from collections import deque
from typing import Optional, Dict, Any, Set

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    DIM = '\033[2m'
    MAGENTA = '\033[95m'


def c(color: str, text: str) -> str:
    return f"{color}{text}{Colors.RESET}"


def print_header(title: str) -> None:
    print("\n" + c(Colors.BOLD, c(Colors.CYAN, "=" * 60)))
    print(c(Colors.BOLD, c(Colors.CYAN, "  " + title)))
    print(c(Colors.BOLD, c(Colors.CYAN, "=" * 60)))


class ChainAdvanced:
    VERSION = "2.1"
    BLOCK_SIZE = 64
    MAX_REPLAY_WINDOW = 1000
    PBKDF2_ITERATIONS = 100_000

    def __init__(
        self,
        initial_key: Optional[bytes] = None,
        session_salt: Optional[bytes] = None,
        compress: bool = False,
        created_at: Optional[float] = None,
    ):
        if initial_key is None:
            initial_key = os.urandom(32)
        if not isinstance(initial_key, bytes) or len(initial_key) != 32:
            raise ValueError("initial_key must be 32 bytes")

        if session_salt is None:
            session_salt = os.urandom(16)
        if not isinstance(session_salt, bytes) or len(session_salt) < 8:
            raise ValueError("session_salt must be at least 8 bytes")

        self.initial_key = initial_key
        self.current_key = initial_key
        self.session_salt = session_salt
        self.stage = 0
        self.compress = compress
        self.created_at = created_at if created_at is not None else time.time()
        self.chain_hash = hashlib.sha256(session_salt).digest()
        # Sliding window for replay protection
        self.seen_stages: deque = deque(maxlen=self.MAX_REPLAY_WINDOW)

    def _derive_stage_key(self) -> bytes:
        """Derive a unique key for the current stage using HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.session_salt,
            info=b"stage|" + str(self.stage).encode(),
        )
        return hkdf.derive(self.current_key)

    def _ratchet(self) -> None:
        """Advance the chain key and update chain_hash (SHA-256)."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.session_salt,
            info=b"ratchet|" + str(self.stage).encode(),
        )
        self.current_key = hkdf.derive(self.current_key)
        self.chain_hash = hashlib.sha256(self.chain_hash + self.current_key).digest()

    def _pad(self, data: bytes) -> bytes:
        """PKCS#7-style padding to BLOCK_SIZE (optional for GCM but kept for consistency)."""
        pad_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        if pad_len == 0:
            pad_len = self.BLOCK_SIZE
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        if not data:
            raise ValueError("empty data after decryption")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > self.BLOCK_SIZE:
            raise ValueError(f"invalid padding length: {pad_len}")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("padding corruption detected")
        return data[:-pad_len]

    def _compute_mac(self, data: bytes) -> bytes:
        """HMAC-SHA256 over ciphertext (extra integrity layer)."""
        return hmac.new(self.current_key, data, hashlib.sha256).digest()

    def _build_aad(self) -> bytes:
        """Additional Authenticated Data for AES-GCM."""
        return (
            b"v" + self.VERSION.encode() +
            b"|stage:" + str(self.stage).encode() +
            b"|hash:" + self.chain_hash[:8].hex().encode()
        )

    def encode(self, data: bytes) -> Dict[str, Any]:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")

        if self.compress:
            data = zlib.compress(data, level=9)

        padded = self._pad(data)
        stage_key = self._derive_stage_key()
        nonce = os.urandom(12)
        aad = self._build_aad()

        aesgcm = AESGCM(stage_key)
        ciphertext = aesgcm.encrypt(nonce, padded, aad)
        mac = self._compute_mac(ciphertext)

        packet = {
            "v": self.VERSION,
            "stage": self.stage,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "mac": mac.hex(),
        }

        self._ratchet()
        self.stage += 1
        return packet

    def decode(self, packet: Dict[str, Any]) -> bytes:
        if not isinstance(packet, dict):
            raise TypeError("packet must be a dict")

        if packet.get("v") != self.VERSION:
            raise ValueError(f"unsupported version: {packet.get('v')}")

        stage = packet.get("stage")
        if stage is None:
            raise ValueError("missing stage in packet")

        if stage != self.stage:
            raise ValueError(
                f"stage mismatch: expected {self.stage}, got {stage}"
            )

        if stage in self.seen_stages:
            raise ValueError(f"replay detected for stage {stage}")

        stage_key = self._derive_stage_key()
        try:
            nonce = bytes.fromhex(packet["nonce"])
            ciphertext = bytes.fromhex(packet["ciphertext"])
            mac = bytes.fromhex(packet["mac"])
        except (KeyError, ValueError) as e:
            raise ValueError(f"malformed packet fields: {e}")

        if len(nonce) != 12:
            raise ValueError("invalid nonce length")

        expected_mac = self._compute_mac(ciphertext)
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("MAC verification failed")

        aad = self._build_aad()
        aesgcm = AESGCM(stage_key)
        try:
            padded = aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise ValueError(f"decryption failed at stage {stage}: {e}")

        data = self._unpad(padded)

        if self.compress:
            try:
                data = zlib.decompress(data)
            except Exception as e:
                raise ValueError(f"decompression failed: {e}")

        self.seen_stages.append(stage)
        self._ratchet()
        self.stage += 1
        return data

    def reset(self) -> None:
        self.current_key = self.initial_key
        self.stage = 0
        self.chain_hash = hashlib.sha256(self.session_salt).digest()
        self.seen_stages.clear()

    def is_expired(self, max_age: int = 3600) -> bool:
        return (time.time() - self.created_at) > max_age

    def save_state(self, path: str) -> None:
        state = {
            "version": self.VERSION,
            "initial_key": self.initial_key.hex(),
            "current_key": self.current_key.hex(),
            "session_salt": self.session_salt.hex(),
            "stage": self.stage,
            "chain_hash": self.chain_hash.hex(),
            "created_at": self.created_at,
            "compress": self.compress,
            "seen_stages": list(self.seen_stages),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)

    @classmethod
    def load_state(cls, path: str) -> "ChainAdvanced":
        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)

        chain = cls(
            initial_key=bytes.fromhex(state["initial_key"]),
            session_salt=bytes.fromhex(state["session_salt"]),
            compress=state.get("compress", False),
            created_at=state.get("created_at"),
        )
        chain.current_key = bytes.fromhex(state["current_key"])
        chain.stage = state["stage"]
        chain.chain_hash = bytes.fromhex(state["chain_hash"])
        chain.seen_stages = deque(state.get("seen_stages", []), maxlen=cls.MAX_REPLAY_WINDOW)
        return chain

    def get_info(self) -> Dict[str, Any]:
        return {
            "version": self.VERSION,
            "stage": self.stage,
            "chain_hash": self.chain_hash.hex()[:16] + "...",
            "session_age": round(time.time() - self.created_at, 1),
            "compressed": self.compress,
            "replay_window": len(self.seen_stages),
        }


def hash_password(password: str, salt: Optional[bytes] = None, iterations: int = 100_000) -> bytes:
    """
    Derive a 32-byte key from password using PBKDF2-HMAC-SHA256.
    This is the hardened version (requested SHA-256 based KDF).
    """
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")

    if salt is None:
        # Static salt for simplicity in tools; in production prefer random salt stored with state
        salt = b"aac2-chain-v2.1-static-salt"

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def packet_to_d(packet: Dict[str, Any]) -> str:
    """Serialize packet to URL-safe base64 (no padding) for GET parameter."""
    raw = json.dumps(packet, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def d_to_packet(d: str) -> Dict[str, Any]:
    """Deserialize from URL-safe base64 parameter."""
    padding = "=" * ((4 - len(d) % 4) % 4)
    raw = base64.urlsafe_b64decode(d + padding)
    return json.loads(raw.decode("utf-8"))
