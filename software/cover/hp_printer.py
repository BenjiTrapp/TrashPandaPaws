#!/usr/bin/env python3
"""
HP Color LaserJet Pro MFP M478 cover identity.
Emulates a full HP network printer: HTTP (401), JetDirect/PJL (9100),
LPD (515), CUPS/IPP (631), SNMP (161) with proper BER encoding, and Telnet (23).
Logs all authentication attempts, connection metadata, and browser fingerprints.

Based on: https://github.com/Meowmycks/fakeprinter
"""

import json
import os
import random
import socket
import struct
import threading
import time
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger("raccoon.cover.printer")

HP_OUIS = ["00:1E:0B", "00:21:5A", "00:25:B3", "3C:D9:2B", "9C:B6:54", "A0:D3:C1"]

PRINTER_MODEL = "HP Color LaserJet Pro MFP M478"
FIRMWARE_VERSION = "002_2445A"
SERIAL_NUMBER = "VNB4G64636"
SERVER_BANNER = "uhttpd/1.0.0"
CUPS_VERSION = "CUPS/2.4.10"

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

FINGERPRINT_JS = """
<script>
(function(){
    var d={ts:new Date().toISOString()};
    try{d.ua=navigator.userAgent}catch(e){}
    try{d.lang=navigator.language;d.langs=navigator.languages?navigator.languages.join(','):''}catch(e){}
    try{d.plat=navigator.platform}catch(e){}
    try{d.cores=navigator.hardwareConcurrency||0}catch(e){}
    try{d.mem=navigator.deviceMemory||0}catch(e){}
    try{d.sw=screen.width;d.sh=screen.height;d.cd=screen.colorDepth;
        d.aw=screen.availWidth;d.ah=screen.availHeight}catch(e){}
    try{d.tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
        d.tzo=new Date().getTimezoneOffset()}catch(e){}
    try{d.touch='ontouchstart'in window?1:0}catch(e){}
    try{d.dnt=navigator.doNotTrack||'unset'}catch(e){}
    try{d.cook=navigator.cookieEnabled?1:0}catch(e){}
    try{var c=document.createElement('canvas');var g=c.getContext('2d');
        c.width=200;c.height=50;g.textBaseline='top';
        g.font='14px Arial';g.fillStyle='#f60';g.fillRect(0,0,200,50);
        g.fillStyle='#069';g.fillText('HPM478fp',2,15);
        g.fillStyle='rgba(102,204,0,0.7)';g.fillText('HPM478fp',4,17);
        d.cvs=c.toDataURL().slice(-32)}catch(e){}
    try{var gl=document.createElement('canvas').getContext('webgl');
        if(gl){var dbg=gl.getExtension('WEBGL_debug_renderer_info');
        if(dbg){d.gpu=gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)}}}catch(e){}
    try{d.plugins=[];for(var i=0;i<Math.min(navigator.plugins.length,10);i++){
        d.plugins.push(navigator.plugins[i].name)}}catch(e){}
    try{var r=window.RTCPeerConnection||window.webkitRTCPeerConnection;
        if(r){var pc=new r({iceServers:[]});
        pc.createDataChannel('');
        pc.createOffer().then(function(o){pc.setLocalDescription(o)});
        pc.onicecandidate=function(e){if(e&&e.candidate){
            var m=e.candidate.candidate.match(/([0-9]{1,3}(\\.[0-9]{1,3}){3})/);
            if(m){d.localip=m[1];send()}pc.onicecandidate=null;pc.close()}}}}catch(e){}
    function send(){
        var x=new XMLHttpRequest();
        x.open('POST','/.hp-internal/fp',true);
        x.setRequestHeader('Content-Type','application/json');
        x.send(JSON.stringify(d));
    }
    setTimeout(send,500);
})();
</script>
"""


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.100"


def _generate_hp_mac(mac_prefix: str = None) -> str:
    prefix = mac_prefix.upper() if mac_prefix else random.choice(HP_OUIS)
    suffix = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
    return f"{prefix}:{suffix}"


# ── SNMP BER encoder ──

def _ber_encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _ber_encode_int(value: int) -> bytes:
    if value == 0:
        payload = b"\x00"
    elif value > 0:
        payload = value.to_bytes((value.bit_length() + 8) // 8, "big")
    else:
        bl = (value.bit_length() + 9) // 8
        payload = value.to_bytes(bl, "big", signed=True)
    return b"\x02" + _ber_encode_length(len(payload)) + payload


def _ber_encode_string(value: str) -> bytes:
    data = value.encode()
    return b"\x04" + _ber_encode_length(len(data)) + data


def _ber_encode_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.split(".")]
    if len(parts) < 2:
        return b"\x06\x00"
    encoded = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 128:
            encoded += bytes([p])
        else:
            chunks = []
            chunks.append(p & 0x7F)
            p >>= 7
            while p:
                chunks.append(0x80 | (p & 0x7F))
                p >>= 7
            encoded += bytes(reversed(chunks))
    return b"\x06" + _ber_encode_length(len(encoded)) + encoded


def _ber_decode_oid(data: bytes) -> str:
    if not data:
        return ""
    parts = [str(data[0] // 40), str(data[0] % 40)]
    i = 1
    while i < len(data):
        val = 0
        while i < len(data):
            val = (val << 7) | (data[i] & 0x7F)
            if not (data[i] & 0x80):
                i += 1
                break
            i += 1
        parts.append(str(val))
    return ".".join(parts)


def _ber_wrap_sequence(data: bytes) -> bytes:
    return b"\x30" + _ber_encode_length(len(data)) + data


def _parse_snmp_request(data: bytes) -> Optional[dict]:
    """Parse an SNMPv1/v2c GET request and extract version, community, request-id, OID."""
    try:
        pos = 0
        if data[pos] != 0x30:
            return None
        pos += 1
        seq_len, pos = _decode_ber_length(data, pos)

        if data[pos] != 0x02:
            return None
        pos += 1
        ver_len, pos = _decode_ber_length(data, pos)
        version = int.from_bytes(data[pos:pos + ver_len], "big")
        pos += ver_len

        if data[pos] != 0x04:
            return None
        pos += 1
        com_len, pos = _decode_ber_length(data, pos)
        community = data[pos:pos + com_len].decode(errors="ignore")
        pos += com_len

        pdu_type = data[pos]
        pos += 1
        pdu_len, pos = _decode_ber_length(data, pos)

        if data[pos] != 0x02:
            return None
        pos += 1
        rid_len, pos = _decode_ber_length(data, pos)
        request_id = int.from_bytes(data[pos:pos + rid_len], "big", signed=True)
        pos += rid_len

        # error-status
        pos += 1
        es_len, pos = _decode_ber_length(data, pos)
        pos += es_len
        # error-index
        pos += 1
        ei_len, pos = _decode_ber_length(data, pos)
        pos += ei_len

        # varbind list
        if data[pos] != 0x30:
            return None
        pos += 1
        vbl_len, pos = _decode_ber_length(data, pos)

        oids = []
        end = pos + vbl_len
        while pos < end:
            if data[pos] != 0x30:
                break
            pos += 1
            vb_len, pos = _decode_ber_length(data, pos)
            if data[pos] != 0x06:
                pos += vb_len
                continue
            pos += 1
            oid_len, pos = _decode_ber_length(data, pos)
            oid_str = _ber_decode_oid(data[pos:pos + oid_len])
            oids.append(oid_str)
            pos += oid_len
            # skip value (NULL typically)
            val_tag = data[pos] if pos < len(data) else 0
            pos += 1
            val_len, pos = _decode_ber_length(data, pos)
            pos += val_len

        return {
            "version": version,
            "community": community,
            "pdu_type": pdu_type,
            "request_id": request_id,
            "oids": oids,
        }
    except Exception:
        return None


def _decode_ber_length(data: bytes, pos: int) -> tuple[int, int]:
    if data[pos] < 0x80:
        return data[pos], pos + 1
    num_bytes = data[pos] & 0x7F
    pos += 1
    length = int.from_bytes(data[pos:pos + num_bytes], "big")
    return length, pos + num_bytes


def _build_snmp_response(request_id: int, community: str, oid_str: str, value: str, version: int = 0) -> bytes:
    """Build a proper SNMPv1/v2c GET-Response."""
    # version
    ver_bytes = _ber_encode_int(version)
    # community
    com_bytes = b"\x04" + _ber_encode_length(len(community.encode())) + community.encode()
    # request-id
    rid_bytes = _ber_encode_int(request_id)
    # error-status = 0
    err_stat = _ber_encode_int(0)
    # error-index = 0
    err_idx = _ber_encode_int(0)
    # varbind: OID + OctetString value
    oid_bytes = _ber_encode_oid(oid_str)
    val_bytes = _ber_encode_string(value)
    varbind = _ber_wrap_sequence(oid_bytes + val_bytes)
    varbind_list = _ber_wrap_sequence(varbind)
    # PDU (GetResponse = 0xA2)
    pdu_content = rid_bytes + err_stat + err_idx + varbind_list
    pdu = b"\xa2" + _ber_encode_length(len(pdu_content)) + pdu_content
    # Full message
    msg_content = ver_bytes + com_bytes + pdu
    return _ber_wrap_sequence(msg_content)


class HPPrinterCover:
    """Manages the HP Printer cover identity (HTTP + PJL + LPD + IPP + SNMP + Telnet)."""

    def __init__(self, config: dict):
        global PRINTER_MODEL, FIRMWARE_VERSION

        self.host = "0.0.0.0"

        printer_cfg = config.get("cover", {}).get("hp_printer", {})
        self.http_port = printer_cfg.get("http_port", 80)
        self.pjl_port = printer_cfg.get("pjl_port", 9100)
        self.lpd_port = printer_cfg.get("lpd_port", 515)
        self.ipp_port = printer_cfg.get("ipp_port", 631)
        self.snmp_port = printer_cfg.get("snmp_port", 161)
        self.telnet_port = printer_cfg.get("telnet_port", 23)

        self.local_ip = _get_local_ip()
        self.mac_address = _generate_hp_mac(printer_cfg.get("mac_prefix"))
        self.mac_raw = self.mac_address.replace(":", "")
        self.hostname = printer_cfg.get("hostname", f"HP-LaserJet-{self.mac_raw[-4:]}")
        self.device_model = printer_cfg.get("model", PRINTER_MODEL)
        self.firmware_version = printer_cfg.get("firmware", FIRMWARE_VERSION)

        PRINTER_MODEL = self.device_model
        FIRMWARE_VERSION = self.firmware_version

        self._running = False
        self._threads: list[threading.Thread] = []
        self._lpd_jobs = 0
        self._ipp_jobs = 0

    # ── HTTP Server (port 80) — HP EWS login ──

    _HP_LOGO_B64 = ""

    @classmethod
    def _load_logo_b64(cls):
        if cls._HP_LOGO_B64:
            return
        b64_path = os.path.join(STATIC_DIR, "hp_logo_80.b64")
        try:
            with open(b64_path) as f:
                cls._HP_LOGO_B64 = f.read().strip()
        except FileNotFoundError:
            cls._HP_LOGO_B64 = ""

    def _run_http(self):
        self._load_logo_b64()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.http_port))
        sock.listen(5)
        logger.info("HTTP admin on :%d", self.http_port)

        while self._running:
            try:
                sock.settimeout(1.0)
                client, addr = sock.accept()
                threading.Thread(
                    target=self._handle_http, args=(client, addr), daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                logger.error("HTTP accept error: %s", e)
        sock.close()

    EWS_TABS = [
        ("/", "Home"),
        ("/scan", "Scan"),
        ("/fax", "Fax"),
        ("/webservices", "Web Services"),
        ("/network", "Network"),
        ("/tools", "Tools"),
        ("/settings", "Settings"),
    ]

    def _handle_http(self, client: socket.socket, addr):
        try:
            data = client.recv(4096).decode(errors="ignore")
            if not data:
                return

            if "GET /favicon.ico" in data:
                self._serve_static(client, "hp-favicon.ico", "image/x-icon")
                return

            if "GET /static/hp_logo.png" in data:
                self._serve_static(client, "hp_logo.png", "image/png")
                return

            if "POST /.hp-internal/fp" in data:
                self._handle_fingerprint(client, addr, data)
                return

            if "POST " in data.split("\r\n")[0]:
                self._handle_login_post(client, addr, data)
                return

            if "Authorization: Basic" in data:
                import base64
                for line in data.split("\r\n"):
                    if line.startswith("Authorization: Basic "):
                        try:
                            creds = base64.b64decode(line.split(" ", 2)[2]).decode(errors="replace")
                            logger.warning("HTTP credential capture from %s — %s", addr[0], creds)
                            from software.notifications import get_notifier
                            notifier = get_notifier()
                            if notifier:
                                user, _, pw = creds.partition(":")
                                notifier.notify(
                                    "credential",
                                    "HP Printer — HTTP Basic Auth",
                                    source=addr[0],
                                    username=user,
                                    password=pw,
                                )
                        except Exception:
                            pass

            request_line = data.split("\r\n")[0]
            path = request_line.split(" ")[1] if len(request_line.split(" ")) > 1 else "/"
            path = path.split("?")[0]
            logger.info("HTTP %s from %s — %s", request_line.split(" ")[0], addr[0], path)
            self._serve_login(client, path=path)
        except Exception as e:
            logger.debug("HTTP handler error: %s", e)
        finally:
            client.close()

    def _handle_login_post(self, client: socket.socket, addr, data: str):
        request_line = data.split("\r\n")[0]
        path = request_line.split(" ")[1] if len(request_line.split(" ")) > 1 else "/"
        path = path.split("?")[0]

        body = data.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in data else ""
        from urllib.parse import parse_qs
        params = parse_qs(body)
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]

        if username or password:
            logger.warning("EWS login attempt from %s on %s — user=%s pass=%s", addr[0], path, username, password)
            from software.notifications import get_notifier
            notifier = get_notifier()
            if notifier:
                notifier.notify(
                    "credential",
                    "HP Printer — EWS Login Attempt",
                    source=addr[0],
                    page=path,
                    username=username,
                    password=password,
                )

        self._serve_login(client, error=True, path=path)

    def _handle_fingerprint(self, client: socket.socket, addr, data: str):
        try:
            body = data.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in data else ""
            if body:
                fp = json.loads(body)
                logger.warning(
                    "Browser fingerprint from %s — %s",
                    addr[0], json.dumps(fp, ensure_ascii=False),
                )
                from software.notifications import get_notifier
                notifier = get_notifier()
                if notifier:
                    notifier.notify(
                        "fingerprint",
                        "HP Printer — Browser Fingerprint",
                        source=addr[0],
                        **fp,
                    )
        except Exception:
            pass
        response = "HTTP/1.1 204 No Content\r\nServer: uhttpd/1.0.0\r\nContent-Length: 0\r\n\r\n"
        client.sendall(response.encode())

    def _serve_static(self, client: socket.socket, filename: str, content_type: str):
        filepath = os.path.join(STATIC_DIR, filename)
        try:
            with open(filepath, "rb") as f:
                file_data = f.read()
            header = (
                f"HTTP/1.1 200 OK\r\n"
                f"Server: {SERVER_BANNER}\r\n"
                f"Content-Type: {content_type}\r\n"
                f"Content-Length: {len(file_data)}\r\n"
                f"Cache-Control: public, max-age=3600\r\n"
                f"\r\n"
            )
            client.sendall(header.encode() + file_data)
        except FileNotFoundError:
            self._http_send(client, 404, "Not Found", "")

    EWS_PAGE_HINTS = {
        "/": ("Home", "View printer status, supply levels and general information."),
        "/scan": ("Scan", "Configure scan-to-email, scan-to-folder and scan settings."),
        "/fax": ("Fax", "Configure fax settings, speed dials and fax logs."),
        "/webservices": ("Web Services", "Configure cloud printing and Web Services settings."),
        "/network": ("Network", "View and configure network settings, IPv4/IPv6, SNMP and security."),
        "/tools": ("Tools", "Firmware updates, diagnostic tools and usage reports."),
        "/settings": ("Settings", "Configure general printer settings and security options."),
    }

    def _serve_login(self, client: socket.socket, error: bool = False, path: str = "/"):
        error_html = ""
        if error:
            error_html = (
                '<div style="background:#fce4e4;border:1px solid #c00;color:#c00;'
                'padding:10px;border-radius:4px;margin-bottom:20px;font-size:13px;text-align:center">'
                '&#10060; The password you entered is incorrect. Please try again.</div>'
            )

        logo_src = f"data:image/png;base64,{self._HP_LOGO_B64}" if self._HP_LOGO_B64 else "/static/hp_logo.png"

        nav_html = ""
        for tab_path, tab_label in self.EWS_TABS:
            active = " class=\"active\"" if tab_path == path else ""
            nav_html += f'<a href="{tab_path}"{active}>{tab_label}</a>\n'

        page_name, page_hint = self.EWS_PAGE_HINTS.get(path, ("Printer", "Sign in to access this feature."))
        title_section = f"{page_name} &mdash; " if path != "/" else ""

        body = f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>{PRINTER_MODEL} - {page_name}</title>
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Arial,Helvetica,sans-serif;background:#f5f5f5;color:#333}}
.ews-header{{background:#fff;border-bottom:3px solid #0096d6;padding:12px 24px;
    display:flex;align-items:center;justify-content:space-between}}
.ews-header img{{height:40px}}
.ews-header .model{{font-size:14px;color:#666}}
.ews-nav{{background:#0096d6;padding:0 24px}}
.ews-nav a{{display:inline-block;padding:10px 18px;color:#fff;text-decoration:none;
    font-size:13px;font-weight:500;transition:background 0.2s}}
.ews-nav a:hover,.ews-nav a.active{{background:#007bb5}}
.ews-body{{max-width:960px;margin:0 auto;padding:30px 24px}}
.page-title{{font-size:20px;font-weight:600;color:#333;margin-bottom:6px}}
.page-breadcrumb{{font-size:12px;color:#888;margin-bottom:24px}}
.page-breadcrumb a{{color:#0096d6;text-decoration:none}}
.login-card{{background:#fff;border:1px solid #ddd;border-radius:6px;
    max-width:420px;margin:20px auto;padding:40px;box-shadow:0 2px 8px rgba(0,0,0,0.08)}}
.login-card h2{{font-size:18px;color:#333;margin-bottom:8px;font-weight:600}}
.login-card .sub{{font-size:13px;color:#666;margin-bottom:24px}}
.form-group{{margin-bottom:18px}}
.form-group label{{display:block;font-size:13px;color:#555;margin-bottom:5px;font-weight:600}}
.form-group input{{width:100%;padding:10px 12px;border:1px solid #ccc;border-radius:4px;
    font-size:14px}}
.form-group input:focus{{outline:none;border-color:#0096d6;box-shadow:0 0 0 2px rgba(0,150,214,0.15)}}
.login-btn{{width:100%;padding:11px;background:#0096d6;color:#fff;border:none;
    border-radius:4px;font-size:15px;font-weight:600;cursor:pointer;transition:background 0.2s}}
.login-btn:hover{{background:#007bb5}}
.ews-footer{{text-align:center;padding:20px;font-size:11px;color:#999;
    border-top:1px solid #eee;margin-top:40px}}
.lock-icon{{text-align:center;margin-bottom:20px}}
.lock-icon svg{{width:48px;height:48px;fill:#0096d6}}
.info-row{{font-size:11px;color:#999;text-align:center;margin-top:16px}}
</style></head><body>
<div class="ews-header">
    <div style="display:flex;align-items:center;gap:16px">
        <img src="{logo_src}" alt="HP" style="height:40px">
        <div>
            <div style="font-size:16px;font-weight:600;color:#333">{PRINTER_MODEL}</div>
            <div class="model">Embedded Web Server</div>
        </div>
    </div>
    <div style="font-size:12px;color:#999">
        <span style="display:inline-block;width:8px;height:8px;background:#4caf50;
            border-radius:50%;margin-right:4px"></span>Ready
    </div>
</div>
<div class="ews-nav">
    {nav_html}
</div>
<div class="ews-body">
    <div class="page-breadcrumb"><a href="/">Home</a> &rsaquo; {page_name}</div>
    <div class="page-title">{title_section}Authentication required</div>
    <div class="login-card">
        <div class="lock-icon">
            <svg viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1
            0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9
            2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2
            2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1
            3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>
        </div>
        <h2>Administrator Login</h2>
        <div class="sub">{page_hint}</div>
        {error_html}
        <form method="POST" action="{path}">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" value="admin" autocomplete="off">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter password" required autofocus>
            </div>
            <button type="submit" class="login-btn">Sign In</button>
        </form>
        <div class="info-row">
            {PRINTER_MODEL} &bull; FW {FIRMWARE_VERSION} &bull; S/N {SERIAL_NUMBER}<br>
            IP: {self.local_ip} &bull; MAC: {self.mac_address}
        </div>
    </div>
</div>
<div class="ews-footer">
    &copy; Copyright 2024 HP Development Company, L.P.
</div>
{FINGERPRINT_JS}
</body></html>"""

        code = 401 if error else 200
        status = "Unauthorized" if error else "OK"
        response = (
            f"HTTP/1.1 {code} {status}\r\n"
            f"Server: {SERVER_BANNER}\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            f"X-Frame-Options: SAMEORIGIN\r\n"
            f"X-Content-Type-Options: nosniff\r\n"
            f"Cache-Control: no-cache, no-store, must-revalidate\r\n"
            f"\r\n"
        )
        client.sendall(response.encode() + body.encode())

    def _http_send(self, client: socket.socket, code: int, status: str, body: str):
        response = (
            f"HTTP/1.1 {code} {status}\r\n"
            f"Server: {SERVER_BANNER}\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n{body}"
        )
        client.sendall(response.encode())

    # ── PJL / JetDirect (port 9100) ──

    def _run_pjl(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.pjl_port))
        sock.listen(5)
        logger.info("JetDirect/PJL on :%d", self.pjl_port)

        while self._running:
            try:
                sock.settimeout(1.0)
                client, addr = sock.accept()
                logger.info("JetDirect connection from %s", addr[0])
                threading.Thread(
                    target=self._handle_pjl, args=(client,), daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                logger.error("PJL accept error: %s", e)
        sock.close()

    def _handle_pjl(self, client: socket.socket):
        buf = ""
        try:
            while self._running:
                data = client.recv(1024).decode(errors="ignore")
                if not data:
                    break
                buf += data
                if "\n" in buf:
                    response = self._pjl_response(buf.strip())
                    buf = ""
                    if response:
                        client.sendall(response.encode())
        except Exception as e:
            logger.debug("PJL handler error: %s", e)
        finally:
            client.close()

    def _pjl_response(self, command: str) -> Optional[str]:
        responses = {
            "@PJL INFO ID": f"{PRINTER_MODEL}\r\n",
            "@PJL INFO STATUS": "CODE=10000 READY\r\n@PJL OK\r\n",
            "@PJL INFO CONFIG": (
                "@PJL INFO CONFIG\r\n"
                "DefaultPaper = A4\r\nPrintResolution = 600\r\nDuplex = OFF\r\n"
                "@PJL OK\r\n"
            ),
            "@PJL INFO VARIABLES": (
                "@PJL INFO VARIABLES\r\n"
                "DEFAULT PAPER=A4\r\nDEFAULT RESOLUTION=600\r\nDEFAULT COPIES=1\r\n"
                "@PJL OK\r\n"
            ),
            "@PJL INFO MEMORY": "TOTAL=8388608 AVAILABLE=4993912\r\n@PJL OK\r\n",
            "@PJL INFO FILESYS": (
                "@PJL INFO FILESYS\r\n"
                "Filesystem=RAMDISK\r\nFree=4993912\r\nTotal=8388608\r\n"
                "@PJL OK\r\n"
            ),
            "@PJL USTATUS": "USTATUS OFF\r\n@PJL OK\r\n",
            "@PJL RESET": "\r\n",
        }

        if "@PJL INFO PRODINFO" in command:
            return (
                f"@PJL INFO PRODINFO\r\n"
                f"ProductName = {PRINTER_MODEL}\r\n"
                f"FormatterNumber = Q910CHL\r\n"
                f"PrinterNumber = Q1234A\r\n"
                f"ProductSerialNumber = {SERIAL_NUMBER}\r\n"
                f"ServiceID = 20127\r\n"
                f"FirmwareDateCode = 20241211\r\n"
                f"MaxPrintResolution = 600\r\n"
                f"ControllerNumber = Q910CHL\r\n"
                f"DeviceDescription = {PRINTER_MODEL}\r\n"
                f"DeviceLang = ZJS PJL ACL HTTP\r\n"
                f"TotalMemory = 8388608\r\n"
                f"AvailableMemory = 4993912\r\n"
                f"Personality = 7\r\n"
                f"EngFWVer = 15\r\n"
                f"IPAddress = {self.local_ip}\r\n"
                f"HWAddress = {self.mac_raw}\r\n"
            )

        return responses.get(command.strip())

    # ── LPD (port 515) ──

    def _run_lpd(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.lpd_port))
        sock.listen(5)
        logger.info("LPD on :%d", self.lpd_port)

        while self._running:
            try:
                sock.settimeout(1.0)
                client, addr = sock.accept()
                logger.info("LPD connection from %s", addr[0])
                threading.Thread(
                    target=self._handle_lpd, args=(client,), daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                logger.error("LPD accept error: %s", e)
        sock.close()

    def _handle_lpd(self, client: socket.socket):
        try:
            data = client.recv(1024)
            if not data:
                return

            cmd = data[0]
            if cmd == 0x02:
                logger.info("LPD receive-job request")
                response = b"\x00"
            elif cmd == 0x03:
                logger.info("LPD control file received")
                response = b"\x00"
            elif cmd == 0x04:
                logger.info("LPD data file received")
                self._lpd_jobs += 1
                response = b"\x00"
            elif cmd == 0x05:
                queue_name = data[1:].decode(errors="ignore").strip() or "default"
                logger.info("LPD queue status request for '%s'", queue_name)
                response = (
                    f"Printer: {PRINTER_MODEL}\n"
                    f"Queue: {queue_name}\n"
                    f"Jobs: {self._lpd_jobs}\n"
                    f"Status: Ready\r\n"
                ).encode()
            else:
                logger.debug("LPD unknown command 0x%02x", cmd)
                response = b"\x00"

            client.sendall(response)
        except Exception as e:
            logger.debug("LPD handler error: %s", e)
        finally:
            client.close()

    # ── CUPS / IPP (port 631) ──

    def _run_ipp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.ipp_port))
        sock.listen(5)
        logger.info("CUPS/IPP on :%d", self.ipp_port)

        while self._running:
            try:
                sock.settimeout(1.0)
                client, addr = sock.accept()
                logger.info("IPP connection from %s", addr[0])
                threading.Thread(
                    target=self._handle_ipp, args=(client,), daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                logger.error("IPP accept error: %s", e)
        sock.close()

    def _handle_ipp(self, client: socket.socket):
        try:
            data = client.recv(4096)
            if not data:
                return

            if b"GET /" in data or b"HEAD /" in data:
                body = (
                    f"<html><head><title>{PRINTER_MODEL}</title></head>"
                    f"<body><h1>{PRINTER_MODEL}</h1>"
                    f"<p>Printer Status: Ready</p></body></html>"
                )
                response = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Server: {CUPS_VERSION}\r\n"
                    f"Content-Type: text/html\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"\r\n{body}"
                ).encode()
            elif b"POST /" in data:
                ipp_body = self._build_ipp_response(data)
                response = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Server: {CUPS_VERSION}\r\n"
                    f"Content-Type: application/ipp\r\n"
                    f"Content-Length: {len(ipp_body)}\r\n"
                    f"\r\n"
                ).encode() + ipp_body
            else:
                response = (
                    f"HTTP/1.1 400 Bad Request\r\n"
                    f"Server: {CUPS_VERSION}\r\n\r\n"
                ).encode()

            client.sendall(response)
        except Exception as e:
            logger.debug("IPP handler error: %s", e)
        finally:
            client.close()

    def _build_ipp_response(self, data: bytes) -> bytes:
        header_start = data.find(b"\r\n\r\n")
        if header_start == -1:
            header_start = data.find(b"\n\n")
        ipp_data = data[header_start + 4:] if header_start != -1 else data

        operation_id = None
        request_id = 1
        if len(ipp_data) >= 8:
            operation_id = (ipp_data[2] << 8) | ipp_data[3]
            request_id = int.from_bytes(ipp_data[4:8], "big")

        if operation_id == 0x0002:
            logger.info("IPP Get-Printer-Attributes")
            attrs = self._ipp_encode_attrs({
                "printer-name": PRINTER_MODEL,
                "printer-state": "3",
                "printer-state-reasons": "none",
                "printer-make-and-model": PRINTER_MODEL,
            })
        elif operation_id == 0x000B:
            self._ipp_jobs += 1
            logger.info("IPP Print-Job #%d", self._ipp_jobs)
            attrs = self._ipp_encode_attrs({
                "job-id": str(self._ipp_jobs),
                "job-state": "3",
            })
        elif operation_id == 0x000A:
            logger.info("IPP Get-Jobs")
            attrs = self._ipp_encode_attrs({
                "printer-name": PRINTER_MODEL,
                "printer-state": "3",
            })
        else:
            logger.debug("IPP operation 0x%04x", operation_id or 0)
            attrs = b""

        version = b"\x02\x00"
        status = b"\x00\x00"
        rid = request_id.to_bytes(4, "big")
        op_attrs_tag = b"\x01"
        charset = (
            b"\x47" + (4).to_bytes(2, "big") + b"utf-8"
            + b"\x00\x12attributes-charset"
        )
        lang = (
            b"\x48" + (5).to_bytes(2, "big") + b"en-us"
            + b"\x00\x1battributes-natural-language"
        )
        end_tag = b"\x03"

        return version + status + rid + op_attrs_tag + charset + lang + attrs + end_tag

    @staticmethod
    def _ipp_encode_attrs(attrs: dict) -> bytes:
        result = b"\x04"
        for name, value in attrs.items():
            name_bytes = name.encode()
            value_bytes = value.encode()
            result += (
                b"\x41"
                + len(name_bytes).to_bytes(2, "big") + name_bytes
                + len(value_bytes).to_bytes(2, "big") + value_bytes
            )
        return result

    # ── SNMP (port 161) — proper BER encoding ──

    SNMP_OIDS = {
        "1.3.6.1.2.1.1.1.0": f"{PRINTER_MODEL} - Firmware {FIRMWARE_VERSION}",
        "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.11.2.3.9.1",
        "1.3.6.1.2.1.1.3.0": "12345678",
        "1.3.6.1.2.1.1.4.0": "IT Department",
        "1.3.6.1.2.1.1.5.0": "HP-LaserJet",
        "1.3.6.1.2.1.1.6.0": "Office Floor 2",
        "1.3.6.1.2.1.25.3.2.1.3.1": PRINTER_MODEL,
        "1.3.6.1.2.1.43.5.1.1.11.1": SERIAL_NUMBER,
        "1.3.6.1.2.1.43.5.1.1.17.1": PRINTER_MODEL,
        "1.3.6.1.2.1.43.11.1.1.6.1.1": "Black Toner",
        "1.3.6.1.2.1.43.11.1.1.6.1.2": "Cyan Toner",
        "1.3.6.1.2.1.43.11.1.1.6.1.3": "Magenta Toner",
        "1.3.6.1.2.1.43.11.1.1.6.1.4": "Yellow Toner",
        "1.3.6.1.2.1.43.11.1.1.9.1.1": "85",
        "1.3.6.1.2.1.43.11.1.1.9.1.2": "72",
        "1.3.6.1.2.1.43.11.1.1.9.1.3": "91",
        "1.3.6.1.2.1.43.11.1.1.9.1.4": "68",
        "1.3.6.1.4.1.11.2.3.9.1.1.7.0": f"{PRINTER_MODEL}; Firmware {FIRMWARE_VERSION}",
    }

    def _run_snmp(self):
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock.bind((self.host, self.snmp_port))
        udp_sock.settimeout(1.0)
        logger.info("SNMP on :%d (UDP)", self.snmp_port)

        while self._running:
            try:
                data, addr = udp_sock.recvfrom(1024)
                parsed = _parse_snmp_request(data)
                if not parsed:
                    continue

                logger.debug(
                    "SNMP GET from %s community=%s oids=%s",
                    addr[0], parsed["community"], parsed["oids"],
                )

                for oid in parsed["oids"]:
                    value = self.SNMP_OIDS.get(oid, PRINTER_MODEL)
                    response = _build_snmp_response(
                        parsed["request_id"],
                        parsed["community"],
                        oid,
                        value,
                        parsed["version"],
                    )
                    udp_sock.sendto(response, addr)
            except socket.timeout:
                continue
            except Exception as e:
                logger.debug("SNMP error: %s", e)
        udp_sock.close()

    # ── Telnet (port 23) ──

    HP_TELNET_BANNER = (
        "\r\n"
        "********************************************************************************\r\n"
        "* Copyright (c) 2010-2024 Hewlett Packard Enterprise Development LP            *\r\n"
        "*                                                                              *\r\n"
        "* Without the owner's prior written consent,                                   *\r\n"
        "* no decompiling or reverse-engineering shall be allowed.                      *\r\n"
        "********************************************************************************\r\n"
        "\r\n"
        "Login authentication\r\n"
        "\r\n"
        "Password: "
    )

    def _run_telnet(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.telnet_port))
        sock.listen(5)
        logger.info("Telnet on :%d", self.telnet_port)

        while self._running:
            try:
                sock.settimeout(1.0)
                client, addr = sock.accept()
                logger.info("Telnet connection from %s", addr[0])
                threading.Thread(
                    target=self._handle_telnet, args=(client, addr), daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                logger.error("Telnet accept error: %s", e)
        sock.close()

    def _handle_telnet(self, client: socket.socket, addr):
        try:
            client.sendall(self.HP_TELNET_BANNER.encode())
            client.settimeout(30)
            password = client.recv(1024).decode(errors="ignore").strip()
            if password:
                logger.warning("Telnet credential capture from %s — password=%s", addr[0], password)
                from software.notifications import get_notifier
                notifier = get_notifier()
                if notifier:
                    notifier.notify(
                        "credential",
                        "HP Printer — Telnet Login Attempt",
                        source=addr[0],
                        password=password,
                    )
            time.sleep(1)
            client.sendall(b"\r\nLogin incorrect.\r\n")
            time.sleep(0.5)
        except Exception as e:
            logger.debug("Telnet handler error: %s", e)
        finally:
            client.close()

    # ── Lifecycle ──

    def start(self):
        self._running = True

        services = [
            ("hp-http", self._run_http),
            ("hp-pjl", self._run_pjl),
            ("hp-lpd", self._run_lpd),
            ("hp-ipp", self._run_ipp),
            ("hp-snmp", self._run_snmp),
            ("hp-telnet", self._run_telnet),
        ]

        for name, target in services:
            t = threading.Thread(target=target, daemon=True, name=name)
            self._threads.append(t)
            t.start()

        logger.info(
            "HP Printer cover active: %s (FW %s) MAC=%s IP=%s",
            PRINTER_MODEL,
            FIRMWARE_VERSION,
            self.mac_address,
            self.local_ip,
        )

    def stop(self):
        self._running = False
        logger.info("HP Printer cover services stopping")
