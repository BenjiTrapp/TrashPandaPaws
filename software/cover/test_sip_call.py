#!/usr/bin/env python3
"""
SIP Test Call — places a full call to the Cisco Phone cover identity.
Performs INVITE → 100/180/200 → ACK → RTP audio (sine tone) → BYE.

Usage:
    python3 test_sip_call.py [target_ip] [target_port] [duration_seconds]

Defaults: 127.0.0.1:5060, 5 seconds of audio
"""

import socket
import struct
import sys
import time
import math
import random
import threading

TARGET_IP = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5060
DURATION = int(sys.argv[3]) if len(sys.argv) > 3 else 5

LOCAL_IP = "127.0.0.1"
LOCAL_RTP_PORT = 30000 + random.randint(0, 999)
CALL_ID = f"testcall-{random.randint(100000,999999)}@{LOCAL_IP}"
FROM_TAG = f"tag{random.randint(10000,99999)}"
BRANCH = f"z9hG4bK-{random.randint(100000,999999)}"


def log(msg):
    print(f"  [{time.strftime('%H:%M:%S')}] {msg}")


def build_invite():
    sdp = (
        f"v=0\r\n"
        f"o=tester {random.randint(1000,9999)} {random.randint(1000,9999)} IN IP4 {LOCAL_IP}\r\n"
        f"s=Test Call\r\n"
        f"c=IN IP4 {LOCAL_IP}\r\n"
        f"t=0 0\r\n"
        f"m=audio {LOCAL_RTP_PORT} RTP/AVP 0\r\n"
        f"a=rtpmap:0 PCMU/8000\r\n"
        f"a=ptime:20\r\n"
    )
    msg = (
        f"INVITE sip:phone@{TARGET_IP}:{TARGET_PORT} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {LOCAL_IP}:5060;branch={BRANCH}\r\n"
        f"From: <sip:tester@{LOCAL_IP}>;tag={FROM_TAG}\r\n"
        f"To: <sip:phone@{TARGET_IP}>\r\n"
        f"Call-ID: {CALL_ID}\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Contact: <sip:tester@{LOCAL_IP}:5060>\r\n"
        f"Content-Type: application/sdp\r\n"
        f"Content-Length: {len(sdp)}\r\n"
        f"Max-Forwards: 70\r\n"
        f"User-Agent: SIP-TestClient/1.0\r\n"
        f"\r\n"
        f"{sdp}"
    )
    return msg


def build_ack():
    return (
        f"ACK sip:phone@{TARGET_IP}:{TARGET_PORT} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {LOCAL_IP}:5060;branch={BRANCH}\r\n"
        f"From: <sip:tester@{LOCAL_IP}>;tag={FROM_TAG}\r\n"
        f"To: <sip:phone@{TARGET_IP}>\r\n"
        f"Call-ID: {CALL_ID}\r\n"
        f"CSeq: 1 ACK\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )


def build_bye():
    return (
        f"BYE sip:phone@{TARGET_IP}:{TARGET_PORT} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {LOCAL_IP}:5060;branch=z9hG4bK-{random.randint(100000,999999)}\r\n"
        f"From: <sip:tester@{LOCAL_IP}>;tag={FROM_TAG}\r\n"
        f"To: <sip:phone@{TARGET_IP}>\r\n"
        f"Call-ID: {CALL_ID}\r\n"
        f"CSeq: 2 BYE\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )


def linear_to_ulaw(sample):
    """Convert 16-bit linear PCM sample to G.711 mu-law."""
    BIAS = 0x84
    MAX = 0x7FFF
    sign = 0
    if sample < 0:
        sign = 0x80
        sample = -sample
    if sample > MAX:
        sample = MAX
    sample += BIAS
    exponent = 7
    for exp_mask in [0x4000, 0x2000, 0x1000, 0x0800, 0x0400, 0x0200, 0x0100]:
        if sample & exp_mask:
            break
        exponent -= 1
    mantissa = (sample >> (exponent + 3)) & 0x0F
    ulaw_byte = ~(sign | (exponent << 4) | mantissa) & 0xFF
    return ulaw_byte


def generate_ulaw_tone(freq=440, sample_rate=8000, duration_ms=20):
    """Generate mu-law encoded sine tone for one RTP packet (20ms)."""
    num_samples = int(sample_rate * duration_ms / 1000)
    samples = []
    for i in range(num_samples):
        t = i / sample_rate
        pcm = int(16000 * math.sin(2 * math.pi * freq * t))
        samples.append(linear_to_ulaw(pcm))
    return bytes(samples)


def send_rtp(rtp_sock, remote_ip, remote_port, duration_sec):
    """Send RTP packets with a 440Hz sine tone."""
    seq = random.randint(0, 65535)
    ts = random.randint(0, 2**31)
    ssrc = random.randint(0, 2**32 - 1)
    packets_sent = 0
    packets_received = 0

    rtp_sock.settimeout(0.005)

    start = time.time()
    log(f"RTP streaming 440Hz tone to {remote_ip}:{remote_port} for {duration_sec}s...")

    while time.time() - start < duration_sec:
        payload = generate_ulaw_tone(freq=440)

        # RTP header: V=2, P=0, X=0, CC=0, M=0, PT=0 (PCMU)
        header = struct.pack("!BBHII",
            0x80,       # V=2, P=0, X=0, CC=0
            0x00,       # M=0, PT=0 (PCMU)
            seq & 0xFFFF,
            ts & 0xFFFFFFFF,
            ssrc & 0xFFFFFFFF,
        )

        rtp_sock.sendto(header + payload, (remote_ip, remote_port))
        packets_sent += 1
        seq += 1
        ts += 160  # 20ms at 8kHz

        # Check for echo packets
        try:
            while True:
                data, addr = rtp_sock.recvfrom(2048)
                packets_received += 1
        except socket.timeout:
            pass

        time.sleep(0.02)  # 20ms pacing

    log(f"RTP done: sent={packets_sent} received={packets_received} "
        f"duration={time.time()-start:.1f}s")
    return packets_sent, packets_received


def parse_sdp_port(response):
    """Extract RTP port from SDP m=audio line."""
    for line in response.split("\r\n"):
        if line.startswith("m=audio"):
            parts = line.split()
            if len(parts) > 1:
                return int(parts[1])
    return None


def main():
    print(f"\n{'='*60}")
    print(f"  SIP Test Call")
    print(f"  Target: {TARGET_IP}:{TARGET_PORT}")
    print(f"  Duration: {DURATION}s")
    print(f"  Local RTP: {LOCAL_RTP_PORT}")
    print(f"  Call-ID: {CALL_ID}")
    print(f"{'='*60}\n")

    sip_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sip_sock.settimeout(5.0)

    # Step 1: Send INVITE
    log("Sending INVITE...")
    sip_sock.sendto(build_invite().encode(), (TARGET_IP, TARGET_PORT))

    # Step 2: Collect responses (100 Trying, 180 Ringing, 200 OK)
    responses = []
    remote_rtp_port = None
    try:
        while True:
            data, addr = sip_sock.recvfrom(4096)
            resp = data.decode()
            first_line = resp.split("\r\n")[0]
            responses.append(resp)

            if "100 Trying" in first_line:
                log("Received: 100 Trying")
            elif "180 Ringing" in first_line:
                log("Received: 180 Ringing")
            elif "200 OK" in first_line:
                log("Received: 200 OK")
                remote_rtp_port = parse_sdp_port(resp)
                if remote_rtp_port:
                    log(f"Remote RTP port from SDP: {remote_rtp_port}")
                break
            elif "4" in first_line[:10] or "5" in first_line[:10]:
                log(f"ERROR: {first_line}")
                sip_sock.close()
                return
    except socket.timeout:
        log("ERROR: Timeout waiting for responses")
        sip_sock.close()
        return

    if not remote_rtp_port:
        log("ERROR: No RTP port in SDP response")
        sip_sock.close()
        return

    # Step 3: Send ACK
    log("Sending ACK...")
    sip_sock.sendto(build_ack().encode(), (TARGET_IP, TARGET_PORT))
    time.sleep(0.1)

    # Step 4: RTP audio session
    rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rtp_sock.bind((LOCAL_IP, LOCAL_RTP_PORT))

    sent, received = send_rtp(rtp_sock, TARGET_IP, remote_rtp_port, DURATION)
    rtp_sock.close()

    # Step 5: Send BYE
    log("Sending BYE...")
    sip_sock.sendto(build_bye().encode(), (TARGET_IP, TARGET_PORT))

    try:
        data, addr = sip_sock.recvfrom(4096)
        resp = data.decode()
        first_line = resp.split("\r\n")[0]
        if "200 OK" in first_line:
            log("Received: 200 OK (call terminated)")
        else:
            log(f"Received: {first_line}")
    except socket.timeout:
        log("WARNING: No response to BYE (timeout)")

    sip_sock.close()

    # Summary
    print(f"\n{'='*60}")
    print(f"  Call Complete")
    print(f"  SIP Flow: INVITE -> 100 -> 180 -> 200 -> ACK -> BYE -> 200")
    print(f"  RTP: {sent} packets sent, {received} echoed back")
    echo_pct = (received / sent * 100) if sent > 0 else 0
    print(f"  Echo rate: {echo_pct:.1f}%")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
