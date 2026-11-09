#!/usr/bin/env python3
"""Run the agent service: `python3 -m software.agent`.

Settings come from config.load: the flags the module defines, the `agent:`
block of raccoon.yaml, the environment. `-c/--config` names the YAML; without
it the same two places the implant looks are tried, and with neither the
defaults and the environment stand.

It starts with no model provider configured, and that is not an error: the
service is then up to say so. Only /status answers usefully, with the reason,
and POST /campaign is a 503 until the configuration is fixed and the process
restarted.
"""

import argparse
import logging
import sqlite3
import sys
from pathlib import Path

from aiohttp import web

from software.agent import c2client, config, service
from software.agent.orchestrator import CampaignManager
from software.agent.store import db

logger = logging.getLogger("agent")

# The places software/main.py looks for the same file, in the same order.
_YAML_CANDIDATES = (
    "/opt/raccoon/configs/raccoon.yaml",
    str(Path(__file__).resolve().parent.parent.parent / "configs" / "raccoon.yaml"),
)


def _yaml_path(given):
    if given:
        return given
    for candidate in _YAML_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return None


def main(argv=None) -> int:
    # Its own parser for the one flag config.load does not know; everything
    # else is handed on, so a typo in a config flag is still config's error.
    # allow_abbrev off, or `--c2-url` could be read as an abbreviation.
    pre = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    pre.add_argument("-c", "--config")
    known, rest = pre.parse_known_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s")

    try:
        cfg = config.load(rest, yaml_path=_yaml_path(known.config))
        c2 = c2client.C2Client(cfg.c2_url, cfg.c2_token or "",
                               verify_tls=cfg.c2_verify_tls)
    except (config.ConfigError, ValueError) as exc:
        logger.error("cannot start: %s", exc)
        return 2
    try:
        conn = db.open_store(cfg.db_path)
    except sqlite3.Error as exc:
        logger.error("cannot open the database %s (%s)", cfg.db_path,
                     type(exc).__name__)
        return 1

    ok, reason = cfg.available()
    if ok:
        logger.info("model: %s / %s, capability tier %s", cfg.provider,
                    cfg.model, cfg.capability_tier)
        if reason:
            # Usable, with a caveat the operator must hear now: the only
            # other place it shows is the status endpoint.
            logger.warning("%s", reason)
    else:
        logger.warning("no campaign can start: %s", reason)
    if not cfg.agent_token:
        logger.warning("no agent token is configured (RACCOON_AGENT_TOKEN): "
                       "only connections from this machine are accepted")

    app = service.make_app(cfg, conn, c2, CampaignManager())
    logger.info("listening on %s:%d", cfg.bind_host, cfg.bind_port)
    try:
        # print=None: aiohttp's own banner would say the same on stdout.
        web.run_app(app, host=cfg.bind_host, port=cfg.bind_port, print=None)
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
