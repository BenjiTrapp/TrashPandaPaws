# The agent service: its own image, deliberately slim.
#
# Build context is the **repository root**, not this directory:
#
#     docker build -f software/agent/Dockerfile .
#
# The C2's image uses software/c2/ as its context, which cannot see
# software/agent/. Copying this file's pattern with the wrong context is the
# mistake to avoid, and it fails with "COPY software/agent: not found"
# rather than anything that points at the cause. docker-compose.yml sets
# `context: ../..` for the same reason.
#
# What is not in here matters as much as what is. The offensive arsenal --
# impacket, NetExec, Responder, nmap -- stays in the C2's image. The agent
# reaches it through /api/server/exec, so a second copy would be weight, a
# second thing to keep patched, and a second place where a version drifts.
# Design section 18.
FROM python:3.12-slim

LABEL maintainer="TrashPandaPaws" \
      description="Raccoon autonomous agent service (sidecar to the C2)"

WORKDIR /opt/raccoon-agent

# Requirements first, so a code change does not re-resolve the dependencies.
# This is the agent's own list, not the C2's: the C2's set must not grow an
# LLM dependency, which is goal 7 of the design.
COPY software/agent/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# `software` has to stay a package, so the parent __init__ comes along; the
# agent imports software.agent.*, not bare modules.
COPY software/__init__.py ./software/__init__.py
COPY software/agent ./software/agent

# Owned by the unprivileged user that runs the service. It holds an API key
# and the C2 token in its environment, and it runs commands on a C2 for a
# living -- there is no reason for it to be root as well.
RUN useradd --create-home --shell /usr/sbin/nologin raccoon \
    && mkdir -p /data/raccoon-agent \
    && chown -R raccoon:raccoon /data/raccoon-agent /opt/raccoon-agent

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AGENT_BIND_HOST=127.0.0.1 \
    AGENT_BIND_PORT=8099 \
    AGENT_DB_PATH=/data/raccoon-agent/agent.db

# No EXPOSE and no published port. The service binds loopback and the C2
# reaches it on the same host; publishing an API that runs commands would
# undo the reason it binds loopback in the first place.

VOLUME ["/data/raccoon-agent"]

USER raccoon

ENTRYPOINT ["python", "-m", "software.agent"]
