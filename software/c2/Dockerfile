# The Debian release is pinned, and that is not housekeeping. This file
# said `python:3.12-slim`, which moved from Debian 12 to Debian 13
# underneath it; `freerdp2-x11` does not exist in 13, and the build died
# at step 3 of 20 for everyone who cloned this repository. An unpinned
# base means the image's contents change without a commit here.
#
# Moving to trixie later means `freerdp3-x11`, whose binary is
# `xfreerdp3` and not `xfreerdp` -- server.py now looks up both names, so
# that move is a one-line change rather than a silently broken RDP button.
FROM python:3.12-slim-bookworm

LABEL maintainer="TrashPandaPaws" \
      description="Raccoon C2 Team Server with Impacket, NetExec, RelayKing & Responder"

# python3-dev is here for the architectures PyPI has no wheel for. `arc4`,
# a NetExec dependency, publishes manylinux x86_64 wheels and no Linux
# aarch64 one, so pip compiles it from source on arm64 and needs Python.h.
# Without this the build succeeded on amd64 and failed on arm64, which is
# why it went unnoticed.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev libssl-dev python3-dev \
        nmap iputils-ping net-tools \
        git pipx \
        freerdp2-x11 \
        tigervnc-viewer \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        flask \
        cryptography \
        impacket \
        lsassy \
        ldap3 \
        requests-ntlm

ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
# NetExec is allowed to fail, and the `||` is the whole point. Its RDP
# library `aardwolf` has no Linux aarch64 wheel and wants a Rust
# toolchain; carrying cargo and compiling crates in a slim image for one
# optional tool is the wrong trade. So on an architecture PyPI serves, the
# tool is there; on one it does not, the image still builds and the
# entrypoint reports NetExec as missing instead of claiming it.
RUN pipx install git+https://github.com/Pennyw0rth/NetExec \
    || echo "NetExec not installed: no wheel for this architecture and no Rust toolchain in this image"

# Install Responder
#
# `ln -sf`, not `ln -s`. A plain link fails with "File exists" the moment
# pip installs its own console script at the same path, which means the
# step could only succeed when pip had FAILED.
RUN git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder \
    && chmod +x /opt/Responder/Responder.py \
    && ln -sf /opt/Responder/Responder.py /usr/local/bin/responder

# Install RelayKing
#
# This is where that bit us: `pip install -e .` started succeeding and
# installing a `relayking` entry point, so the following `ln -s` died on
# "File exists" and broke the build on every architecture. The
# `2>/dev/null` on the pip call hid which of the two branches had run.
RUN git clone --depth 1 https://github.com/depthsecurity/RelayKing-Depth.git /opt/RelayKing \
    && cd /opt/RelayKing && pip install --no-cache-dir -e . 2>/dev/null \
    || pip install --no-cache-dir -r /opt/RelayKing/requirements.txt \
    && ln -sf /opt/RelayKing/relayking.py /usr/local/bin/relayking \
    && chmod +x /opt/RelayKing/relayking.py

WORKDIR /opt/raccoon-c2

# The whole package, not three flat files.
#
# This used to be `COPY server.py .` and two siblings, while server.py
# imports `software.c2.listeners` and `software.c2.stagers`. The image
# built and then died at start-up with "No module named 'software'" -- so
# the shipped team server could not run at all, on any architecture. The
# build context is the repository root (see docker-compose.yml), which is
# what the listener image already used.
COPY software/__init__.py ./software/
COPY software/c2/ ./software/c2/
ENV PYTHONPATH=/opt/raccoon-c2

RUN mkdir -p /data/raccoon-c2

ENV RACCOON_PORT=8443 \
    RACCOON_HOST=0.0.0.0 \
    RACCOON_OPERATOR_PORT=8444 \
    RACCOON_OPERATOR_HOST=127.0.0.1 \
    RACCOON_DATA=/data/raccoon-c2

EXPOSE 8443

VOLUME ["/data/raccoon-c2"]

COPY software/c2/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
