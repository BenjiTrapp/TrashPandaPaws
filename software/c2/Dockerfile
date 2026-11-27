# The Debian release is pinned, and that is not housekeeping. This file
# said `python:3.12-slim`, which moved from Debian 12 to Debian 13
# underneath it; `freerdp2-x11` does not exist in 13, and the build died
# at step 3 of 20 for everyone who cloned this repository. An unpinned
# base means the image's contents change without a commit here.
#
# Moving to trixie later means `freerdp3-x11`, whose binary is
# `xfreerdp3` and not `xfreerdp` -- server.py now looks up both names, so
# that move is a one-line change rather than a silently broken RDP button.

# ── Stage 1: the one wheel PyPI will not give us ──
#
# `aardwolf` is NetExec's RDP library and a hard dependency of it
# (`aardwolf>=0.2.16`, not an extra), and at 0.2.17 it publishes a macOS
# arm64 wheel, a manylinux x86_64 wheel, a Windows wheel -- and no Linux
# aarch64 one. Its own pyproject builds two PyO3 extensions through
# setuptools-rust, so on arm64 pip has to compile Rust or give up.
#
# It gave up, and that was not cosmetic: `software/agent/executor/
# server_tool.py` runs an admitted command *on the C2 host*, which is this
# container, and the agent emits `nxc smb ...`. The image built green on
# arm64 and the agent then hit "command not found".
#
# So the toolchain lives here and nothing else does. The earlier
# judgement -- that carrying cargo in the image an operator runs is the
# wrong trade -- still holds; this stage is how both can be true. The
# base is the same image as the final stage on purpose, so the wheel is
# built against the very interpreter that will import it.
#
# `--no-deps`: only aardwolf is built here. Its dependency `arc4` has no
# aarch64 wheel either, but it is a plain C extension and the final stage
# already carries gcc and python3-dev for exactly that. On x86_64 this
# stage downloads the published wheel in seconds and compiles nothing, so
# the same file is cheap on the architecture that never had the problem.
FROM python:3.12-slim-bookworm AS wheels

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev libssl-dev python3-dev \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# rustup rather than Debian's `cargo`, and that is measured too: bookworm
# ships rustc 1.63, and the PyO3 that aardwolf's crates build against
# wants newer. A stable toolchain from rustup is the version the upstream
# wheels are built with.
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable \
    && rustc --version && cargo --version

RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels aardwolf \
    && ls -1 /wheels

# ── Stage 2: what ships ──
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

# The wheelhouse from stage 1, and the variable that makes pip look in it.
# PIP_FIND_LINKS is additive: it adds a place to resolve from, it does not
# cut PyPI off, so every other dependency resolves exactly as before. The
# directory stays in the image rather than being deleted after the install
# -- it is a few megabytes, the variable would otherwise point at nothing,
# and it is the honest record of what was injected.
COPY --from=wheels /wheels /wheels
ENV PIP_FIND_LINKS=/wheels

ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
# `--python` is not tidiness, it is the difference between an image with
# NetExec and one without. pipx comes from apt, so it runs under
# `#!/usr/bin/python3`, which `python3-dev` above pulled in as Debian's
# 3.11.2 -- while this image's own interpreter is 3.12.16. Left to its
# default, pipx built the venv with 3.11, the cp312 wheel from the wheels
# stage did not match it, pip went back to the sdist and died with
# "can't find Rust compiler", and the `||` below swallowed that: a green
# build with no nxc in it, exactly the defect the stage was added to fix.
# Upstream's published wheels are cp311-abi3 and fit either, which is why
# only the architecture without a wheel ever showed this.
#
# The `||` stays, and its reason has changed. It used to mean "this
# architecture cannot have NetExec"; the wheels stage removed that. It
# now means one tool that fails to install must not cost every
# architecture its image -- a network hiccup, an upstream yank, a crate
# that stops building. What it must not do is hide the absence, so the
# shipped-image workflow asserts `nxc --version` instead of merely
# reporting it.
RUN pipx install --python /usr/local/bin/python3 \
        git+https://github.com/Pennyw0rth/NetExec \
    || echo "NetExec not installed: see the wheels stage and /wheels"

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
