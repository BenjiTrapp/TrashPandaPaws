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
# (`aardwolf>=0.2.17`, not an extra), and at 0.2.17 it publishes a macOS
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
# built against the very interpreter that will import it, and a test
# fails if the two FROM lines ever drift apart.
#
# Both versions are pinned. `docs/AGENT.md` carries "nothing is pinned"
# as an open finding, and a stage that fetched a toolchain of the day
# would have made it worse; a fixed toolchain also means the wheel this
# produces is reproducible rather than whatever stable was on build day.
FROM python:3.12-slim-bookworm AS wheels

ENV AARDWOLF_VERSION=0.2.17 RUST_VERSION=1.100.0
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev libssl-dev python3-dev \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The architecture decides, not a build argument. `ARG TARGETARCH` would
# read empty under the classic builder -- which is what this project's
# own development machine has, where `docker compose` does not exist at
# all -- and the arm64 path would then be skipped on the one machine that
# needs it. Asking pip first costs nothing and answers the same question:
# if a published wheel fits, there is nothing to compile.
#
# Nothing here may fail the image. The first version of this stage had no
# tolerance at all, so a `sh.rustup.rs` outage or a crate that stopped
# building would have cost *every* architecture its image -- the inverse
# of what the `||` on the NetExec install below exists to guarantee. Now
# the worst case is an empty wheelhouse, the install below falls back to
# PyPI, and CI is what says the tool is missing.
#
# rustup rather than Debian's `cargo`: bookworm ships rustc 1.63 and
# aardwolf's crates build against pyo3 0.27, whose MSRV is far above it.
RUN if pip wheel --no-cache-dir --no-deps --wheel-dir /wheels \
            "aardwolf==${AARDWOLF_VERSION}"; then \
        echo "aardwolf: a published wheel fits $(uname -m), nothing compiled"; \
    elif curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
              | sh -s -- -y --profile minimal \
                  --default-toolchain "${RUST_VERSION}" \
            && pip wheel --no-cache-dir --no-deps --wheel-dir /wheels \
                  "aardwolf==${AARDWOLF_VERSION}"; then \
        echo "aardwolf: built from source with $(rustc --version)"; \
    else \
        echo "WARNING: no aardwolf wheel for $(uname -m) and none could be"; \
        echo "WARNING: built -- nxc will be ABSENT from the shipped image"; \
    fi; \
    ls -1 /wheels 2>/dev/null || true

# ── Stage 2: what ships ──
FROM python:3.12-slim-bookworm

LABEL maintainer="TrashPandaPaws" \
      description="Raccoon C2 Team Server with Impacket, NetExec, RelayKing & Responder"

# gcc and the -dev packages are here for the architectures PyPI has no
# wheel for: `arc4`, a NetExec dependency, publishes manylinux x86_64
# wheels and no Linux aarch64 one, so pip compiles it from source there.
# Measured in the built arm64 image, the artefact is
# `arc4.cpython-312-aarch64-linux-gnu.so` -- compiled against this base
# image's own headers under /usr/local/include/python3.12, not against
# Debian's, which `python3-dev` installs for its own 3.11 interpreter.
# The package is left in place because nothing here has measured a build
# without it, but the reason to keep it is gcc's company, not Python.h.
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
# cut PyPI off, so every other dependency resolves exactly as before, and
# a newer release on PyPI still wins on version. It applies to the pip
# calls further down and to anything an operator runs after `docker exec`
# too, which is harmless -- one wheel, the same version PyPI publishes,
# and a tag-incompatible wheel is ignored rather than preferred.
#
# The directory stays in the image rather than being deleted after the
# install: it is 2.2 MB, the variable would otherwise point at nothing,
# and it is the honest record of what was injected. Nothing but this
# directory crosses the stage boundary -- a test pins that, because a
# `COPY --from=wheels /usr/local/ /usr/local/` would ship the toolchain
# while naming none of it.
COPY --from=wheels /wheels /wheels
ENV PIP_FIND_LINKS=/wheels

ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
# pipx runs its own pip, which never saw `--no-cache-dir`, so the shipped
# image carried 60 MB of wheel cache for packages it will never install
# again. Measured; the variable is the only way to reach that pip.
ENV PIP_NO_CACHE_DIR=1
# `--python` is not tidiness, it is the difference between an image with
# NetExec and one without. pipx comes from apt, so it runs under
# `#!/usr/bin/python3`, which on this base is Debian's 3.11.2 -- while the
# image's own interpreter is 3.12.16. (Both `python3-dev` above and pipx
# itself, through `python3-venv`, pull that interpreter in; removing
# either would not remove it.) Left to its default, pipx built the venv
# with 3.11, the cp312 wheel from the wheels stage did not match it, pip
# went back to the sdist and died with "can't find Rust compiler", and the
# `||` below swallowed that: a green build with no nxc in it, exactly the
# defect the stage was added to fix. Upstream's published wheels are
# cp311-abi3 and fit either, which is why only the architecture without a
# wheel ever showed this.
#
# The `||` stays, and its reason has changed. It used to mean "this
# architecture cannot have NetExec"; the wheels stage removed that. It
# now means one tool that fails to install must not cost every
# architecture its image -- a network hiccup, an upstream yank, a crate
# that stops building. What it must not do is hide the absence, so the
# shipped-image workflow asserts the tool and its RDP library, on both
# architectures.
RUN pipx install --python /usr/local/bin/python3 \
        git+https://github.com/Pennyw0rth/NetExec \
    || echo "WARNING: nxc is NOT in this image -- the NetExec install failed"

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
