# Measures the launcher's NetExec path on a native aarch64 Debian host.
#
# Not part of the shipped artefacts and not built by CI: it exists so that
# "nxc on aarch64 from start_server.sh" is a measurement rather than a
# reading of the script. Build and run it on an arm64 machine:
#
#   docker build --platform linux/arm64 -f tools/nxc_probe.Dockerfile -t tpp-nxc-probe .
#   docker run --rm --platform linux/arm64 tpp-nxc-probe
#
# The image deliberately has **no Rust toolchain**, which is the state of
# the operator host this project cares about: the shipped team-server image
# builds aardwolf's wheel in a stage it throws away, and the launcher is
# not allowed to install a toolchain on somebody's machine.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip pipx git ca-certificates \
        bash coreutils \
    && rm -rf /var/lib/apt/lists/*

# `--build-arg RUST=1` adds the toolchain, which is the other half of the
# measurement: without it the launcher must refuse legibly, with it the
# install must succeed. The version is the one software/c2/Dockerfile pins,
# because bookworm's own rustc 1.63 is far below pyo3 0.27's MSRV.
ARG RUST=""
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
RUN if [ -n "$RUST" ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
            curl gcc libffi-dev libssl-dev python3-dev \
        && rm -rf /var/lib/apt/lists/* \
        && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
             | sh -s -- -y --profile minimal --default-toolchain 1.100.0 \
        && rustc --version; \
    fi

ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
WORKDIR /opt/raccoon
COPY software/c2/start_server.sh software/c2/start_server.sh
COPY tools/nxc_probe.sh tools/nxc_probe.sh
RUN chmod +x tools/nxc_probe.sh

ENTRYPOINT ["bash", "tools/nxc_probe.sh"]
