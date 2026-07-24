FROM python:3.12-slim

LABEL maintainer="TrashPandaPaws" \
      description="Raccoon C2 Team Server with Impacket, NetExec, RelayKing & Responder"

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev libssl-dev \
        nmap iputils-ping net-tools \
        git pipx \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        flask \
        cryptography \
        impacket \
        lsassy \
        ldap3 \
        requests-ntlm

ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
RUN pipx install git+https://github.com/Pennyw0rth/NetExec

# Install Responder
RUN git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder \
    && chmod +x /opt/Responder/Responder.py \
    && ln -s /opt/Responder/Responder.py /usr/local/bin/responder

# Install RelayKing
RUN git clone --depth 1 https://github.com/depthsecurity/RelayKing-Depth.git /opt/RelayKing \
    && cd /opt/RelayKing && pip install --no-cache-dir -e . 2>/dev/null \
    || pip install --no-cache-dir -r /opt/RelayKing/requirements.txt \
    && ln -s /opt/RelayKing/relayking.py /usr/local/bin/relayking \
    && chmod +x /opt/RelayKing/relayking.py

WORKDIR /opt/raccoon-c2

COPY server.py .
COPY beacon.py .
COPY __init__.py .

RUN mkdir -p /data/raccoon-c2

ENV RACCOON_PORT=8443 \
    RACCOON_HOST=0.0.0.0 \
    RACCOON_DATA=/data/raccoon-c2

EXPOSE 8443

VOLUME ["/data/raccoon-c2"]

COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
