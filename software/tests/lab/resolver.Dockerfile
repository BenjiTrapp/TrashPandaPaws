# The lab's recursive resolver: dnsmasq and nothing else. No project source
# and no Python -- it is a real resolver in the path, which is the point.
# The configuration is mounted at run time (docker-compose.yml), so editing
# it needs no rebuild.
FROM debian:stable-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends dnsmasq \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/dnsmasq

# Foreground, so the container lives as long as the resolver does and
# compose can tell when it died. dnsmasq starts as root to bind 53 and open
# the log file, then drops to its own user.
ENTRYPOINT ["dnsmasq", "--keep-in-foreground", "--conf-file=/etc/lab/dnsmasq.conf"]
