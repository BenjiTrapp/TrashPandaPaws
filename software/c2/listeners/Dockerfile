# A listener container: one transport, one port, nothing else.
#
# Deliberately not the team server's image. That one carries impacket,
# NetExec, Responder, a graphical RDP client and a VNC viewer, and running
# a listener from it would put all of that one process away from the port
# that faces the network. A listener is stdlib only, and this image is
# what makes that checkable rather than aspirational: there is no
# `pip install` here, and nothing is installed with a package manager.
#
# It also does not carry `server.py` or `beacon.py`. The listener package
# must not import the team server -- that would pull in flask, werkzeug,
# cryptography, jinja2 and click -- and the simplest way to keep that true
# is for the file not to be in the image.
#
# Build from the repository root:
#   docker build -f software/c2/listeners/Dockerfile .
FROM python:3.12-slim

WORKDIR /app

# Just the package and the two empty __init__ files above it.
COPY software/__init__.py ./software/
COPY software/c2/__init__.py ./software/c2/
COPY software/c2/listeners/ ./software/c2/listeners/

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

# nobody. A listener never binds a privileged port: in Docker the port
# mapping belongs to dockerd, and under systemd the descriptor comes from
# a .socket unit. So there is nothing here that needs privilege, and
# nothing here gets it.
USER 65534:65534

ENTRYPOINT ["python3", "-m", "software.c2.listeners"]
