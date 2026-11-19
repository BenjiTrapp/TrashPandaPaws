# The lab's team server: what `software.c2.server` imports, and nothing
# else. Measured sufficient -- the module imports with flask and
# cryptography alone, because impacket is only reached from the code paths
# that run a relay or an SMB tool.
#
# Deliberately not software/c2/Dockerfile. That image carries gcc, nmap, a
# graphical RDP client, a VNC viewer, pipx-installed NetExec and two cloned
# tools, and its build takes many minutes. The lab proves the code; the
# shipped image's packaging is what a flag on the driver selects.
#
# No source here. It arrives by read-only bind mount of the repository, so
# the lab runs the working tree.
FROM python:3.12-slim

RUN pip install --no-cache-dir flask cryptography
