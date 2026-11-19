#!/bin/sh
# A stand-in for `gs-netcat`, so that every carrier test runs offline.
#
# The anti-goal is a test suite that needs the Global Socket Relay
# Network: that would send traffic to a third-party relay from whatever
# machine runs the suite, which is the one thing this feature's
# constraints say carries OPSEC meaning. So this script does the three
# things the carrier can observe about a real `gs-netcat` and nothing
# else:
#
#   * in the **server** shape (`-l -d <host> -p <port>`) it stays up
#     until it is killed and **binds nothing**, because that `-p` is a
#     destination port on this machine rather than a port to listen on.
#     See the note above `GsocketCarrier.argv` in
#     `software/c2/gsocket/carrier.py`, which is the model this has to
#     agree with. It matters beyond tidiness: the realistic deployment
#     is several carriers all pointed at one beacon socket,
#     `127.0.0.1:8443`, so a stand-in that bound `-p` would have them
#     fight over that port and the loser's non-zero exit would read as a
#     supervisor thrashing for reasons of its own;
#   * in the **client** shape (`-w -p <port>`, the implant's side) it
#     binds that loopback port and stays up, because there `-p` really
#     is a local forward;
#   * with `-t`, it exits immediately with $FAKE_GS_NETCAT_PROBE_EXIT
#     (default 0), which is how the probe's answers are staged.
#
# Either long-lived shape gives `is_running()` and `stop()` a live
# process to be right or wrong about.
#
# It records its argv and its environment when asked, because the two
# properties the carrier must hold -- the secret never on a command
# line, no encryption key anywhere near the child -- are properties of
# the *spawn*, and a test that only inspected the argv builder would
# pass against a `start` that assembled its own command.
#
# Env hooks, all optional:
#   FAKE_GS_NETCAT_ARGV_FILE   one argument per line, argv[0] excluded
#   FAKE_GS_NETCAT_ENV_FILE    the output of `env`
#   FAKE_GS_NETCAT_PID_FILE    this process's pid, written before the
#                              `exec` below and therefore still correct
#                              afterwards -- an `exec` keeps the pid. It
#                              is how a test can assert that a killed
#                              stand-in is really gone rather than
#                              reparented and still holding a port.
#   FAKE_GS_NETCAT_PROBE_EXIT  exit status for `-t` (default 0)
#   FAKE_GS_NETCAT_PROBE_HANG  non-empty: `-t` never answers, so the
#                              probe's timeout has something to expire on
set -u

if [ -n "${FAKE_GS_NETCAT_ARGV_FILE:-}" ]; then
    : > "$FAKE_GS_NETCAT_ARGV_FILE"
    for argument in "$@"; do
        printf '%s\n' "$argument" >> "$FAKE_GS_NETCAT_ARGV_FILE"
    done
fi

if [ -n "${FAKE_GS_NETCAT_ENV_FILE:-}" ]; then
    env > "$FAKE_GS_NETCAT_ENV_FILE"
fi

if [ -n "${FAKE_GS_NETCAT_PID_FILE:-}" ]; then
    printf '%s\n' "$$" > "$FAKE_GS_NETCAT_PID_FILE"
fi

port=""
probe=""
server=""
while [ $# -gt 0 ]; do
    case "$1" in
        -p)
            port="${2:-}"
            shift 2 || shift
            ;;
        -k|-d)
            shift 2 || shift
            ;;
        -t)
            probe="yes"
            shift
            ;;
        -l)
            # The server shape. What follows from it is *not* binding
            # `-p`; see the header.
            server="yes"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

if [ -n "$probe" ]; then
    if [ -n "${FAKE_GS_NETCAT_PROBE_HANG:-}" ]; then
        # `exec`, so the process the carrier holds is the one doing the
        # waiting. A shell left in the middle would turn the probe's
        # kill into an orphaned grandchild, and an orphan that holds a
        # port is how a later test fails for reasons of its own.
        exec python3 -c 'import time
while True:
    time.sleep(3600)'
    fi
    exit "${FAKE_GS_NETCAT_PROBE_EXIT:-0}"
fi

# Required in both long-lived shapes, because both argv the carrier
# builds carry it: an argv without `-p` is a bug in the carrier and
# should fail loudly rather than produce a process that looks healthy.
if [ -z "$port" ]; then
    echo "fake_gs_netcat.sh: no -p <port> in: $*" >&2
    exit 64
fi

if [ -n "$server" ]; then
    # The server shape: stay up, bind nothing. A real `gs-netcat -l`
    # listens on the relay network, which this stand-in cannot and must
    # not do, and connects what arrives to `-d`/`-p` -- so the only
    # locally observable thing it does is exist. `exec` for the same
    # reason as above: one process, and the pid recorded above stays
    # correct.
    exec python3 -c 'import time
while True:
    time.sleep(3600)'
fi

# The client shape: `-p` is the implant's local forward, so bind it.
# Bind before going quiet, and let the failure out on stderr: a
# stand-in that silently did not listen would make a test asserting the
# forward is up pass for the wrong reason.
exec python3 -c 'import socket, sys, time
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", int(sys.argv[1])))
listener.listen(8)
while True:
    time.sleep(3600)' "$port"
