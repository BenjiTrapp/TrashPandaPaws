#!/usr/bin/env bash
# Run the launcher's NetExec section on this host and report what happened.
#
# The section is cut out of `software/c2/start_server.sh` by its own
# headings rather than copied, so this cannot drift from the script it
# measures: if the headings move, the extraction fails loudly.
#
# What it reports, in order: the architecture and interpreter, whether a
# published aardwolf wheel fits, whether a Rust toolchain is present, what
# the section printed, and whether `nxc` resolves afterwards.
set -uo pipefail

LAUNCHER="${1:-software/c2/start_server.sh}"

echo "architecture:   $(uname -m)"
echo "python3:        $(python3 -V 2>&1)"
echo "pipx:           $(command -v pipx || echo absent)"
echo "cargo:          $(command -v cargo || echo absent)"

echo
echo "-- is there a published aardwolf wheel here?"
if python3 -m pip download --no-deps --only-binary :all: -q \
        -d /tmp/wheelprobe "aardwolf>=0.2.17" 2>&1 | tail -2; then
    echo "   a wheel fits"
else
    echo "   no wheel fits this interpreter and architecture"
fi

echo
echo "-- the launcher's NetExec section, run as written"
python3 - "$LAUNCHER" <<'PY' > /tmp/nxc_section.sh
import sys
text = open(sys.argv[1]).read()
start = text.index("# \u2500\u2500 NetExec")
end = text.index("\n# \u2500\u2500", start + 10)
block = text[start:end]
# The section reads two variables the script sets earlier.
print("PYTHON=$(command -v python3)")
for name, value in (("Y", "\\033[1;33m"), ("G", "\\033[1;32m"),
                    ("C", "\\033[1;36m"), ("W", "\\033[1;37m"),
                    ("D", "\\033[0;90m"), ("N", "\\033[0m"),
                    ("R", "\\033[1;31m")):
    print("%s='%s'" % (name, value))
print(block)
PY
bash /tmp/nxc_section.sh
status=$?

echo
echo "-- afterwards"
if command -v nxc >/dev/null 2>&1; then
    echo "nxc:            $(command -v nxc)"
    echo "nxc --version:  $(nxc --version 2>&1 | head -1)"
    /opt/pipx/venvs/netexec/bin/python -c "import aardwolf, arc4" \
        && echo "import aardwolf, arc4: ok" \
        || echo "import aardwolf, arc4: FAILED"
else
    echo "nxc:            absent"
fi
echo "section exit:   $status"
