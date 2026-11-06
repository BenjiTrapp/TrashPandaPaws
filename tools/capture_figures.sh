#!/usr/bin/env bash
# Build the documentation figures from a running stack, reproducibly.
#
# Everything here is real except which commands the model asks for: a real
# C2, a real beacon checked in from this host, the real agent service, the
# real safety tiers and expected-value gate. Only the model is scripted,
# over the `local` provider's ordinary HTTP path.
#
#   tools/capture_figures.sh            both figures
#   tools/capture_figures.sh tour       just the C2 tour
#   tools/capture_figures.sh agent      just the agent campaign
#   tools/capture_figures.sh stills     the same screens as PNG stills
#
# Why a script rather than a note: the order matters and two of the
# mistakes cost a capture run each.
#
#   * The beacon must be FRESH for every agent capture. A campaign restores
#     the beacon's interval when it ends -- to 300 seconds as shipped -- so
#     a second run against the same beacon waits five minutes per command
#     and looks like a hang. The demo config below shortens both the
#     campaign and the restore interval, and the beacon is restarted anyway.
#
#   * Sliver has to be off. With c2.sliver.enabled true the agent reports
#     itself unavailable, correctly: a Sliver-managed box never checks in to
#     the Raccoon server, so the agent would face an empty fleet.

set -euo pipefail

cd "$(dirname "$0")/.."

WHICH="${1:-both}"
WORK="${CAPTURE_WORK:-/tmp/raccoon-figures}"
C2_PORT="${C2_PORT:-18500}"
AGENT_PORT="${AGENT_PORT:-18099}"
MODEL_PORT="${MODEL_PORT:-18601}"
TOKEN="${C2_TOKEN:-demo-operator-token}"
WIDTH="${GIF_WIDTH:-1000}"
COLOURS="${GIF_COLOURS:-64}"

mkdir -p "$WORK"

# Substring matches, not -x: -x needs the pattern to be the whole command
# line, and every launch below carries further arguments, so -x never matched
# and a stale stack kept the ports -- a capture then measures a foreign
# process. Nor do the patterns start at "python3": a framework Python on
# macOS lists itself as .../Python.app/.../Python, so "python3 tools/..."
# is not in its command line either.
cleanup() {
  pkill -f "tools/demo_env.py --operator-port $C2_PORT " 2>/dev/null || true
  pkill -f "tools/scripted_model.py --port $MODEL_PORT " 2>/dev/null || true
  pkill -f "software.agent .*--bind-port $AGENT_PORT " 2>/dev/null || true
}
trap cleanup EXIT
cleanup
sleep 1

# The shipped config with Sliver off and both beacon intervals shortened.
# Written rather than committed: it differs from the shipped one only in
# ways that suit a figure, and a second config in the repo would be a
# second thing to keep true.
python3 - "$WORK/raccoon-demo.yaml" <<'PY'
import pathlib, re, sys
src = pathlib.Path("configs/raccoon.yaml").read_text()
lines = src.splitlines(keepends=True)
sliver = next(i for i, l in enumerate(lines) if l.strip() == "sliver:")
enabled = next(i for i in range(sliver, len(lines))
               if lines[i].strip() == "enabled: true")
lines[enabled] = lines[enabled].replace("true", "false")
out = "".join(lines)
for key, value in (("campaign_interval", 3), ("restore_interval", 3)):
    out, n = re.subn(r"(\n\s*%s:\s*)\d+" % key, r"\g<1>%d" % value, out, count=1)
    assert n == 1, key

# A fallback link, so the status panel has a chain to show. `local` needs no
# key, which is also the honest example: a model on the box itself cannot be
# rate-limited and cannot have its key revoked, which makes it the sensible
# last link. It is never reached here -- the scripted primary always answers.
out, n = re.subn(r"(\n    provider: )",
                 "\n    fallbacks:\n"
                 "      - provider: local\n"
                 "        model: qwen2.5-coder\n"
                 "        base_url: http://127.0.0.1:11434/v1\n"
                 r"\g<1>", out, count=1)
assert n == 1, "fallbacks"
pathlib.Path(sys.argv[1]).write_text(out)
print("  config: sliver off, intervals 3s -> %s" % sys.argv[1])
PY

wait_for_http() {   # url, what
  for _ in $(seq 1 60); do
    if curl -s -o /dev/null "$1"; then return 0; fi
    sleep 0.5
  done
  echo "timed out waiting for $2" >&2
  exit 1
}

start_stack() {
  rm -f "$WORK/agent.db"
  nohup python3 tools/scripted_model.py --port "$MODEL_PORT" \
      --script tools/storyboards/agent_run_script.json \
      --set BEACON_ID=raccoon-bandit > "$WORK/model.log" 2>&1 &
  sleep 1
  RACCOON_TOKEN="$TOKEN" nohup python3 -m software.agent \
      -c "$WORK/raccoon-demo.yaml" \
      --provider local --model scripted \
      --base-url "http://127.0.0.1:$MODEL_PORT/v1" \
      --c2-url "http://127.0.0.1:$C2_PORT" \
      --bind-port "$AGENT_PORT" --db-path "$WORK/agent.db" \
      --capability-tier full --approval-timeout 900 \
      > "$WORK/agent.log" 2>&1 &
  sleep 1
  AGENT_URL="http://127.0.0.1:$AGENT_PORT" nohup python3 tools/demo_env.py \
      --operator-port "$C2_PORT" --token "$TOKEN" > "$WORK/c2.log" 2>&1 &

  wait_for_http "http://127.0.0.1:$C2_PORT/api/agents" "the C2"
  for _ in $(seq 1 60); do
    BEACON=$(grep -m1 '^beacon ' "$WORK/c2.log" | awk '{print $2}' || true)
    [ -n "${BEACON:-}" ] && break
    sleep 0.5
  done
  [ -n "${BEACON:-}" ] || { echo "the beacon never registered" >&2; exit 1; }
  echo "  stack: c2 :$C2_PORT  agent :$AGENT_PORT  beacon $BEACON"
}

build() {           # name, storyboard
  local name="$1" board="$2"
  rm -rf "$WORK/$name"
  python3 tools/capture_sequence.py \
      --url "http://127.0.0.1:$C2_PORT/" \
      --storyboard "$board" --out-dir "$WORK/$name" \
      --set "BEACON_ID=$BEACON" --set "TOKEN=$TOKEN" \
      --width 1440 --height 900 --scale 2
  python3 tools/make_gif.py --manifest "$WORK/$name/frames.txt" \
      --out "docs/screenshots/$name.gif" --width "$WIDTH" --colours "$COLOURS"
}

if [ "$WHICH" = "both" ] || [ "$WHICH" = "tour" ]; then
  echo "== C2 tour =="
  start_stack
  build c2_tour tools/storyboards/c2_tour.json
  cleanup
  sleep 1
fi

if [ "$WHICH" = "stills" ]; then
  # The same storyboard without the caption bar, written under the names
  # docs/C2_DEMO.md already references. Most of the stills it had were
  # window grabs -- Chrome's tab strip, the address bar reading
  # localhost:8443 -- which is what tools/capture_gui.py exists to avoid,
  # and none of them had the Automated Attack button because they predate
  # it. One storyboard rather than two, so the two cannot drift.
  echo "== stills =="
  start_stack
  rm -rf "$WORK/stills"
  python3 tools/capture_sequence.py \
      --url "http://127.0.0.1:$C2_PORT/" \
      --storyboard tools/storyboards/c2_tour.json \
      --out-dir "$WORK/stills" --set "BEACON_ID=$BEACON" --set "TOKEN=$TOKEN" \
      --no-captions --width 1440 --height 900 --scale 2
  echo "  wrote $(ls "$WORK/stills"/*.png | wc -l | tr -d ' ') stills to $WORK/stills"
  echo "  review them, then copy the ones you want into docs/screenshots/"
fi

if [ "$WHICH" = "both" ] || [ "$WHICH" = "agent" ]; then
  echo "== agent campaign =="
  # A fresh stack even when the tour just ran: the tour leaves panels open
  # and, more to the point, a finished campaign would have put this beacon
  # back to its restore interval.
  start_stack
  build agent_run tools/storyboards/agent_run.json
fi
