#!/usr/bin/env python3
"""An OpenAI-compatible endpoint that answers from a script.

The agent figures have to show a campaign actually running -- the stream
filling, the drawer updating, a knock arriving. The live Bedrock run this
was first validated against cannot be re-run on demand: it costs tokens,
it is non-deterministic, and one nmap phase alone takes about seven
minutes, which no GIF can carry.

So the model is scripted and everything else is real. The agent service,
its orchestrator, the safety tiers, the expected-value gate, the scope
check, the C2 and the beacon all run exactly as shipped, reached over the
`local` provider's ordinary HTTP path -- no test hooks, no mock client
injected past the seams. What is scripted is only which commands the model
asks for.

    python3 tools/scripted_model.py --port 18600 \
        --script tools/storyboards/agent_run_script.json

Then point the agent at it:

    python3 -m software.agent --provider local --model scripted \
        --base-url http://127.0.0.1:18600/v1 ...
"""

import argparse
import json
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tools.placeholders import fill

# Enough that the drawer's token counter moves visibly between turns, and
# small enough that a short campaign does not look like it burned a budget.
_TOKENS_IN = 1800
_TOKENS_OUT = 220


def calls(*pairs):
    """A reply asking for tool calls: ("name", {...}), ..."""
    return {"calls": [{"name": name, "arguments": arguments}
                      for name, arguments in pairs]}


def text(body):
    """A reply that is just prose, which is how a phase ends normally."""
    return {"text": body}


# Which conversation a request belongs to, decided by the tools it offers.
# A campaign runs two loops: the orchestrator decides what to dispatch, and
# each dispatched task runs its own executor loop. Both call this one
# endpoint, and they interleave according to how fast the beacon answers --
# so a single flat queue hands the orchestrator a reply meant for an
# executor as soon as the timing shifts by one turn.
#
# The marker tools come from the tool registry's own role split, which this
# file does not get to decide: `dispatch_task` is offered to the
# orchestrator only, `run_command` to executors only. A test pins both
# against registry.specs().
_ROLE_MARKERS = (("orchestrator", "dispatch_task"),
                 ("executor", "run_command"))

ROLES = tuple(role for role, _ in _ROLE_MARKERS)


def role_of(request):
    """The conversation a request comes from, or None if unrecognisable."""
    offered = set()
    for tool in request.get("tools") or ():
        name = (tool.get("function") or {}).get("name")
        if name:
            offered.add(name)
    for role, marker in _ROLE_MARKERS:
        if marker in offered:
            return role
    return None


class Script:
    """Replies in order per conversation, then plain text forever.

    What happens at the end decides whether a capture finishes. Raising
    would abort the run mid-frame; repeating the last tool call would
    loop to the turn limit, which is twenty turns of the same command on
    screen. Plain text is how a phase ends normally, so that is the
    fallback -- and the same answer serves a role with no script at all,
    or a request whose tools the capability tier filtered down to
    nothing.
    """

    FALLBACK = ("Nothing further to do in this phase with the access and "
                "findings available.")

    def __init__(self, by_role):
        # A bare list is one unrouted conversation: it answers every
        # request, whoever asked. A dict routes strictly, which is what a
        # real campaign needs because both loops share this endpoint.
        self._routed = not isinstance(by_role, list)
        if not self._routed:
            by_role = {ROLES[0]: by_role}
        self._queues = {role: list(replies) for role, replies in by_role.items()}
        self._at = {role: 0 for role in self._queues}
        self._lock = threading.Lock()
        self._id = 0

    @property
    def remaining(self):
        return sum(max(0, len(q) - self._at[role])
                   for role, q in self._queues.items())

    def next_reply(self, request=None):
        role = role_of(request or {})
        if not self._routed:
            role = ROLES[0]
        with self._lock:
            queue = self._queues.get(role) or []
            at = self._at.get(role, 0)
            if at < len(queue):
                entry = queue[at]
                self._at[role] = at + 1
            else:
                entry = text(self.FALLBACK)
            base = self._id
            self._id += len(entry.get("calls") or ())
        return self._wire(entry, base)

    def _wire(self, entry, base):
        wanted = entry.get("calls")
        if wanted:
            message = {
                "role": "assistant",
                "content": entry.get("text") or None,
                # A distinct id per call: the agent answers each one by
                # id, and two calls sharing one would have the second
                # result attributed to the first.
                "tool_calls": [
                    {"id": "call_%d" % (base + i), "type": "function",
                     "function": {"name": c["name"],
                                  "arguments": json.dumps(c["arguments"])}}
                    for i, c in enumerate(wanted)],
            }
            finish = "tool_calls"
        else:
            message = {"role": "assistant", "content": entry["text"]}
            finish = "stop"
        return {
            "id": "scripted",
            "object": "chat.completion",
            "model": "scripted",
            "choices": [{"index": 0, "message": message,
                         "finish_reason": finish}],
            # Reported so the drawer's token counter moves between turns:
            # a budget that never moves is one of the things the agent
            # figure exists to show.
            "usage": {"prompt_tokens": _TOKENS_IN,
                      "completion_tokens": _TOKENS_OUT,
                      "total_tokens": _TOKENS_IN + _TOKENS_OUT},
        }


def load(raw):
    """Build a Script from parsed JSON, strictly.

    `{"orchestrator": [...], "executor": [...]}`, or a bare list for a
    single executor conversation.
    """
    if not raw:
        raise ValueError("the script has no replies; the captured campaign "
                         "would do nothing at all")
    if isinstance(raw, list):
        raw = {"executor": raw}
    unknown = sorted(set(raw) - set(ROLES))
    if unknown:
        raise ValueError("unknown conversation(s) in the script: %s; "
                         "expected %s"
                         % (", ".join(unknown), " or ".join(ROLES)))
    by_role = {}
    for role, entries in raw.items():
        replies = []
        for index, entry in enumerate(entries, 1):
            if "calls" in entry:
                replies.append({"calls": [{"name": c["name"],
                                           "arguments": c.get("arguments", {})}
                                          for c in entry["calls"]],
                                "text": entry.get("text")})
            elif "text" in entry:
                replies.append(text(entry["text"]))
            else:
                raise ValueError("%s reply %d has neither 'calls' nor "
                                 "'text': %r" % (role, index, sorted(entry)))
        by_role[role] = replies
    return Script(by_role)


class _Handler(BaseHTTPRequestHandler):
    script = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        if not self.path.rstrip("/").endswith("chat/completions"):
            self.send_error(404)
            return
        try:
            request = json.loads(raw or b"{}")
        except ValueError:
            request = {}
        body = json.dumps(self.script.next_reply(request)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # One line per turn on stdout, so a capture run shows progress.
        sys.stderr.write("  scripted model: turn served, %d left\n"
                         % self.script.remaining)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=18600)
    parser.add_argument("--script", required=True)
    parser.add_argument("--set", action="append", metavar="NAME=VALUE",
                        help="fill a {{placeholder}} in the script")
    args = parser.parse_args(argv)

    values = dict(pair.split("=", 1) for pair in args.set or [])
    raw = json.loads(fill(pathlib.Path(args.script).read_text(), values))
    _Handler.script = load(raw)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print("scripted model on http://127.0.0.1:%d/v1 (%d replies)"
          % (args.port, _Handler.script.remaining))
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
