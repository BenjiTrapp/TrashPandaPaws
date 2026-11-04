"""The scripted model server the agent figures are captured against.

The agent GIF has to show a campaign actually running: the stream filling,
the drawer updating, a knock arriving. The live Bedrock run that this was
first validated against is not reproducible on demand -- it costs tokens,
it is non-deterministic, and one nmap phase alone takes about seven
minutes, which no GIF can carry.

So the model is scripted and everything else is real. The agent service,
its orchestrator, the safety tiers, the expected-value gate, the scope
check, the C2 and the beacon all run as shipped, over the `local`
provider's ordinary HTTP path. What is scripted is only *which commands
the model asks for*.

These tests cover the server's half of that contract: the shape the
OpenAI-compatible client parses, and what happens when the script runs
out -- which decides whether a captured campaign ends or hangs.
"""

import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from software.agent.llm import provider
from tools import scripted_model


class TestTheReplyIsWhatTheClientParses(unittest.TestCase):
    """The shape is a contract with software/agent/llm/openai_client.py.

    Asserted by handing the reply to the real client's own parser rather
    than by comparing dictionaries: a hand-written expectation would
    drift from the parser the moment either side changed, and the figures
    would fail at capture time with an unhelpful error.
    """

    def _parse(self, reply):
        client = provider_client()
        return client._parse_response(reply)

    def test_a_tool_call_arrives_with_its_name_and_arguments(self):
        server = scripted_model.Script([
            scripted_model.calls(("run_command",
                                  {"command": "uname -a",
                                   "beacon_id": "raccoon-bandit"})),
        ])
        completion = self._parse(server.next_reply())
        self.assertEqual(len(completion.tool_calls), 1)
        call = completion.tool_calls[0]
        self.assertEqual(call.name, "run_command")
        self.assertEqual(call.arguments["command"], "uname -a")
        self.assertIsNone(call.error)

    def test_several_calls_in_one_reply_keep_their_order(self):
        server = scripted_model.Script([
            scripted_model.calls(("run_command", {"command": "id"}),
                                 ("run_command", {"command": "pwd"})),
        ])
        completion = self._parse(server.next_reply())
        self.assertEqual([c.arguments["command"] for c in completion.tool_calls],
                         ["id", "pwd"])

    def test_a_text_reply_arrives_as_text(self):
        server = scripted_model.Script([scripted_model.text("phase complete")])
        completion = self._parse(server.next_reply())
        self.assertEqual(completion.text, "phase complete")
        self.assertEqual(completion.tool_calls, [])

    def test_every_call_has_a_distinct_id(self):
        # The agent answers each call by id; two calls sharing one would
        # have the second result attributed to the first.
        server = scripted_model.Script([
            scripted_model.calls(("run_command", {"command": "a"}),
                                 ("run_command", {"command": "b"})),
        ])
        completion = self._parse(server.next_reply())
        ids = [c.id for c in completion.tool_calls]
        self.assertEqual(len(set(ids)), 2)

    def test_usage_is_reported_so_the_budget_moves(self):
        # The drawer shows tokens spent. A server reporting none would
        # leave the figure showing a budget that never moves, which is
        # exactly the thing the agent GIF is meant to demonstrate.
        server = scripted_model.Script([scripted_model.text("done")])
        completion = self._parse(server.next_reply())
        self.assertGreater(completion.total_tokens, 0)


class TestRunningOutOfScriptEndsTheCampaign(unittest.TestCase):
    """What happens at the end decides whether a capture finishes.

    A server that errors once the script is exhausted would abort the run
    mid-frame; one that repeats its last tool call would loop until the
    turn limit, which is twenty turns of the same command on screen.
    Neither is capturable, so it answers with plain text, which is how a
    phase ends normally.
    """

    def test_after_the_script_it_answers_with_text(self):
        server = scripted_model.Script([scripted_model.text("one")])
        server.next_reply()
        reply = server.next_reply()
        choice = reply["choices"][0]
        self.assertEqual(choice["finish_reason"], "stop")
        self.assertFalse(choice["message"].get("tool_calls"))
        self.assertTrue(choice["message"]["content"])

    def test_it_keeps_answering_rather_than_raising(self):
        server = scripted_model.Script([scripted_model.text("one")])
        for _ in range(25):
            self.assertIn("choices", server.next_reply())

    def test_the_script_is_served_in_order(self):
        server = scripted_model.Script([
            scripted_model.calls(("run_command", {"command": "first"})),
            scripted_model.calls(("run_command", {"command": "second"})),
        ])
        seen = []
        for _ in range(2):
            reply = server.next_reply()
            args = reply["choices"][0]["message"]["tool_calls"][0]["function"]
            seen.append(json.loads(args["arguments"])["command"])
        self.assertEqual(seen, ["first", "second"])

    def test_how_many_replies_are_left_is_readable(self):
        server = scripted_model.Script([scripted_model.text("a"),
                                        scripted_model.text("b")])
        self.assertEqual(server.remaining, 2)
        server.next_reply()
        self.assertEqual(server.remaining, 1)


class TestTheScriptIsLoadedFromAFile(unittest.TestCase):
    """The storyboard and the script live next to each other, as data."""

    def test_a_json_script_becomes_replies(self):
        raw = {"executor": [{"calls": [{"name": "run_command",
                                        "arguments": {"command": "uname -a"}}]},
                            {"text": "done"}]}
        script = scripted_model.load(raw)
        self.assertEqual(script.remaining, 2)

    def test_an_entry_that_is_neither_is_refused(self):
        with self.assertRaises(ValueError):
            scripted_model.load({"executor": [{"nonsense": 1}]})

    def test_an_empty_script_is_refused(self):
        # It would capture a campaign that does nothing at all.
        with self.assertRaises(ValueError):
            scripted_model.load({})

    def test_an_unknown_role_is_refused_by_name(self):
        with self.assertRaises(ValueError) as caught:
            scripted_model.load({"exectuor": [{"text": "x"}]})
        self.assertIn("exectuor", str(caught.exception))


class TestEachConversationGetsItsOwnScript(unittest.TestCase):
    """A campaign runs two loops, and they interleave unpredictably.

    The orchestrator decides what to dispatch; each dispatched task runs
    its own executor loop. Both call the same endpoint, so a single flat
    queue hands the orchestrator a reply meant for an executor the moment
    the interleaving shifts by one -- and the interleaving depends on how
    fast the beacon answers.

    They are told apart by the tools the request offers: `dispatch_task`
    exists only for the orchestrator and `run_command` only for an
    executor, which the tool registry decides, not this file.
    """

    def _request(self, *tool_names):
        return {"tools": [{"type": "function", "function": {"name": n}}
                          for n in tool_names]}

    def test_the_orchestrator_is_recognised_by_its_dispatch_tool(self):
        self.assertEqual(
            scripted_model.role_of(self._request("dispatch_task", "set_phase")),
            "orchestrator")

    def test_an_executor_is_recognised_by_run_command(self):
        self.assertEqual(
            scripted_model.role_of(self._request("run_command", "lookup_cve")),
            "executor")

    def test_each_role_is_served_from_its_own_queue(self):
        script = scripted_model.load({
            "orchestrator": [{"calls": [{"name": "dispatch_task",
                                         "arguments": {"name": "recon"}}]}],
            "executor": [{"calls": [{"name": "run_command",
                                     "arguments": {"command": "id"}}]}],
        })
        # Executor first, out of script order: the queues are independent.
        ex = script.next_reply(self._request("run_command"))
        orch = script.next_reply(self._request("dispatch_task"))
        self.assertEqual(
            ex["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
            "run_command")
        self.assertEqual(
            orch["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
            "dispatch_task")

    def test_a_role_with_no_script_still_answers_with_text(self):
        script = scripted_model.load({"executor": [{"text": "done"}]})
        reply = script.next_reply(self._request("dispatch_task"))
        self.assertEqual(reply["choices"][0]["finish_reason"], "stop")

    def test_an_unrecognisable_request_does_not_crash_the_run(self):
        # A future role, or a request whose tools were filtered down to
        # nothing by the capability tier. Answering with text ends that
        # conversation instead of aborting the capture.
        script = scripted_model.load({"executor": [{"text": "done"}]})
        reply = script.next_reply({"tools": []})
        self.assertEqual(reply["choices"][0]["finish_reason"], "stop")

    def test_the_markers_really_are_unique_to_their_role(self):
        # The docstring above claims the registry decides this, not
        # scripted_model. Without this test that claim is just a comment,
        # and a change to the role split would mis-route every reply in a
        # captured campaign -- silently, because both answers parse.
        from software.agent.tools import registry
        caps = ("shell", "netscan", "sniffer")
        offered = {role: {s.name for s in
                          registry.specs(role, caps=caps, tier="full")}
                   for role in scripted_model.ROLES}
        for role, marker in scripted_model._ROLE_MARKERS:
            self.assertIn(marker, offered[role],
                          "%s is no longer offered to %s" % (marker, role))
            for other in scripted_model.ROLES:
                if other != role:
                    self.assertNotIn(
                        marker, offered[other],
                        "%s is offered to %s too, so it cannot tell the "
                        "conversations apart" % (marker, other))

    def test_every_role_the_registry_knows_has_a_marker(self):
        # A third role appearing with no marker would be routed to
        # whichever marker happened to match, or to none at all.
        from software.agent.tools import registry
        known = {role for entry in registry._CATALOGUE for role in entry.roles}
        self.assertEqual(known, set(scripted_model.ROLES))


def provider_client():
    """The real OpenAI-compatible client, for its parser only."""
    from software.agent.llm import openai_client
    return openai_client.OpenAiCompatibleClient(
        provider="local", model="scripted",
        api_key=None, base_url="http://127.0.0.1:1/v1")


if __name__ == "__main__":
    unittest.main()
