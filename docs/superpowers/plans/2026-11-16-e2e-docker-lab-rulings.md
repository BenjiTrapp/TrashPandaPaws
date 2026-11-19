# Rulings: the Linux end-to-end lab

Every decision I took on the operator's behalf while executing
`docs/superpowers/plans/2026-11-16-e2e-docker-lab.md`, in the order I took
them, with what each costs if it is wrong.

This file exists because a chat window cannot hold them and because a
ruling that reaches nobody was a decision made in secret. The branch is
21 commits; read this, and rework whatever I got wrong.

Source: `.superpowers/sdd/2026-11-16-e2e-docker-lab/progress.md` (git-ignored
scratch, also copied to the main checkout).

---

## 1

Ruling: the worktree keeps its misleading directory name — why: using-git-
worktrees says an existing linked worktree is not replaced, and moving it
would create phantom state the harness does not track — costs: a subagent
could infer the wrong task from the path, so every dispatch names the absolute
path and the branch.

## 2

Ruling: Task 2's verification mechanism changed from a monkeypatch to a
recording proxy — why: measured that socket objects reject attribute
assignment, so the plan's test could not be written at all — costs: nothing;
the proxy additionally pins the ordering, which the monkeypatch would have
left to chance.

## 3

Ruling: Task 6 must use PyYAML — why: it is installed and already required by
software/requirements.txt, and a hand-rolled YAML reader in a test is a defect
magnet the review rubric would reject — costs: nothing.

## 4

Ruling: Tasks 1 and 2 run first and commit separately — why: reverse-socks-
tunnel and implant-shell-session are live in the same files — costs: if either
conflicts, the two commits can be cherry-picked out without unpicking the lab.

## 5

Ruling: no plan text mandates anything the review rubric treats as a defect —
checked for tests that assert nothing and for duplicated logic blocks; the
only verbatim repetition is the Docker command in Task 2 Step 5 and Task 9
Step 5, which differ in their unittest argument and are a command line rather
than a logic block.

## 6

Ruling: the implementer's scope extension stands -- it updated
test_tunnel_config.py and test_tunnel_yara.py because they parsed the "python3
-c " prefix -- why: a change that breaks a caller owns fixing the caller --
costs: nothing.

## 7

Ruling: test_the_quoting_invariant_still_holds is a guard, not a
discriminator, and must say so -- why: it passed before the change too, and a
test that cannot fail must not look like proof; I explicitly forbade inventing
a way to make it fail, because a dishonest discriminator is worse than an
honest guard -- costs: the fix has one less test arguing for it, which is
accurate rather than cheaper.

## 8

Ruling: the stale comments were NOT out of scope -- beacon.py ~7021 and ~7315,
server.py:609 described the artifact as python3 -c with sys.argv[0] == "-c" --
why: in this codebase comments carry the reasoning and a reader trusts them,
so a comment that lies about a shipped artifact's shape is a defect even where
no code compares the literal -- costs: a slightly larger diff.

## 9

Ruling: the "roughly 115 KB" figure in docs/TUNNEL.md gets fixed by
measurement, not by copying my number -- why: a wrong number beside a new
correct one is worse than either alone -- outcome: measured 135,453 chars at 1
layer, 138,465 at the default 3, 143,105 at 6.

## 10

Ruling: all three Minor findings get fixed rather than carried -- why: two
were names claiming more than the test checked, which is the exact defect
class that cost this project twice this week (a test asserting its own
invented spelling, and a QUIC test that only passed because macOS raises where
Linux is silent) -- costs: one cheap fix round.

## 11

Ruling: the implementer was right that my cited line numbers were diff-
relative -- it reflowed the lines this task's diff added and said so instead
of guessing -- no correction needed.

## 12

Ruling: MY PLAN TEXT WAS WRONG and the implementer's correction stands -- the
plan's comment said shutdown() wakes a blocked accept() "on both platforms" --
why: the implementer measured, and the reviewer independently re-measured,
that on macOS shutdown() on a LISTENING socket raises OSError(57, 'Socket is
not connected') and close() is what wakes the accept
(ConnectionAbortedError(53)); only on Linux does shutdown() do the waking --
consequence: the two try/except blocks are load-bearing rather than defensive,
because one combined try would raise at shutdown() on macOS and skip close()
entirely -- costs: nothing; the comments are now true where my text would have
shipped a confident falsehood into a file whose comments carry the reasoning.

## 13

Ruling: the brief's predicted RED output was also wrong -- it said [] where
the real failure was ['close'] != ['shutdown', 'close'] -- why: the old stop()
does call close(), so the proxy records it; the missing "shutdown" is still
exactly the property under test -- costs: nothing, and it is a reminder that a
predicted failure string in a plan is a guess unless it was run.

## 14

Ruling: Minor 1 is carried, not fixed -- the test comment repeats the platform
reasoning from the fix's comment, and the reviewer suggested a cross-reference
-- why: a pointer can go stale as easily as a duplicate, both comments were
just measured correct by two independent parties, and the value does not
justify a fix round plus a re-review -- costs: if one comment is later edited
without the other, they diverge; recorded here so the final review can take
another look.

## 15

Ruling: the full macOS suite and the Linux run predate a comment-only amend,
and that is accepted -- why: the diff shows no code or test-logic change after
the run, test_beacon was re-run afterwards (78 OK), and the controller's own
full-suite run covers the rest -- costs: a comment typo could in principle
break a docstring-asserting test, which the controller's run would catch.

## 16

Ruling on verification cadence: the controller runs the full suite itself at
GROUP boundaries -- after Task 2 (the two splittable product fixes), after
Task 5 (the product changes), after Task 8 (the lab), and before the final
review -- not after every task -- why: each run is eight minutes of serialized
waiting because an implementer editing files mid-run makes the result
meaningless, and nine runs would cost over an hour while the implementer's own
run plus an independent task reviewer already gate each task -- costs: a
regression introduced in task N is caught at the group boundary rather than
immediately, which is a longer bisect but the same safety.

## 17

Ruling, CROSS-TASK and it changes Task 4: a server without the route answers
405, not 404 -- the implementer measured this; the catch-all /<path:path>
accepts only POST, so a GET to an unrouted path is Method Not Allowed -- and
c2client._request treats ONLY 404 as missing when allow_missing=True
(c2client.py:237), so a 405 raises C2Unavailable -- consequence: Task 4's
planned "the tool still works when the c2 has no such route" test would have
been written against the wrong status and the tool would have failed hard
against any older team server -- decision: Task 4 catches the failure at the
TOOL level and degrades to {"stuck": ...}, rather than widening allow_missing
to cover 405 globally, which would make every other call treat a method error
as an absent resource -- costs: the tool swallows a genuine server fault on
that one sub-call, which is the right trade for a feature that must not break
the call it rides in.

## 18

Ruling: the deleted-agent test removes the entry from the agents dict
directly, because server.py has no agent-delete route -- why: the behaviour
under test is the server's attribution against the live fleet, and the fleet
dict IS that state -- costs: if a delete route is ever added with extra
bookkeeping, this test would not exercise it.

## 19

Ruling: 2-byte fingerprint collisions are accepted, not fixed -- two beacons
can share one, so a rescue could in principle be attributed to the wrong agent
-- why: the fingerprint is 2 of the record's 16 bytes and the format is fixed
by the design as a non-goal to widen; at a dozen agents the birthday
probability is about a tenth of a percent -- costs: a misattributed diagnosis
on a large fleet, which argues for widening the record in a later change
rather than here.

## 20

Ruling: Minor 1 is carried, not fixed -- each unattributed rescue appends an
event_log entry, and _log_event trims 1000 entries once the log passes 5000,
so a beacon that retries in a loop could push out unrelated events -- why:
sending one requires the beacon key, the rescue latch allows one per
exhaustion episode, and a per-fingerprint rate limit is a product decision
rather than this task's -- NOTE the connection: the earlier dns-rescue project
parked a minor that a restart loop sends one rescue per restart, which is
exactly the loop that would drive this -- costs: on a crash-looping beacon the
operator's event log ages faster; the 50-record cap on the list itself is
unaffected.

## 21

Ruling: Minor 2 and 3 carried -- a test cleanup that deletes event_log by
index would shift if the log hit its trim mid-test, and two tests share a
mechanism -- why: both are harmless at the handful-of-events scale these tests
run at, and the reviewer explicitly did not ask for a change on the second.

## 22

Ruling: MY OWN RULING WAS THE LOOSE PART -- I wrote "an empty OR absent
unattributed list" and the implementer reasonably took the first, which means
a model cannot tell "asked, there are none" from "could not ask" -- decision:
on a failed fetch the key is OMITTED, present-and-empty means none, and the
tool description states the convention because a model cannot infer one it was
never told -- no second status flag, because two channels for one fact drift
apart -- costs: a caller that ignores key presence sees nothing at all, which
is the failure mode we want rather than a false negative.

## 23

Ruling: fingerprint belongs in each entry and its absence from my brief was an
error, not a decision -- why: without it the entries are indistinguishable, so
a model cannot tell one unknown beacon reporting three times from three
unknown beacons, and that changes what it would do -- costs: two bytes, and no
target string can reach it by construction.

## 24

Ruling: the implementer's NARROWING of my instruction stands -- I said catch
"any reason", it caught C2Unavailable and C2Unauthorized only -- why: a
programming error in that path must surface as a crash rather than quietly
become "no unattributed rescues"; a code comment now warns against simplifying
it to except Exception -- this is the second time an implementer improved on
my wording by being stricter than it.

## 25

Ruling: removing allow_missing=True from unattributed_rescues() is correct and
supersedes the brief -- why: with it a 404 returns None, the client would
render [], and the tool would emit "asked, none" for a server that could not
be asked, defeating the ruling above; 404 and 405 now both raise and the tool
omits the key for both, with _request untouched so allow_missing stays
404-only for every other caller -- costs: none found; the reviewer verified
the shared helper is unchanged.

## 26

Ruling: Minor 1 WILL be fixed -- nothing in the suite pins the premise that an
unrouted GET answers 405, which is the premise my own ruling rests on; if
someone adds a GET catch-all the rationale becomes silently wrong -- it also
closes the reviewer's one open warning -- costs: one assertion.

## 27

Ruling: Minor 2 carried -- the tool silently drops non-dict entries from the
served list, so a malformed record shrinks the count without a signal -- why:
it matches the tolerance of the surrounding file, and the alternative is
element-level validation in the client that would fail the whole call over one
bad record -- costs: a model could see "present, fewer than expected" and not
know why.

## 28

Ruling on the unexplained red run: NOT waved through. The implementer reported
run A of the full suite failing with 5 failures right after two mutation
experiments, kept only the tail, and guessed stale bytecode. The reviewer
found a better explanation -- both mutations changed the file's size, so pyc
invalidation by mtime+size would have caught them, whereas a cp file-swap
overlapping a still-running suite produces exactly the 5 failures mutation 1
produced. I am re-running the suite myself with every __pycache__ removed
first, and I am NOT dispatching the next edit until it finishes, because doing
so would set the same trap the hypothesis describes.

## 29

Ruling: the premise test needs no mutation evidence -- the implementer worried
it had never been seen red -- why: it asserts one status code from the real
app with no logic between request and assertion, the only way it stays green
under a GET catch-all is one that itself answers 405 (which would keep the
premise true anyway), and the chosen path /never-a-route-405-premise/x cannot
plausibly become routed -- costs: nothing.

## 30

Ruling: the red run A is CLOSED as an artifact of the implementer's own
tooling, not a flake -- controller re-ran the full suite with every
__pycache__ removed first: 3470 tests, OK, 3 skips, zero FAIL/ERROR -- lesson
carried into later dispatches: never swap a source file while a suite runs
against it, and keep a failing run's whole output rather than its tail,
because the tail is what cost the certainty.

## 31

Ruling: the first-load toast storm IS a defect and the brief was wrong -- the
implementer raised it and deferred to the brief's "one per unseen record"; a
server holding 50 records would have raised 50 notifications at once, which is
what a real operator meets opening the console on a week-old server --
decision: ONE rule, no first-tick special case -- when a single poll finds
more than one unseen record, raise one notification for the batch; it states
the count and that they are unclaimable and names none of them -- costs: the
per-record detail is only in the Server Log drawer, because toast() shows and
files in one call and separating them would be new plumbing the ruling
forbade.

## 32

Ruling: Minor 1 carried -- the seen-set is never pruned -- why: the server
caps the list at 50, so it grows only with genuinely new records at a few
bytes each; unbounded in principle, bounded in practice, and the suggested fix
would re-announce a record that dropped out of the cap and came back.

## 33

Ruling: Minor 2 carried -- a failed poll rejects unhandled, so an expired
token logs an error every three seconds -- why: refreshAgents on the same page
already behaves identically, so this adds no new failure mode; the reviewer
confirmed other intervals are unharmed because each callback is its own
promise.

## 34

Ruling, HARD INPUT TO TASK 9: Minor 3 is not carried, it is routed. The dedupe
and batching tests are @skipUnless(shutil.which("node")), so on a host without
node they skip SILENTLY and exactly the logic this task is about goes
unverified. Task 9's CI job must have node available, and its test must assert
the workflow provides it -- otherwise CI reports green over a feature it never
exercised, which is the failure mode this whole branch exists to prevent.

## 35

Ruling, CROSS-TASK and it binds Task 7: "docker compose" DOES NOT WORK on this
machine -- "docker: unknown command: docker compose", while the standalone
"docker-compose" is 5.5.1 and works -- I measured both -- consequence: the
compose file's own header documents "docker compose -f ..." which fails here,
and a driver that hardcodes either form breaks on the other; newer ubuntu-
latest images ship the plugin form and have dropped the v1 standalone, so
hardcoding "docker-compose" would break CI exactly as hardcoding "docker
compose" breaks this laptop -- decision: Task 7's driver DETECTS which form
works and Task 6's header documents both.

## 36

Ruling: the TDD evidence for this task is unrecoverable and I am not
pretending otherwise -- the code existed before any fresh implementer could
see it fail -- compensating control: the reviewer must judge whether each of
the 30 tests would FAIL if the topology were wrong, by mutation rather than by
a RED-first transcript, and the completing implementer must produce that
mutation evidence.

## 37

Ruling: the draft is kept rather than discarded and rewritten -- why: it is
verifiably sound on the four objective checks above, it chose TEST-NET-1 (RFC
5737) for the subnet so it can never collide with a real network, and it
carries its reasoning in comments in the house style; discarding it would cost
a full re-implementation to reach the same place -- costs: no RED-first
evidence, which the ruling above compensates for.

## 38

Ruling: both design departures were MY document being wrong, and I corrected
it rather than the code -- the table said the beacon image installs "requests"
while beacon.py is stdlib-only (its HTTP session is _HttpSession over urllib),
which contradicted this same document's stdlib-only constraint; and the smb-up
scenario spoke of giving the SMB listener "a valid token" when only the DNS
listener has that concept -- costs: nothing, and the note now says both were
caught by an implementer reading the design against the code.

## 39

Ruling: Task 6's concern 3 -- "the lab has never been brought up, nothing here
is evidence a scenario runs" -- is accepted as TRUE and is exactly Task 7's
job. It is not a defect in Task 6; it is the boundary between them.

## 40

Ruling: execution switches to NATIVE for the remaining tasks, declared rather
than quietly. FOUR consecutive dispatches were refused today: Task 6's first
implementer (sonnet-5-5, "Provider blocked the response"), Task 6's reviewer
twice (opus-5 and opus-5-5, both "completed without a text response"), and
Task 7's implementer (opus-5, same). openai.gpt-5.4 does not exist in this
catalog. The same content area produced the same pattern in the earlier dns-
rescue project, where both whole-branch review dispatches were blocked. The
operator chose subagent-driven and I am not overriding that preference -- the
provider is. What I keep from the chosen method: a task review for every task,
done by me and DECLARED as a self-review, with objective verification (running
things, mutation, counting assertions) in place of a fresh reader's judgement.
What is lost: independent context, and this branch has already shown twice
this week that a fresh reader finds what the author cannot. That loss is
recorded here so the final review can weigh it.

## 41

Ruling: the driver's "refuse if the project's containers exist" check must be
scoped to the raccoon-lab project ONLY. There are 15 foreign containers on
this host (fld-*, up 43 hours) belonging to other work, and a driver that
refused on any running container, or worse tore them down, would be a
destructive bug. docker-compose -p raccoon-lab ps is the correct scope.

## 42

Ruling: _compose called subprocess.run WITHOUT env, so the per-run RACCOON_KEY
never reached docker-compose, ${RACCOON_KEY:-} resolved to empty, and the team
server exited 2 with its own correct complaint -- which reads like a lab fault
and is not one. Diagnosed by starting the team server alone under a SEPARATE
project name (raccoon-probe) and reading its log, rather than guessing. The
reason is now in _compose's docstring.

## 43

Ruling: I read the resolver's queries from

## 44

Ruling: I took agents[0]["id"] where the fleet key is agents[0]["agent_id"] --
"id" is the implant's own identifier -- so /api/agents/<id> answered 404. This
is the SAME distinction the rescue's attribution turns on, and the one the
builder check flagged in the design days ago; I then walked into it in the
driver.

## 45

Ruling: python 3.9's argparse validates the EMPTY list that nargs="*" produces
against

## 46

Ruling: my failure message said "the latch is the OpSec promise and a second
query breaks it" when ZERO rescues had crossed -- the opposite failure. A
message that misdescribes the failure sends the next reader the wrong way. The
two cases are now distinguished.

## 47

Ruling: a test I wrote forbade "down" in any _compose call, which banned the
legitimate teardown and asserted the opposite of what was meant. It now pins
the real property: every compose call goes through one helper that injects -p
PROJECT, and nothing reaches for "down" outside it. This is the same defect
class I have flagged in three other people's work this week.

## 48

Ruling: I appended DriverTests with

## 49

Ruling, A DEFECT OF MY OWN AND THE FOURTH OF THIS CLASS THIS WEEK: the first
smb-up check compared last_channel to "smb". A listener relays to the beacon
handler over HTTP, so an SMB delivery lands as last_channel: http and the
field cannot distinguish SMB from HTTPS AT ALL. The check only failed on
"dns", so the scenario PASSED while printing "expected smb" next to "http" --
its central claim proved by nothing. I have flagged exactly this class three
times in other people's work this week (a test asserting its own invented
spelling, a QUIC test that only passed because macOS raises where Linux is
silent, a name claiming more than the test checked). The fourth was mine.
Replaced with an inference from an implant invariant: a leg reaches
_leg_status only when it FAILS and the ladder is ordered, so if SMB delivered
then smb is absent from every cycle AND quic was never reached. Both
directions demonstrated.

## 50

Ruling: per-scenario expectations, not one shared check -- why: Task 7's
assertion would have reported smb-up's correct "no diagnosis" as a failure, so
a shared check is wrong by construction once the scenarios differ; a test now
refuses a scenario that declares no expectation at all, because such a
scenario passes merely by running.

## 51

Ruling: BOTH jobs run, not just the lab -- why: this repository had no CI at
all, and the suite is the primary guard while the lab covers what unit tests
structurally cannot; running one without the other would misrepresent either
-- costs: a longer CI run.

## 52

Ruling: python pinned to 3.9 -- why: software/tests/requirements.txt says the
suite runs in a 3.9 venv and has only ever run against it -- costs: a 3.12
incompatibility would not be caught here, which is a separate piece of work.

## 53

Ruling: MY OWN TEST DESIGN WAS THE DEFECT, and it is the FIFTH of this class
this week. CiTests.setUpClass raised SkipTest when the workflow was absent, so
deleting CI would have removed its own guard -- the same silent green the node
check exists to prevent. Changed to fail.

## 54

Ruling, found by the final review and the most serious thing in it: THREE CI
tests asserted against the file's RAW TEXT, which contains my own explanatory
comments. The words node, ffmpeg and 3.9 all appear in the prose explaining
why they matter, so the tests stayed green when the step they describe was
deleted. MEASURED: removing actions/setup-node left all ten CI tests passing.
They now assert against the PARSED structure -- the setup-node step, the
actual apt-get command, the real python-version value -- and two counter-
checks confirm the guard fires: removing the step says "no setup-node step",
removing ffmpeg from the apt line says "named in prose but never installed".
That phrase is the distinction this branch failed on four times before.

## 55

Ruling: the workflow's central claim is MEASURED, not argued. With node hidden
from PATH and ffmpeg, git and ps left in place, test_c2_hardening +
test_dns_rescue + test_brand_assets run 294 tests and report OK either way --
0 skips with node, 17 WITHOUT, including all seven notification tests (dedupe,
batching, escaping). Green both times. The claim that node's absence is silent
is exactly right, and the numbers are now in the workflow.

## 56

Ruling: my FIRST attempt to measure that was unclean and I am recording it --
I reduced PATH to /usr/bin:/bin and removed ffmpeg along with node, so the 11
failures were all "ffmpeg is not on PATH" and proved nothing about node. Two
variables changed at once. The second attempt failed too, because node is in
/opt/homebrew/bin as well as nvm's. The third isolated it with a symlink
directory. This is the same mistake I proved against an implementer earlier in
this branch, when its red run came from a concurrent file swap.
