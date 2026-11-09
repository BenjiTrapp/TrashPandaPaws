"""What lays a payload out on a host: stager templates and startup hooks.

Everything here produces text that runs on a target rather than on the
team server. The stager templates the generator fills live here, and so
does the interpreter-level startup hook that a brought-interpreter build
carries in its own `Lib/`.

Two rules, for the same reason they hold in `tunnel/` and `listeners/`.

Stdlib only, and **nothing here may import from `software.c2.server`**,
which pulls in flask, werkzeug, cryptography, jinja2 and click. The
consumers of this package are the generator *and* command-line tools --
`tools/build_interpreter_bundle.py` assembles a bundle and has no
business loading a web application to render a few lines of text.

What is written here ships verbatim to a target, comments included. So
the emitted text carries no comments, no absolute paths and no literal
that somebody else's detection content already holds; the reasons live
in the docstrings on this side, where they are read by us and by nobody
on the host.
"""
