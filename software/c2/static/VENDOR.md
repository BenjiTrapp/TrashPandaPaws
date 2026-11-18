# Vendored files

The only third-party code in this repository that is not installed by a
package manager, and the reason it is here rather than in a
`requirements.txt`: **`AGENT.md` carries an open finding that nothing is
pinned.** Four requirements files use lower bounds, the server image
installs six packages with no version constraint at all, and three tools
are built from moving git branches with no tag -- so "a rebuild a month
later is a different image". A dependency added as a manifest line would
be a new instance of that finding. A file with its hash written down is
not: it cannot change without this table failing its test.

`software/tests/test_operator_shell.py` reads this table. It is a table
and not prose for exactly that reason -- a record only a human can parse
is a record that drifts.

**The files are unmodified.** A local edit, however small, would make the
hash a record of nothing: it would still match the file, and no longer
match anything upstream. Replacing a file means fetching the new release,
recomputing its hash, and updating its row -- never editing in place.

| file | version | sha256 | upstream | licence | fetched | bytes |
|---|---|---|---|---|---|---|
| `xterm.js` | 6.0.0 | 14903579ff54664cd72f8e8699e6961a6272c21863ec1c3b118cdc8af5d4a972 | https://cdn.jsdelivr.net/npm/@xterm/xterm@6.0.0/lib/xterm.js | MIT | 2026-11-18 | 488663 |
| `xterm.css` | 6.0.0 | 854a7c0fb70e8b1a083c16797ab827299fb18744f5ad34f227b48337e33293c6 | https://cdn.jsdelivr.net/npm/@xterm/xterm@6.0.0/css/xterm.css | MIT | 2026-11-18 | 7112 |

## What these are

`xterm.js` is the terminal the operator shell draws into: a real terminal
emulator, which is what makes `msfconsole`, `vim` and colours work rather
than a line-oriented echo of output. `xterm.css` is its stylesheet. The
UMD build is taken deliberately -- it needs no module loader, and this
project's interface is served as one inline document with no bundler.

The **fit addon is not here**, and that is a design decision rather than
an omission: the shell session's geometry is fixed when the session opens
and the wire cannot renegotiate it (`tools/raccoon_shell.py`: "The size is
sent once and cannot be renegotiated"). An addon that resized the canvas
alone would make the terminal's size a quiet fiction.

## Checking them by hand

    shasum -a 256 software/c2/static/xterm.js software/c2/static/xterm.css

Compare against the rows above. The test does the same thing on every run.
