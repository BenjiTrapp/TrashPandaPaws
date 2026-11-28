#!/usr/bin/env python3
"""A file name from the target is never code in the operator's page.

The file browser built its buttons as HTML strings carrying a JavaScript
string literal inside an `onclick` attribute, filled with a directory
entry's name as the beacon reported it. `esc` escapes `'` as `&#39;`,
which does not help there: the HTML parser decodes the entity before the
JavaScript parser sees the attribute, so the quote arrives intact. The
sites that added a backslash before `'` never escaped the backslash, so a
name ending in one broke out the other way.

Four places had the shape -- the entry rows' three buttons, the detail
panel's five, the directory tree's nodes, and the loot vault's name and
download button. They carry `data-fb-path` / `data-loot-url` now, and one
function per container attaches the handler after the markup is in the
DOM. `dataset` hands back the text an attribute holds and never parses
it, which is the property being bought: there is no context in which a
file name is code.

These tests run the real page's own JavaScript under node against a small
DOM of their own, rather than asserting on its source. The repository has
no browser in CI, and the previous attempt at this finding was scoped out
as "a GUI refactor" partly because of that -- so the point here is to
execute the two functions with a hostile name and see what the handler is
given.
"""

import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from software.c2 import server as server_mod

PAGE = server_mod._OPERATOR_HTML

# Names a beacon could report. Each one broke out of one of the two old
# shapes: the bare quote out of the `esc`-only sites, the trailing
# backslash out of the ones that escaped the quote and not the backslash,
# and the rest are the ordinary attribute and entity cases.
HOSTILE = [
    "a');alert(1);('",
    "a\\'); alert(1); ('",
    "ends-with-a-backslash\\",
    'has"double"quotes',
    "has&#39;entity",
    "<img src=x onerror=alert(1)>",
    "sp ace and ;semi",
    "a'b'c",
    # Percent signs, because "the exact bytes" is the property and a
    # handler that decoded them would be a different one. A lone `%` makes
    # `decodeURIComponent` throw; `%41` would come back as `A`. A mutation
    # that wrapped the attribute read in it survived this list without
    # these two.
    "percent-%41-literal",
    "a-lone-%-sign",
]


def _function(name):
    """One top-level function of the operator page, by name."""
    found = re.search(r"\nfunction %s\(.*?\n\}\n" % re.escape(name),
                      PAGE, re.S)
    if found is None:
        raise AssertionError("the page has no function %s" % name)
    return found.group(0)


def _const(name):
    found = re.search(r"\nconst %s = \{.*?\n\};\n" % re.escape(name),
                      PAGE, re.S)
    if found is None:
        raise AssertionError("the page has no const %s" % name)
    return found.group(0)


# A DOM with just enough in it: elements that hold attributes, a
# `dataset` that behaves like the browser's for `data-fb-*`, a
# `querySelectorAll` that can find by attribute, and an `innerHTML` that
# parses the markup the page builds. Written here rather than pulled in,
# because a dependency for this would be a new one in a repository that
# has none for JavaScript.
_DOM = r"""
function parseAttrs(tag){
  const attrs = {};
  const re = /([A-Za-z-]+)\s*=\s*"([^"]*)"/g;
  let m;
  while((m = re.exec(tag)) !== null){ attrs[m[1]] = decodeEntities(m[2]); }
  return attrs;
}
function decodeEntities(s){
  return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">")
          .replace(/&quot;/g, '"').replace(/&#39;/g, "'")
          .replace(/&amp;/g, "&");
}
function datasetOf(attrs){
  const data = {};
  for(const key of Object.keys(attrs)){
    if(!key.startsWith("data-")) continue;
    const camel = key.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    data[camel] = attrs[key];
  }
  return data;
}
class El {
  constructor(tag){
    this.tagName = (tag || "div").toUpperCase();
    this.attrs = {};
    this.dataset = {};
    this.children = [];
    this.classList = { add(){}, remove(){}, contains(){ return false; } };
    this.style = {};
    this.onclick = null;
    this._html = "";
  }
  set innerHTML(markup){
    this._html = markup;
    this.children = [];
    // Every tag that carries an attribute we care about becomes a node.
    const re = /<(?:button|a|div|span)\b([^>]*)>/g;
    let m;
    while((m = re.exec(markup)) !== null){
      const attrs = parseAttrs(m[1]);
      if(!Object.keys(attrs).some(k => k.startsWith("data-"))) continue;
      const child = new El("button");
      child.attrs = attrs;
      child.dataset = datasetOf(attrs);
      this.children.push(child);
    }
  }
  get innerHTML(){ return this._html; }
  querySelectorAll(selector){
    const m = /^\[([A-Za-z-]+)\]$/.exec(selector);
    if(m) return this.children.filter(c => m[1] in c.attrs);
    return [];
  }
  appendChild(child){ this.children.push(child); }
  closest(){ return null; }
}
const CMD_INPUT = new El("input");
CMD_INPUT.value = "";
CMD_INPUT.focus = () => {};
const document = {
  createElement: tag => new El(tag),
  getElementById: id => (id === "cmd-input" ? CMD_INPUT : STUBS[id] || null),
};
const STUBS = {};
const calls = [];
function esc(s){
  if(s==null) return "";
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
function fbLootDir(p){ calls.push(["fbLootDir", p]); }
function fbLoadDir(p){ calls.push(["fbLoadDir", p]); }
function fbDownloadFile(p){ calls.push(["fbDownloadFile", p]); }
function fbUploadTo(p){ calls.push(["fbUploadTo", p]); }
function fbFormatSize(n){ return String(n); }
function fbShowDetail(){}
let fbSelected = null;
let fbPath = "/tmp";
let fbData = [];
const FB_ICONS = { file: "f", dir: "d" };
function alert(){ throw new Error("a name became code"); }
"""


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class TestAHostileNameStaysText(unittest.TestCase):
    """The page's own `fbRenderList` and `fbBindActions`, run.

    `fbRenderList` is driven with one entry per hostile name, the handler
    attached by `fbBindActions` is called, and the test reads what
    `fbDownloadFile` was given. Before the change the markup carried the
    name inside an `onclick`; a browser would have executed it, and this
    DOM has no `onclick`-from-markup at all, so what it checks instead is
    the one thing that makes the browser case impossible: the path reaches
    the handler as the exact bytes the beacon sent, out of an attribute
    nothing evaluates.
    """

    def _run(self, script):
        out = subprocess.run(["node", "-e", script], capture_output=True,
                             text=True, timeout=60)
        self.assertEqual(out.returncode, 0,
                         "node failed:\n%s\n%s" % (out.stdout, out.stderr))
        return json.loads(out.stdout)

    def test_the_path_reaches_the_handler_unchanged(self):
        script = (_DOM + _const("FB_ACTIONS") + _function("fbBindActions")
                  + _function("fbRenderList") + r"""
const names = %s;
STUBS["fb-list"] = new El("div");
fbData = names.map(name => ({name: name, is_dir: false, size: 1,
                             mtime: "2026-01-01", type: "file", mode: "644"}));
fbRenderList();
const list = STUBS["fb-list"];
const seen = [];
for(const entry of list.children){
  for(const node of entry.children || []){
    if(node.dataset.fbAct === "download"){
      calls.length = 0;
      node.onclick({stopPropagation(){}, preventDefault(){}});
      seen.push(calls[0]);
    }
  }
}
console.log(JSON.stringify(seen));
""" % json.dumps(HOSTILE))
        seen = self._run(script)
        self.assertEqual(len(seen), len(HOSTILE),
                         "not every entry produced a download handler: %r"
                         % (seen,))
        # `fbRenderList` sorts by name, so the handlers do not come back in
        # the order the names went in. What matters is the set.
        for fn, _path in seen:
            self.assertEqual(fn, "fbDownloadFile")
        self.assertEqual(sorted(path for _fn, path in seen),
                         sorted("/tmp/" + name for name in HOSTILE),
                         "a path the handler got is not a name the beacon "
                         "sent")

    def test_the_cat_action_puts_the_name_in_the_input_and_nowhere_else(self):
        script = (_DOM + _const("FB_ACTIONS") + _function("fbBindActions")
                  + _function("fbRenderList") + r"""
STUBS["fb-list"] = new El("div");
fbData = [{name: %s, is_dir: false, size: 1, mtime: "", type: "file",
           mode: "644"}];
fbRenderList();
let fired = null;
for(const entry of STUBS["fb-list"].children){
  for(const node of entry.children || []){
    if(node.dataset.fbAct === "cat"){
      node.onclick({stopPropagation(){}, preventDefault(){}});
      fired = CMD_INPUT.value;
    }
  }
}
console.log(JSON.stringify([fired, calls]));
""" % json.dumps(HOSTILE[0]))
        value, calls = self._run(script)
        self.assertEqual(value, "cat /tmp/" + HOSTILE[0])
        self.assertEqual(calls, [], "the cat button called something")

    def test_the_markup_carries_no_handler_at_all(self):
        script = (_DOM + _const("FB_ACTIONS") + _function("fbBindActions")
                  + _function("fbRenderList") + r"""
STUBS["fb-list"] = new El("div");
fbData = %s.map(name => ({name: name, is_dir: false, size: 1, mtime: "",
                          type: "file", mode: "644"}));
fbRenderList();
const markup = STUBS["fb-list"].children.map(c => c.innerHTML).join("");
console.log(JSON.stringify(markup));
""" % json.dumps(HOSTILE))
        markup = self._run(script)
        self.assertNotIn("onclick", markup,
                         "the rendered row still carries an inline handler")
        # The name's own text is allowed to contain anything -- it is shown
        # to the operator -- as long as it arrives escaped. What must not
        # appear is a tag or a handler the parser would act on.
        self.assertNotIn("<img", markup)
        self.assertNotIn("onerror=", markup.replace("onerror=alert(1)&gt;",
                                                    ""))
        for name in HOSTILE:
            if "<" in name or ">" in name or '"' in name:
                self.assertNotIn(name, markup,
                                 "%r appears unescaped in the markup"
                                 % name)


class TestNoInlineHandlerCarriesATargetName(unittest.TestCase):
    """By source, for the sites a DOM of this size cannot drive.

    The detail panel, the tree and the loot vault are built the same way
    and bound the same way; what a test can say cheaply is that no
    `onclick` attribute in this page is built out of a name, a path or a
    URL that came from a beacon.
    """

    def test_no_onclick_is_concatenated_with_a_target_controlled_value(self):
        # Every site of the shape, not the four the audit named. This test
        # found a fifth while it was being written -- the NetExec menu's
        # subnet buttons, whose `subnet` comes out of `pivotScanData`,
        # which is scan output a beacon reported.
        found = re.findall(r"""onclick="[^"\n]*\\'\s*'\s*\+\s*esc\([^)]*\)""",
                           PAGE)
        self.assertEqual(found, [],
                         "an onclick attribute is still built with a value "
                         "inside a JavaScript string literal: %r" % (found,))

    def test_the_netexec_menu_binds_its_own_buttons(self):
        body = _function("showNxcMenu")
        self.assertIn("data-nxc-target", body)
        self.assertIn("dataset.nxcTarget", body)
        self.assertNotIn("onclick=\"nxcRun", body)

    def test_the_four_places_bind_instead(self):
        for marker in ("data-fb-path", "data-loot-url"):
            self.assertIn(marker, PAGE)
        self.assertIn("function fbBindActions", PAGE)
        # Every container that renders one of these binds it.
        for fn, container in (("fbRenderList", "entry"),
                              ("fbShowDetail", "detail"),
                              ("fbUpdateTree", "tree")):
            body = _function(fn)
            with self.subTest(function=fn):
                self.assertIn("fbBindActions(%s)" % container, body,
                              "%s renders data-fb-act nodes and binds "
                              "nothing" % fn)

    def test_the_loot_vault_binds_its_own(self):
        body = re.search(r"async function showLootViewer\(.*?\n\}\n",
                         PAGE, re.S)
        self.assertIsNotNone(body)
        self.assertIn("data-loot-url", body.group(0))
        self.assertIn("dataset.lootUrl", body.group(0))
        self.assertNotIn("onclick=\"lootSave", body.group(0))

    def test_known_limits_no_longer_lists_the_file_browser(self):
        limits = (REPO_ROOT / "docs" / "AGENT.md").read_text()
        self.assertNotIn("handler-body injections", limits)


if __name__ == "__main__":
    unittest.main()
