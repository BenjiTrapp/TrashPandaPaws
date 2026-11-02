#!/usr/bin/env node
// Runs PCBWay's own EdgeCoupledMicrostrip() and fix(), as they stand in
// hardware/fab/pcbway-source-excerpts.txt section [1], against a stubbed DOM,
// and prints the differential impedance the page would show.
//
//   node hardware/fab/run_pcbway_page_formula.js [t_oz h_mm w_mm s_mm er]...
//
// With no arguments it runs the two geometries of stackup-note.md.
// The unit selectors are set to the page's oz/ft2 (t) and mm (h, w, s), the
// factors the page then applies are the ones in the excerpt (1.379 and 39.3).
const fs = require("fs");
const path = require("path");

const text = fs.readFileSync(
  path.join(__dirname, "pcbway-source-excerpts.txt"), "utf8");
const start = text.indexOf("        function EdgeCoupledMicrostrip(");
const stop = text.indexOf("-- raw: the unit factors");
if (start < 0 || stop < 0) throw new Error("excerpt section [1] not found");
const pageCode = text.slice(start, stop);

const stubs = `
var t, h, s, w, Er, Zo, Zd, tunit, hunit, sunit, wunit, utdata;
var units = {EdgeCoupledMicrostript: "1.379", EdgeCoupledMicrostriph: "39.3",
             EdgeCoupledMicrostripw: "39.3", EdgeCoupledMicrostrips: "39.3"};
var document = {getElementById: function (id) {
  return {getElementsByClassName: function () {
    return [{dataset: {val: units[id]}}]; }}; }};
var out = {};
function $(sel) {
  var o = [];
  if (sel.charAt(0) == "#") { out[sel] = out[sel] || {value: ""}; o = [out[sel]]; }
  o.val = function () {}; o.show = function () {}; o.hide = function () {};
  return o;
}
`;
const run = `
function zd(t_oz, h_mm, w_mm, s_mm, er) {
  EdgeCoupledMicrostrip(String(t_oz), "t");
  EdgeCoupledMicrostrip(String(h_mm), "h");
  EdgeCoupledMicrostrip(String(w_mm), "w");
  EdgeCoupledMicrostrip(String(s_mm), "s");
  EdgeCoupledMicrostrip(String(er), "Er");
  return out["#EdgeCoupledMicrostripZd"].value;
}
`;
const zd = new Function(stubs + pageCode + run + "return zd;")();

const args = process.argv.slice(2).map(Number);
const cases = args.length
  ? [args]
  : [[1, 0.1855, 0.20, 0.17, 4.74], [1, 0.1855, 0.18, 0.21, 4.74]];
for (let i = 0; i < cases.length; i += 1) {
  const c = cases[i];
  console.log(`t=${c[0]} oz  h=${c[1]} mm  w=${c[2]} mm  s=${c[3]} mm  ` +
              `Er=${c[4]}  ->  Zd = ${zd(...c)} ohm`);
}
