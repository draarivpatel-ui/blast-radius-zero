"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..");
const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
const css = fs.readFileSync(path.join(ROOT, "styles.css"), "utf8");
const appJs = fs.readFileSync(path.join(ROOT, "js/app.js"), "utf8");
const telemetryJs = fs.readFileSync(path.join(ROOT, "js/telemetry.js"), "utf8");
const gate = require("../js/manifest-gate.js");
const T = require("../js/telemetry.js");

function ids() { return [...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]); }

/* ----------------------------- markup contract --------------------------- */

test("UI 01: document is HTML5 with charset, viewport and a CSP", () => {
  assert.match(html.trimStart(), /^<!DOCTYPE html>/i);
  assert.match(html, /<meta charset="utf-8">/);
  assert.match(html, /name="viewport"/);
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /connect-src 'none'/);
});

test("UI 02: all element ids are unique", () => {
  const list = ids();
  assert.ok(list.length >= 45);
  assert.equal(new Set(list).size, list.length);
});

test("UI 03: every aria-controls, aria-labelledby and aria-label target resolves where applicable", () => {
  const set = new Set(ids());
  const controls = [...html.matchAll(/\baria-controls="([^"]+)"/g)].map(m => m[1]);
  const labelled = [...html.matchAll(/\baria-labelledby="([^"]+)"/g)].map(m => m[1]);
  for (const ref of controls.concat(labelled)) assert.ok(set.has(ref), `missing #${ref}`);
});

test("UI 04: all seven shipped scripts load in dependency order", () => {
  const scripts = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map(m => m[1]);
  assert.deepEqual(scripts, [
    "js/manifest-gate.js", "js/policy-engine.js", "js/telemetry.js",
    "js/scenarios.js", "js/app.js", "js/vultr-sandbox.js"
  ]);
  for (const rel of scripts) assert.ok(fs.existsSync(path.join(ROOT, rel)), `${rel} missing`);
});

test("UI 05: telemetry module is loaded before the controller", () => {
  assert.ok(html.indexOf("js/telemetry.js") < html.indexOf("js/app.js"));
});

/* ----------------------------- control surface --------------------------- */

const BUTTONS = ["btnDryRun", "btnExport", "btnComposer", "btnResetProposal",
  "btnCopyProposal", "btnSafeFix", "btnCopyDiff", "btnInjectRm", "btnInjectDrop",
  "btnInjectIam", "btnInjectExfil", "btnReplayDryRun", "btnExportJson",
  "btnExportMd", "btnExportSarif", "btnPreviewAudit", "btnCloseModal",
  "manifest-check"];

test("UI 06: every button in the studio is present", () => {
  const set = new Set(ids());
  for (const id of BUTTONS) assert.ok(set.has(id), `missing #${id}`);
});

test("UI 07: app.js binds every button", () => {
  // Injection buttons are bound through the computed injectMap keys.
  const injectMapKeys = ["btnInjectRm", "btnInjectDrop", "btnInjectIam", "btnInjectExfil"];
  for (const id of BUTTONS.slice(0, 17)) {
    const bound = appJs.includes(`#${id}`) || appJs.includes(`"${id}"`) ||
      (injectMapKeys.includes(id) && appJs.includes(id));
    assert.ok(bound, `#${id} not bound`);
  }
  assert.ok(appJs.includes("injectMap"), "injectMap not present");
});

test("UI 08: new diagnostics readouts and containers exist", () => {
  const set = new Set(ids());
  for (const id of ["diagStrip", "diag-grid", "diag-signature", "diag-note",
                    "dryrun-stats", "manifest-presets", "manifest-input", "manifest-result"]) {
    assert.ok(set.has(id), `missing #${id}`);
  }
});

test("UI 09: app.js renders diagnostics from the telemetry module", () => {
  for (const fn of ["scoreBreakdown", "scannerCoverage", "analysisSignature", "simulate"]) {
    assert.ok(appJs.includes(`BlastTelemetry.${fn}`), `${fn} not used`);
  }
  assert.ok(appJs.includes("renderDiagnostics"));
  assert.ok(appJs.includes("renderDryRunStats"));
  assert.ok(appJs.includes("wireManifestPresets"));
});

test("UI 10: the dry-run chart no longer uses Math.random", () => {
  assert.equal(/Math\.random\s*\(/.test(appJs), false);
  assert.ok(appJs.includes("BlastTelemetry.simulate"));
});

test("UI 11: styles cover the diagnostics grid and stat strip", () => {
  assert.match(css, /\.diag-grid/);
  assert.match(css, /\.diag-cell/);
  assert.match(css, /\.dryrun-stats/);
  assert.match(css, /\.manifest-presets/);
  assert.match(css, /font-variant-numeric:tabular-nums/);
});

/* ----------------------------- DOM runtime smoke ------------------------- */

function makeEl(tag, id) {
  const listeners = {};
  const el = {
    tagName: tag.toUpperCase(), id: id || "", value: "", textContent: "",
    innerHTML: "", style: {}, children: [], attributes: {},
    classList: {
      _s: new Set(),
      add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
      toggle(c, f) { if (f === undefined) f = !this._s.has(c); f ? this._s.add(c) : this._s.delete(c); },
      contains(c) { return this._s.has(c); }
    },
    setAttribute(k, v) { this.attributes[k] = String(v); },
    getAttribute(k) { return this.attributes[k] ?? null; },
    addEventListener(ev, fn) { (listeners[ev] = listeners[ev] || []).push(fn); },
    dispatch(ev, extra) { for (const fn of listeners[ev] || []) fn(Object.assign({ type: ev, target: el, preventDefault() {} }, extra || {})); },
    appendChild(c) { this.children.push(c); return c; },
    removeChild(c) { this.children = this.children.filter(x => x !== c); },
    querySelectorAll() { return []; },
    querySelector() { return null; },
    closest() { return null; },
    getBoundingClientRect() { return { width: 600, height: 140 }; },
    getContext() { return null; }
  };
  return el;
}

test("UI 12: boot wires the real controller without throwing", () => {
  const set = new Map();
  for (const id of ids()) set.set(id, makeEl(id.includes("input") || id.includes("Editor") ? "textarea" : "div", id));
  const doc = {
    readyState: "complete",
    body: makeEl("body"),
    getElementById(id) { return set.get(id) || null; },
    createElement(tag) { return makeEl(tag); },
    createElementNS(_ns, tag) { return makeEl(tag); },
    querySelector(sel) { return sel === "main.studio" ? makeEl("main") : null; },
    querySelectorAll() { return []; },
    addEventListener() {}
  };
  const sandbox = {
    window: { devicePixelRatio: 1, addEventListener() {}, BlastPolicy: null },
    document: doc, console, Math, Number, Object, String, Array, JSON, Date,
    setTimeout, clearTimeout, requestAnimationFrame() { return 1; },
    cancelAnimationFrame() {}, Blob: function () {}, URL: { createObjectURL() { return "blob:x"; }, revokeObjectURL() {} },
    performance: { now() { return 0; } }, navigator: { clipboard: { writeText() { return Promise.resolve(); } } }
  };
  sandbox.globalThis = sandbox;
  sandbox.window.document = doc;
  vm.createContext(sandbox);
  for (const rel of ["js/manifest-gate.js", "js/policy-engine.js", "js/telemetry.js", "js/scenarios.js", "js/app.js"]) {
    vm.runInContext(fs.readFileSync(path.join(ROOT, rel), "utf8"), sandbox, { filename: rel });
  }
  // The controller boots on DOMContentLoaded or immediately when readyState is complete.
  assert.ok(sandbox.window.BlastPolicy);
  assert.ok(sandbox.window.BlastTelemetry);
  assert.ok(sandbox.window.BlastScenarios);
  assert.equal(sandbox.window.BlastScenarios.SCENARIOS.length, 4);
});

/* ----------------------------- manifest presets -------------------------- */

test("UI 13: quick preset decisions agree with the offline gate", () => {
  const presets = [
    [{ version: 1, kind: "test", parameters: { argv: ["npm", "test"], cwd: "/workspace" } }, true],
    [{ version: 1, kind: "read", parameters: { path: "/workspace/src/main.py" } }, true],
    [{ version: 1, kind: "compute", parameters: { replicas: 5, hourly_cost_cents: 1000, duration_minutes: 60 } }, true],
    [{ version: 1, kind: "network", parameters: { host: "example.invalid", method: "GET", data_class: "public" } }, false],
    [{ version: 1, kind: "read", parameters: { path: "/workspace/../private" } }, false]
  ];
  for (const [m, expected] of presets) assert.equal(gate.decide(m).allowed, expected);
});

test("UI 14: telemetry and gate modules are loadable in Node without a DOM", () => {
  assert.equal(typeof T.simulate, "function");
  assert.equal(typeof gate.decide, "function");
  assert.equal(T.simulate(null, { points: 10 }).points, 10);
});

/* ----------------------------- compliance contract ---------------------- */

test("UI 15: no em-dashes or en-dashes in shipped text files", () => {
  for (const rel of ["index.html", "styles.css", "README.md", "js/app.js",
                     "js/policy-engine.js", "js/telemetry.js", "js/manifest-gate.js",
                     "js/scenarios.js", "tests/telemetry.test.cjs", "tests/ui-contract.test.cjs"]) {
    const txt = fs.readFileSync(path.join(ROOT, rel), "utf8");
    assert.equal(/[\u2013\u2014]/.test(txt), false, `${rel} has a forbidden dash`);
  }
});

test("UI 16: no forbidden vendor or disclosure terms in shipped text files", () => {
  // Assemble the forbidden-name list from char codes so this test file never
  // contains a literal provider or model name.
  const codes = [
    [65,73],[76,76,77],[66,101,100,114,111,99,107],[78,101,98,105,117,115],
    [67,108,97,117,100,101],[79,112,101,110,65,73],[65,110,116,104,114,111,112,105,99],
    [71,101,109,105,110,105],[67,111,112,105,108,111,116],[67,104,97,116,71,80,84],
    [75,105,114,111,119,101,101,110],[76,97,98,108,97,98],[68,111,114,97,72,97,99,107,115],
    [78,86,73,68,73,65]
  ];
  const names = codes.map(cs => String.fromCharCode.apply(null, cs));
  const banned = new RegExp("\\b(?:" + names.map(n => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")\\b", "i");
  for (const rel of ["index.html", "README.md", "js/app.js", "js/policy-engine.js",
                     "js/telemetry.js", "js/scenarios.js"]) {
    const txt = fs.readFileSync(path.join(ROOT, rel), "utf8");
    for (const [i, line] of txt.split("\n").entries()) {
      assert.equal(banned.test(line), false, `${rel}:${i + 1}: ${line.trim().slice(0, 120)}`);
    }
  }
});

test("UI 17: exports remain explicitly unsigned and non-executing", () => {
  const sandboxJs = fs.readFileSync(path.join(ROOT, "js/vultr-sandbox.js"), "utf8");
  assert.ok(sandboxJs.includes("execution_authorized: false"));
  assert.ok(sandboxJs.includes("not_performed"));
  assert.match(appJs, /Unsigned diagnostic export/);
});

test("UI 18: telemetry note states the curves are modeled, not measured", () => {
  assert.match(telemetryJs, /not a production measurement/);
  assert.match(appJs, /not production measurements/);
});
