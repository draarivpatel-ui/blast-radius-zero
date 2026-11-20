"use strict";
// Regression tests for the verdict console, rule inspector, containment
// diff and one-click plans added in the November 18 interface revamp.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..");
const read = rel => fs.readFileSync(path.join(ROOT, rel), "utf8");
const html = read("index.html");
const css = read("styles.css");
const appJs = read("js/app.js");
const T = require("../js/telemetry.js");

const ctx = { window: {} };
vm.createContext(ctx);
vm.runInContext(read("js/policy-engine.js"), ctx);
vm.runInContext(read("js/scenarios.js"), ctx);
const P = ctx.window.BlastPolicy;
const S = ctx.window.BlastScenarios;
const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));

/* ------------------------------ verdict tiers ---------------------------- */

test("C01: verdict is ALLOW only for a clean scan", () => {
  assert.deepEqual(T.verdict(P.analyze("SELECT 1;")), { key: "allow", label: "ALLOW", status: "ALLOW" });
  assert.equal(T.verdict(P.analyze("")).status, "ALLOW");
});

test("C02: a lone sub-blocking finding requires approval", () => {
  const a = P.analyze("maxReplicas: 50");
  assert.equal(a.findings.length, 1);
  assert.ok(a.findings[0].severity < 8);
  assert.ok(a.score > 0 && a.score < 35);
  assert.equal(T.verdict(a).status, "APPROVAL_REQUIRED");
  assert.equal(T.verdict(a).label, "APPROVAL REQUIRED");
});

test("C03: any blocking finding is BLOCKED and a missing analysis fails closed", () => {
  for (const text of ["DROP TABLE users;", "rm -rf /", "redis-cli FLUSHALL"]) {
    assert.equal(T.verdict(P.analyze(text)).status, "BLOCKED", text);
  }
  assert.equal(T.verdict(null).status, "BLOCKED");
  assert.equal(T.verdict({}).status, "BLOCKED");
  const fault = { score: 35, clean: false, findings: [{ rule: "ENGINE-ERROR", severity: 10, line: 0 }] };
  assert.equal(T.verdict(fault).status, "BLOCKED");
});

test("C04: the verdict agrees with the score thresholds on every scenario plan", () => {
  for (const sc of [...S.SCENARIOS, S.CUSTOM_TEMPLATE]) {
    for (const text of [sc.rawPlan, sc.safeRemediation]) {
      const a = P.analyze(text);
      const v = T.verdict(a).status;
      if (a.clean) assert.equal(v, "ALLOW");
      else if (a.score >= 35) assert.equal(v, "BLOCKED");
      else assert.equal(v, "APPROVAL_REQUIRED");
    }
  }
});

/* ------------------------------ scenario truth --------------------------- */

test("C05: every incident's raw plan is blocked and its safe plan scans clean", () => {
  for (const sc of S.SCENARIOS) {
    const before = P.analyze(sc.rawPlan);
    const after = P.analyze(sc.safeRemediation);
    assert.equal(T.verdict(before).status, "BLOCKED", sc.id);
    assert.equal(after.clean, true, `${sc.id} safe plan fired ${after.findings.map(f => f.rule).join(", ")}`);
    assert.equal(after.score, 0, sc.id);
  }
});

test("C06: the custom template does not claim to synthesize a remediation", () => {
  assert.doesNotMatch(S.CUSTOM_TEMPLATE.safeRemediation, /synthesi[sz]ed from your edits/i);
  assert.match(S.CUSTOM_TEMPLATE.safeRemediation, /no prewritten safe plan/);
});

/* ------------------------------ one-click plans -------------------------- */

function loadPlans() {
  const block = appJs.slice(appJs.indexOf("const LOAD_PLANS = ["), appJs.indexOf("];", appJs.indexOf("const LOAD_PLANS = [")));
  return [...block.matchAll(/label: ("[^"]+"),\s*cls: ("[^"]+"),\s*text: ("(?:[^"\\]|\\.)*")/g)]
    .map(m => ({ label: JSON.parse(m[1]), cls: JSON.parse(m[2]), text: JSON.parse(m[3]) }));
}

test("C07: each one-click plan's label matches the real engine verdict", () => {
  const plans = loadPlans();
  assert.equal(plans.length, 3);
  for (const p of plans) {
    const v = T.verdict(P.analyze(p.text)).status;
    if (p.label.startsWith("Benign")) { assert.equal(v, "ALLOW", p.label); assert.equal(p.cls, "chip-benign"); }
    else if (p.label.startsWith("Needs approval")) { assert.equal(v, "APPROVAL_REQUIRED", p.label); assert.equal(p.cls, "chip-approval"); }
    else assert.fail("unexpected plan label " + p.label);
  }
});

test("C08: each attack injection button blocks a clean plan on its own", () => {
  const block = appJs.slice(appJs.indexOf("const injectMap = {"), appJs.indexOf("};", appJs.indexOf("const injectMap = {")));
  const snippets = [...block.matchAll(/(btnInject\w+): (["'])((?:\\.|(?!\2).)*)\2/g)];
  assert.equal(snippets.length, 4);
  for (const [, id, quote, body] of snippets) {
    const text = quote === '"' ? JSON.parse('"' + body + '"') : body.replace(/\\n/g, "\n");
    const a = P.analyze("SELECT 1;\n" + text);
    assert.equal(T.verdict(a).status, "BLOCKED", id);
    assert.ok(ids.has(id), `#${id} missing from index.html`);
  }
});

/* ------------------------------ inspector helpers ------------------------ */

test("C09: primaryFinding picks the highest severity, then the earliest line", () => {
  const a = P.analyze("maxReplicas: 50\nredis-cli FLUSHALL\nDROP TABLE jobs;\nrm -rf /");
  const p = T.primaryFinding(a);
  assert.equal(p.severity, 10);
  assert.equal(p.line, 3);
  assert.equal(T.primaryFinding(P.analyze("SELECT 1;")), null);
  assert.equal(T.primaryFinding(null), null);
});

test("C10: flaggedLines maps each finding line to its worst severity", () => {
  const a = P.analyze("SELECT 1;\nmaxReplicas: 50\nDROP TABLE jobs;");
  const f = T.flaggedLines(a);
  assert.equal(f[1], undefined);
  assert.equal(f[2], 7);
  assert.equal(f[3], 10);
});

/* ------------------------------ diff and containment --------------------- */

function rebuild(ops, side) {
  return ops.filter(o => o.op === "same" || o.op === (side === "a" ? "del" : "add")).map(o => o.text).join("\n");
}

test("C11: lineDiff reconstructs both sides exactly and numbers lines", () => {
  const a = "one\ntwo\nthree\nfour";
  const b = "one\n2\nthree\nfour\nfive";
  const ops = T.lineDiff(a, b);
  assert.equal(rebuild(ops, "a"), a);
  assert.equal(rebuild(ops, "b"), b);
  assert.deepEqual(ops.map(o => o.op), ["same", "del", "add", "same", "same", "add"]);
  assert.equal(ops[1].a, 2);
  assert.equal(ops[2].b, 2);
  assert.ok(T.lineDiff("x\ny", "x\ny").every(o => o.op === "same"));
  for (const sc of S.SCENARIOS) {
    const d = T.lineDiff(sc.rawPlan, sc.safeRemediation);
    assert.equal(rebuild(d, "a"), sc.rawPlan, sc.id);
    assert.equal(rebuild(d, "b"), sc.safeRemediation, sc.id);
  }
});

test("C12: lineDiff falls back without quadratic work on huge inputs", () => {
  const big = Array.from({ length: 450 }, (_, i) => "l" + i).join("\n");
  const ops = T.lineDiff(big, "x");
  assert.equal(ops.length, 451);
  assert.equal(rebuild(ops, "a"), big);
});

test("C13: containment lists what the safe plan removes from the blast radius", () => {
  for (const sc of S.SCENARIOS) {
    const before = P.analyze(sc.rawPlan);
    const after = P.analyze(sc.safeRemediation);
    const c = T.containment(before, after);
    assert.deepEqual([...c.contained].sort(), [...before.affected].sort(), sc.id);
    assert.deepEqual([...c.residual], []);
    assert.equal(c.verdictBefore, "BLOCKED");
    assert.equal(c.verdictAfter, "ALLOW");
    assert.equal(c.scoreAfter, 0);
  }
  const partial = T.containment(P.analyze("DROP TABLE a;\nredis-cli FLUSHALL"), P.analyze("redis-cli FLUSHALL"));
  assert.deepEqual([...partial.contained], ["postgres"]);
  assert.deepEqual([...partial.residual], ["redis"]);
});

test("C14: the engine exposes per-finding resource mapping used by the map", () => {
  assert.equal(typeof P.affectedFromFindings, "function");
  const f = P.analyze("DROP TABLE jobs;").findings[0];
  assert.deepEqual([...P.affectedFromFindings([f])], ["postgres"]);
});

/* ------------------------------ markup contract -------------------------- */

test("C15: the console, inspector, diff and map toggle exist in the page", () => {
  for (const id of ["verdictConsole", "verdictWord", "editorGutter", "graphProposed", "graphContained",
                    "graphNote", "ruleDetail", "ruleCount", "diffView", "diffStats", "receiptPanel",
                    "manifest-verdict", "btnSafeFix", "injectRow"]) {
    assert.ok(ids.has(id), `missing #${id}`);
  }
  for (const id of ["graphProposed", "graphContained"]) assert.ok(appJs.includes(`#${id}`), `#${id} not bound`);
  assert.match(html, /aria-pressed="true">Proposed plan/);
});

test("C16: the page stays fully offline (no external script, style, font or image)", () => {
  assert.doesNotMatch(html, /\b(?:src|href)="(?:https?:)?\/\//i);
  assert.doesNotMatch(css, /@import|url\(\s*["']?(?:https?:)?\/\//i);
  assert.doesNotMatch(css, /@font-face/);
  assert.match(html, /<link rel="icon" href="data:image\/svg\+xml,/);
});

test("C17: titles stand alone with no kicker above or tagline below", () => {
  // The top bar holds only the brand mark and name, never a subtitle line.
  const header = html.slice(html.indexOf('<header class="topbar">'), html.indexOf("</header>"));
  assert.doesNotMatch(header, /<p\b/);
  // No panel heading is followed directly by a paragraph.
  assert.doesNotMatch(html, /<\/h2>\s*<\/div>\s*<p class="panel-copy"/);
  assert.doesNotMatch(html, /class="(?:eyebrow|kicker)"/);
});

test("C18: one verdict function drives header, console and exports", () => {
  assert.ok((appJs.match(/BlastTelemetry\.verdict\(/g) || []).length >= 4);
  assert.doesNotMatch(appJs, /"REVIEW"/);
  assert.match(appJs, /gateStatus: window\.BlastTelemetry\.verdict\(analysis\)\.status/);
});

test("C19: editor-derived text reaches the inspector and diff through textContent", () => {
  const inspector = appJs.slice(appJs.indexOf("function renderInspector"), appJs.indexOf("function selectFinding"));
  const diff = appJs.slice(appJs.indexOf("function renderRightDiff"), appJs.indexOf("function renderDiagnostics"));
  for (const block of [inspector, diff]) assert.doesNotMatch(block, /innerHTML\s*=\s*`/);
  assert.match(appJs, /replace\(\/'\/g, "&#39;"\)/);
});

test("C20: mobile layout keeps a 390px viewport free of page-level overflow rules", () => {
  assert.match(css, /@media \(max-width: 640px\)/);
  assert.match(css, /\.topbar \{ position: static;/);
  assert.doesNotMatch(css, /\.topo-svg \{ min-width/);
  assert.match(appJs, /matchMedia\("\(max-width: 640px\)"\)/);
  assert.match(css, /body \{[^}]*overflow-x: hidden;/);
});

test("C21: finding lines match the editor when a plan starts with blank lines", () => {
  const text = "\n\n  \nDROP TABLE x;\nredis-cli FLUSHALL";
  const raw = P.analyze(text);
  assert.deepEqual([...raw.findings.map(f => f.line)], [1, 2]);
  const shifted = T.withEditorLines(raw, text);
  assert.deepEqual([...shifted.findings.map(f => f.line)], [4, 5]);
  assert.equal(text.split("\n")[shifted.findings[0].line - 1], "DROP TABLE x;");
  assert.deepEqual([...raw.findings.map(f => f.line)], [1, 2], "the engine result is not mutated");
  assert.equal(T.withEditorLines(P.analyze("DROP TABLE x;"), "DROP TABLE x;").findings[0].line, 1);
  assert.equal(T.withEditorLines(null, "x"), null);
  assert.match(appJs, /BlastTelemetry\.withEditorLines\(/);
  assert.match(appJs, /window\.BlastPolicy\.analyze\(text\)/);
});

test("C22: the custom composer never claims a containment result", () => {
  assert.match(appJs, /currentScenario\.id !== "custom"/);
  for (const id of ["btnSafeFix", "btnCopyDiff"]) assert.match(appJs, new RegExp(`\\$\\("#${id}"\\)`));
  assert.match(appJs, /safeBtn\.disabled = !hasSafePlan\(\)/);
  assert.match(appJs, /gc\.disabled = !hasSafePlan\(\)/);
  assert.match(appJs, /containment: analysis && hasSafePlan\(\)/);
  assert.match(appJs, /if \(!ed \|\| !currentScenario \|\| !hasSafePlan\(\)\) return;/);
});

test("C23: scenario cards carry no small label above their title", () => {
  const sw = appJs.slice(appJs.indexOf("function renderScenarioSwitcher"), appJs.indexOf("function syncScenarioActive"));
  assert.doesNotMatch(sw, /sc-kind/);
  assert.match(sw, /"sc-dot"/);
});
