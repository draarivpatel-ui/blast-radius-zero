"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const context = { window: {} };
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, "../js/policy-engine.js"), "utf8"), context);
const engine = context.window.BlastPolicy;
const T = require("../js/telemetry.js");

function analyze(text) { return engine.analyze(text); }

/* --------------------------- deterministic curves ------------------------ */

test("telemetry simulate is byte-identical for identical inputs", () => {
  const a = T.simulate(analyze("DROP TABLE jobs;"), { points: 60, scenarioId: "gpu-loop" });
  const b = T.simulate(analyze("DROP TABLE jobs;"), { points: 60, scenarioId: "gpu-loop" });
  assert.deepEqual(a, b);
});

test("telemetry simulate never uses Math.random (stubbed to throw)", () => {
  const old = Math.random;
  Math.random = () => { throw new Error("random used"); };
  try {
    const res = T.simulate(analyze("terraform destroy"), { points: 40, scenarioId: "x" });
    assert.equal(res.points, 40);
  } finally {
    Math.random = old;
  }
});

test("telemetry simulate respects the requested point count and gate index", () => {
  for (const n of [10, 24, 60, 240]) {
    const r = T.simulate(analyze("printenv"), { points: n });
    assert.equal(r.points, n);
    assert.equal(r.t.length, n);
    assert.equal(r.p95.length, n);
    assert.equal(r.errorRate.length, n);
    assert.equal(r.safePath.length, n);
    assert.equal(r.queueDepth.length, n);
    assert.equal(r.gateIndex, Math.floor(n * 0.42));
  }
});

test("telemetry simulate clamps points into [10, 240]", () => {
  assert.equal(T.simulate(null, { points: 1 }).points, 10);
  assert.equal(T.simulate(null, { points: 9999 }).points, 240);
});

test("telemetry simulate values are finite and bounded", () => {
  for (const text of ["", "SELECT 1;", "DROP TABLE jobs;", "terraform destroy", "printenv", "gpu: 40"]) {
    const r = T.simulate(analyze(text), { points: 60, scenarioId: "loop" });
    for (const v of r.p95.concat(r.errorRate, r.safePath, r.queueDepth)) {
      assert.ok(Number.isFinite(v), `non-finite value for ${text}: ${v}`);
    }
    assert.ok(r.summary.peakP95 > 0);
    assert.ok(r.summary.recoveryRatio > 0);
  }
});

test("telemetry simulate clean proposals stay calmer than blocking ones", () => {
  const clean = T.simulate(analyze("SELECT count(*) FROM jobs;"), { points: 60, scenarioId: "s" });
  const blocking = T.simulate(analyze("DROP TABLE jobs;"), { points: 60, scenarioId: "s" });
  assert.equal(clean.clean, true);
  assert.equal(blocking.clean, false);
  assert.ok(clean.summary.peakP95 < blocking.summary.peakP95);
  assert.ok(clean.summary.peakErrorRate < blocking.summary.peakErrorRate);
});

test("telemetry simulate changes with the scenario id but not with replay order", () => {
  const analysis = analyze("DROP TABLE jobs;");
  const a = T.simulate(analysis, { points: 60, scenarioId: "gpu-loop" });
  const b = T.simulate(analysis, { points: 60, scenarioId: "bgp-stampede" });
  assert.notEqual(a.seed, b.seed);
  assert.notDeepEqual(a.p95, b.p95);
  const again = T.simulate(analysis, { points: 60, scenarioId: "gpu-loop" });
  assert.deepEqual(a, again);
});

test("telemetry simulate summary reports deterministic recovery math", () => {
  const r = T.simulate(analyze("rm -rf /"), { points: 60, scenarioId: "s" });
  const peak = Math.max.apply(null, r.p95);
  assert.equal(r.summary.peakP95, Math.round(peak * 1000) / 1000);
  assert.equal(r.summary.settledP95, r.p95[59]);
  assert.equal(r.summary.simulated, true);
  assert.match(r.summary.note, /not a production measurement/);
});

/* --------------------------- score breakdown ----------------------------- */

test("scoreBreakdown of a clean analysis has zero findings", () => {
  const b = T.scoreBreakdown(analyze("SELECT 1;"));
  assert.equal(b.findingCount, 0);
  assert.equal(b.policyCount, 0);
  assert.equal(b.rawScore, 0);
  assert.equal(b.reportedScore, 0);
  assert.equal(b.bySeverity.block, 0);
});

test("scoreBreakdown groups findings by policy and severity", () => {
  const b = T.scoreBreakdown(analyze('DROP TABLE jobs;\n{"Action":"iam:*","Resource":"*"}'));
  assert.ok(b.findingCount >= 2);
  assert.ok(b.policyCount >= 2);
  assert.ok(b.byPolicy["POL-01"]);
  assert.ok(b.byPolicy["POL-02"]);
  assert.ok(b.distinctRules >= 2);
  assert.ok(b.affectedCount >= 1);
});

test("scoreBreakdown raw score matches the documented weighting", () => {
  const a = analyze("DROP TABLE jobs;");
  const b = T.scoreBreakdown(a);
  let raw = 0;
  for (const f of a.findings) raw += f.severity * 3.2;
  raw += Math.max(0, b.policyCount - 1) * 6;
  assert.equal(b.rawScore, Math.round(raw * 10000) / 10000);
});

test("scoreBreakdown on injected scanner errors still counts them", () => {
  const old = engine.RULES[0].test;
  engine.RULES[0].test = () => { throw new Error("defect"); };
  const a = analyze("SELECT 1;");
  engine.RULES[0].test = old;
  const b = T.scoreBreakdown(a);
  assert.ok(b.findingCount >= 1);
  assert.ok(b.bySeverity.block >= 1);
});

/* --------------------------- scanner coverage ---------------------------- */

test("scannerCoverage reports fired, silent and total rules", () => {
  const c = T.scannerCoverage(analyze("DROP TABLE jobs;"), engine.RULES);
  assert.equal(c.ruleCount, engine.RULES.length);
  assert.ok(c.firedRuleCount >= 1);
  assert.equal(c.totalHits, c.fired["R01-drop-table"]);
  assert.equal(c.errorFindings, 0);
});

test("scannerCoverage clean analysis fires zero rules", () => {
  const c = T.scannerCoverage(analyze("SELECT 1;"), engine.RULES);
  assert.equal(c.firedRuleCount, 0);
  assert.equal(c.totalHits, 0);
  for (const p of Object.values(c.byPolicy)) {
    assert.equal(p.fired, 0);
    assert.ok(p.total >= 1);
  }
});

test("scannerCoverage isolates engine error findings", () => {
  const old = engine.RULES[0].test;
  engine.RULES[0].test = () => { throw new Error("defect"); };
  const c = T.scannerCoverage(analyze("SELECT 1;"), engine.RULES);
  engine.RULES[0].test = old;
  assert.equal(c.errorFindings, 1);
  assert.equal(c.firedRuleCount, 0);
});

test("scannerCoverage per-policy totals sum to the rule count", () => {
  const c = T.scannerCoverage(analyze("printenv"), engine.RULES);
  const total = Object.values(c.byPolicy).reduce((s, p) => s + p.total, 0);
  assert.equal(total, c.ruleCount);
});

/* --------------------------- signatures and PRNG -------------------------- */

test("analysisSignature is stable and uint32", () => {
  const a = T.analysisSignature(analyze("terraform destroy"));
  const b = T.analysisSignature(analyze("terraform destroy"));
  assert.equal(a, b);
  assert.ok(Number.isInteger(a) && a >= 0 && a <= 0xffffffff);
});

test("analysisSignature changes with the proposal", () => {
  assert.notEqual(T.analysisSignature(analyze("SELECT 1;")), T.analysisSignature(analyze("DROP TABLE x;")));
});

test("analysisSignature handles a null analysis", () => {
  assert.equal(T.analysisSignature(null), T.hashString("empty"));
});

test("seeded PRNG is deterministic and in [0,1)", () => {
  const a = T.seeded(42), b = T.seeded(42);
  for (let i = 0; i < 100; i++) {
    const v = a();
    assert.equal(v, b());
    assert.ok(v >= 0 && v < 1);
  }
  assert.notEqual(T.seeded(1)(), T.seeded(2)());
});

test("hashString is the FNV-1a offset basis for an empty string", () => {
  assert.equal(T.hashString(""), 0x811c9dc5);
});
