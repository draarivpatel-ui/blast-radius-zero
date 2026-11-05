"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const c = { window: {} };
vm.createContext(c);
vm.runInContext(fs.readFileSync(path.join(__dirname, "../js/policy-engine.js"), "utf8"), c);
const engine = c.window.BlastPolicy;
const gate = require("../js/manifest-gate.js");
test("clean risk score is deterministic and zero", () => {
  for (let i = 0; i < 30; i++) assert.equal(engine.analyze("SELECT count(*) FROM jobs;").score, 0);
});
for (const text of ["DROP TABLE jobs;", "terraform destroy", "printenv",
                    '{"Action":"iam:*","Resource":"*"}', "gpu: 40"]) {
  test("actual text scanner blocks " + text, () => assert.equal(engine.analyze(text).clean, false));
}
test("scanner rule failures deny approval", () => {
  const old = engine.RULES[0].test;
  engine.RULES[0].test = () => { throw Error("injected defect"); };
  assert.equal(engine.analyze("SELECT 1;").clean, false);
  engine.RULES[0].test = old;
});
test("empty descriptions never authorize structured execution", () => {
  for (const m of [null, {}, [], {version: 1}, {version: 1, kind: "unknown", parameters: {}}])
    assert.equal(gate.decide(m).allowed, false);
});
test("budget uses per-replica cost and an exact inclusive boundary", () => {
  const make = cents => ({version: 1, kind: "compute", parameters: {replicas: 5, hourly_cost_cents: cents, duration_minutes: 60}});
  assert.equal(gate.decide(make(1000)).allowed, true);
  assert.equal(gate.decide(make(1001)).allowed, false);
  assert.equal(gate.decide(make(1000.1)).allowed, false);
});
test("only scoped dry-run deletion descriptions pass", () => {
  const make = (path, dry_run) => ({version: 1, kind: "delete", parameters: {path, dry_run}});
  assert.equal(gate.decide(make("/workspace/build/cache", true)).allowed, true);
  for (const path of ["/workspace/build", "/workspace/build/../src", "/workspace/build-old/cache", "/"])
    assert.equal(gate.decide(make(path, true)).allowed, false);
  assert.equal(gate.decide(make("/workspace/build/cache", false)).allowed, false);
});
