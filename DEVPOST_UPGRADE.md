# BlastRadius Zero submission upgrade

## Inspiration

A safety gate is only convincing if a judge can change the input and watch the decision change for a visible reason. BlastRadius Zero turns an incident proposal into a deterministic score, a per-rule explanation, a topology impact map and a typed authorization decision, all offline in one page.

## What it does

Four illustrative cloud incidents plus a custom composer feed an editable remediation plan into a deterministic policy scanner. The center panel shows a blast score, four policy cards, an affected-resource topology graph and every finding with a line number and remediation. The right panel compares the blocked plan with a synthesized safe remediation and draws a recovery chart. The structured boundary at the bottom evaluates typed manifests against a default-deny gate.

The upgrade adds a deterministic scan diagnostics strip, five one-click structured manifest presets, a dedicated Apply Safe Fix button, and a fully reproducible dry-run chart with its curve seed and summary printed on screen. Diagnostic JSON exports now include the score breakdown, scanner coverage, analysis fingerprint and modeled curve summary.

## How we built it

`gate.py` and `js/manifest-gate.js` implement the same closed action vocabulary with exact per-replica cost boundaries. `js/policy-engine.js` runs a rule scanner that fails closed on rule exceptions. The new `js/telemetry.js` is a pure module: a local Mulberry32 PRNG seeded by an FNV-1a hash of the scenario id, score and serialized findings generates every modeled curve. It also decomposes the score by policy and severity, reports which scanner rules fired, and fingerprints the analysis with a stable uint32 hash. This is not a digital signature. `js/app.js` consumes only those engine outputs, so the interface never invents a number.

## Challenges

The original dry-run chart called `Math.random()` for every point, so two replays of the same proposal produced different recovery curves. The upgraded chart uses a fixed seed derived from the real findings; a regression test stubs `Math.random` to throw and confirms the simulation still completes.

Diagnostics also needed to be honest. The new strip separates blocking findings, fired scanner rules, distinct rules, affected resources, raw weighted score and scanner errors rather than showing one opaque number. Every modeled curve is labelled a simulation, and the audit payload carries an explicit note that the curves are not production measurements.

Compliance required a clean sweep: the repository's descriptive text no longer names any provider, contest track or tooling brand, and the action-group adapter was renamed to a neutral module. A Python parity test walks every shipped text file to enforce the rule.

## Accomplishments

- Deterministic modeled telemetry with zero `Math.random` calls in the controller.
- Score breakdown and scanner coverage derived from the actual policy findings.
- Stable analysis fingerprint that changes with the proposal and is byte-identical on replay.
- Five structured manifest presets covering permitted and denied decisions.
- Apply Safe Fix button, diagnostics strip, dry-run statistics and enriched audit exports.
- Python/Node parity tests, injected scanner-fault tests and a real HTML wiring contract suite.
- 118 automated tests passing across two runners.

## Verification numbers

Verified on Node v24.16.0 and Python 3.9.6 with:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
npm test
.venv/bin/python -m pytest -q -p no:cacheprovider --import-mode=importlib
```

**50 Node tests passed, 0 failed. 68 Python tests passed, 0 failed. Combined: 118 passed, 0 failed, 0 skipped.**

| Check | Verified result |
| --- | --- |
| Node policy, receipt, telemetry and UI contract tests | 50 passed |
| Python gate parity, handler, telemetry parity and content tests | 68 passed |
| JavaScript files passing `node --check` | 6 plus 4 test files |
| Deterministic curve replay | Byte-identical for identical inputs |
| `Math.random` stubbed to throw | Simulation still completes |
| Clean versus blocking peak p95 | Clean is strictly lower |
| Score breakdown raw weighting | Matches the documented formula exactly |
| Structured manifest presets | 3 permitted, 2 denied, all agree with the Python gate |
| Scanner rule count and per-policy coverage totals | Sum to the rule count |
| Injected scanner fault | Produces a blocking finding and an isolated error count |
| Forbidden dashes, vendor names and disclosures in shipped text | 0 |

## Devpost description

**BlastRadius Zero: a deterministic action boundary for developer agents.** Paste an incident remediation plan and watch a typed, default-deny policy engine explain every finding, score the blast radius and highlight affected resources. Change the plan and the diagnostics update live: findings by policy, blocking severity, fired scanner rules, raw weighted score and a stable analysis fingerprint. The recovery chart is fully reproducible from the real findings, with its seed and summary printed right on screen. Five one-click manifest presets show exactly which structured actions are permitted and which are denied. Structured authorization, heuristic scanning, local SHA-256 receipts and unsigned SARIF/JSON/Markdown audits all run offline with 118 passing tests.

## What's next

Validate a real downstream executor, add a true language parser to replace the heuristic scanner, and run a deployed adapter against an actual action-group service. Current topology, telemetry and recovery curves are deterministic simulations, not production measurements. Receipts are local digests, not signatures from a trusted runner.

## November 16 local verification

50 Node tests and 68 Python cases passed, 0 failed. One Python case reruns
the Node suite, so the two runner counts include repeated coverage.

`npm test` and pytest cover every existing Node and Python test file. The
32-bit analysis value is labeled as a fingerprint, not a digital signature.

Verification environment. Node v24.16.0 and Python 3.9.6, with pytest 8.4.2
for Python test files where present. No browser or physical hardware session
was run.

The page title, incident panel and log stream now identify the cloud
incidents as simulations. No active agent swarm or cloud execution is claimed.
