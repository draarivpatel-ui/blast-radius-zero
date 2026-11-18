# BlastRadius Zero

**A deterministic action boundary for developer agents, with a fully inspectable incident diagnostics studio.** The enforcement layer accepts structured actions and denies everything outside its policy. The text scanner explains suspicious plans with explicit rule findings, but it is a heuristic, not a shell, SQL or Terraform parser. Everything runs locally in the browser.

Open `index.html` directly, or serve the folder with any static file server. There is no backend, no key, no network request and no infrastructure account.

## Run and verify

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
npm test
.venv/bin/python -m pytest -q -p no:cacheprovider --import-mode=importlib
```

Both suites run offline. `npm test` expands to `node --test tests/*.test.cjs` and passes **50 tests**. The pytest command passes **68 tests**, including a parity check that runs the real Node regressions from Python. Combined: **118 tests, 0 failures**.

Optional local server:

```bash
python3 -m http.server 8000
```

All shipped JavaScript files pass `node --check`. No install is needed for the Node suite; the Python suite needs `pytest` (see `requirements-dev.txt`).

## Default-deny structured boundary

`gate.py` and `js/manifest-gate.js` implement the same policy. The regression suite checks browser/Python agreement against labelled cases, cost boundaries, path traversal, malformed types and unknown actions.

A manifest has exactly `version`, `kind` and `parameters`. Each supported kind has a closed parameter schema.

| Kind | Permitted behavior |
| --- | --- |
| read | Absolute canonical paths within the protocol's virtual workspace |
| test | Explicit test-command argument vectors and a scoped working directory |
| delete | Only a preview below the build subtree; actual deletion is denied |
| iam | Explicit read-only actions and the configured demo resources |
| compute | Whole-number replica, cost and duration bounds with an exact cost cap |
| network | Always denied by the default offline policy |

Compute cost is checked per replica, in integer cents. Five replicas at 1000 cents each meet the hourly boundary; increasing per-replica cost to 1001 cents fails. Unknown keys or action types never inherit a default approval. The structured boundary panel now includes five one-click presets (permitted test, permitted read, compute at cap, denied network egress, denied path escape) so a judge can watch the exact decision change.

These are authorization decisions over descriptions. The project does not execute commands, delete files, grant roles or allocate compute. A downstream executor must enforce the same scope, prevent symlink escapes and avoid translating approved paths into shell strings.

## Offline function action-group adapter

`action_handler.py` implements a generic function action-group response contract with no cloud SDK dependency. The function `authorizeAgentAction` accepts one string manifest parameter and returns the deterministic gate decision.

Malformed events fail closed. The handler logs no incoming event or payload and performs no remote calls. It is locally contract-tested, not a deployed or load-tested service. Deploying it requires a reviewed execution role and the actual provider's configuration.

## Incident studio

Four illustrative scenarios cover a runaway GPU billing loop, destructive database migration, cache stampede and prompt-injection exfiltration. Editable plans are scanned by the actual policy rules; clean scores are always zero and identical findings receive identical scores. The left panel offers injection chips, a safe remediation chip and a dedicated **Apply Safe Fix** button.

Scanner faults create a blocking finding. Obfuscation can evade a text scanner, and quoted documentation can produce false positives. The research package includes both examples rather than claiming perfect text understanding.

Topology diagrams, incident telemetry and recovery curves are simulations. They are not measurements of a production outage.

## Deterministic telemetry and diagnostics

`js/telemetry.js` is a new pure module. It removes every `Math.random()` call from the dry-run chart and replaces them with reproducible curves derived from the real policy analysis, the scenario id and a fixed FNV-1a seed. Replaying the same proposal produces byte-identical numbers.

The module also exposes:

- `simulate(analysis, options)`: p95 latency, error rate, safe path and queue depth curves with a summary of peak, settled, recovery ratio and modeled latency saved.
- `scoreBreakdown(analysis)`: finding counts per policy, severity buckets, distinct rules hit and the raw weighted score.
- `scannerCoverage(analysis, rules)`: fired and silent rules, per-policy coverage and isolated engine-error findings.
- `analysisSignature(analysis)`: a stable uint32 hash of the serialized findings and score, not a digital signature.

The center panel shows these values in the **Deterministic Scan Diagnostics** strip, and the dry-run chart prints peak, settled, safe path, recovery ratio, latency saved and the exact curve seed. The full structured breakdown, coverage, fingerprint and modeled curve summary are included in the diagnostic audit JSON export with an explicit note that the curves are modeled, not measured.

## Honest receipts and exports

The local receipt panel uses WebCrypto SHA-256 over the actual proposal and policy findings and reports measured analysis time. It explicitly records that no cloud connection or execution occurred.

Previously displayed gVisor lifecycle, memory, runtime and container-destruction numbers were not execution evidence. They have been removed. A SHA-256 digest detects a change to the serialized material; it is not a signature or an attestation from a trusted cloud runner.

Diagnostic JSON and Markdown exports are unsigned and labelled that way. SARIF exports remain available for rule diagnostics. Do not publish an export containing private pasted source or credentials.

## Judge walkthrough

1. Load a scenario and inspect its labelled simulated telemetry.
2. Edit the proposal and inspect deterministic text findings.
3. Read the diagnostics strip: findings, blocking severity, fired rules, distinct rules, affected resources, raw weighted score, scanner errors and modeled peak p95.
4. Click a structured manifest preset and watch the offline gate permit or deny it.
5. Inject a destructive command, then click **Apply Safe Fix** to see the score collapse.
6. Replay the dry-run and confirm the printed seed and curve summary never change.
7. Generate a local receipt and independently verify its SHA-256 format.

## Competition positioning

The strongest demonstrated contribution is the separation between generated plans, mathematical verification and a typed authorization boundary. The action-group adapter is a contract; cloud execution is not implemented.

Local engineering specs and an automated test hook are retained, with no fabricated usage log. Contest eligibility and any required provider use must be checked against current rules before entry. No winning or participant status is implied.

## Project layout

```
index.html              the three column studio
styles.css              dark mission control visual system
gate.py                 Python default-deny decision engine
action_handler.py       offline function action-group response adapter
js/manifest-gate.js     browser default-deny decision engine
js/policy-engine.js     deterministic heuristic scanner and blast scoring
js/telemetry.js         deterministic curves, breakdown, coverage, fingerprint
js/scenarios.js         four illustrative incidents plus a custom composer
js/app.js               controller, topology, chart, diagnostics, exports
js/vultr-sandbox.js     honest local analysis receipts
tests/                  Node and Python regression, parity and UI contract suites
```

## License

MIT.

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
