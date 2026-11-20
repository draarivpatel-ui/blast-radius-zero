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

Both suites run offline. `npm test` expands to `node --test tests/*.test.cjs` and passes **82 tests**. The pytest command passes **72 tests**. Two Python cases rerun the Node suite (a parity check and the demo-script check), so the runner totals overlap. Combined runner total: **154 passing, 0 failures**.

The Node suite now includes `tests/adversarial.test.cjs`, which pins 45 formerly bypassable payloads (flag reordering, SQL comments, unicode escapes, curl `@file` exfiltration, covert egress, exponent-notation costs) as blocked regressions, plus benign-documentation false-positive checks and what-if toggle invariants.

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

## Verdict console

The page opens on one answer: **ALLOW**, **APPROVAL REQUIRED** or **BLOCKED**, with the blast score, the exact rule and line that decided it, and how many findings, policies and resources are involved. A single function (`BlastTelemetry.verdict`) drives the console, the header, the JSON and Markdown audits and the SARIF export, so they can never disagree.

| Verdict | When |
| --- | --- |
| ALLOW | No rule fired |
| APPROVAL REQUIRED | Findings exist, every one is below blocking severity, and the score is under 35 |
| BLOCKED | Any blocking finding, a score of 35 or more, a scanner fault, or a missing analysis |

One-click controls change the plan and the verdict follows:

- **Inject an attack** appends `rm -rf /`, `DROP TABLE`, an `iam:*` wildcard or a `curl` secret exfiltration to the current plan.
- **Load a plan** replaces the editor with a benign rolling restart, a read-only query (both ALLOW) or an autoscaler with a ceiling of 50 (APPROVAL REQUIRED). A test checks each label against the real engine.
- **Contain: apply safe plan** swaps in the scenario's safe plan. All four incident safe plans scan clean (score 0, ALLOW), which a regression test enforces.

The **impact strip** sits directly under the verdict: proposed score and resource count on the left, contained score and count on the right, with a two-bar meter and a plain-language delta. It always compares the unfiltered engine result with the scenario's safe plan, so a what-if toggle can never fake containment.

The **policy toggles** under the blast map let a judge switch each POL on or off live. The console, header, inspector, map, diagnostics and diff all re-run from the filtered analysis; the impact strip remains the unfiltered baseline. Disabling every policy yields an ALLOW what-if view, explicitly a comparison aid, not an authorization.

The **rule inspector** lists every fired rule with its severity and line. Selecting one shows the matched text, policy, effect, the resources it reaches and the fix; the same line is flagged in the plan editor gutter and the reached resources are outlined on the map. The **blast-radius map** toggles between the proposed plan and the state after containment, and says which reached resources are not drawn on the map. On phones the map switches to a two-column layout so labels stay readable without a sideways scroller. Finding line numbers match the editor even when a plan starts with blank lines. The custom composer has no safe plan, so its containment controls are disabled instead of showing a made-up result. The **containment diff** is a line-level diff (longest common subsequence) from the current plan to the safe plan, with the score and verdict change.

All editor text reaches the page through `textContent` or an HTML escaper. A headless Chrome probe typed `<img>`, `<svg onload>`, `<iframe>` and `<script>` payloads into the plan and the manifest field and found no injected element.

## Incident studio

Four illustrative scenarios cover a runaway GPU billing loop, destructive database migration, cache stampede and prompt-injection exfiltration. Editable plans are scanned by the actual policy rules; clean scores are always zero and identical findings receive identical scores. Each scenario's safe plan is prewritten for that scenario and labelled that way; the custom composer has none and says so.

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

Diagnostic JSON and Markdown exports are unsigned and labelled that way. SARIF 2.1.0 exports remain available for rule diagnostics and can now be inspected in-page with the **SARIF view** button. The export includes full rule metadata (help text, help URI, semantic version, tags, base URI, `uriBaseId` and severity-derived levels). Do not publish an export containing private pasted source or credentials.

### Known heuristic limits

The scanner normalizes command and SQL text before matching: it strips comments, decodes Unicode escapes and reorders equivalent shell flags. It deliberately treats quoted documentation that names a destructive command as a finding rather than silently ignoring it. It is not a shell, SQL or infrastructure parser, so a sufficiently creative encoding can still evade it. The structured manifest gate is the actual authorization boundary; the text scan only explains what it sees. The adversarial suite documents both the closed bypasses and the conservative behavior.

## Judge walkthrough

1. Read the verdict console: BLOCKED, score 89, and the rule and line that decided it.
2. Click **Benign: rolling restart** (ALLOW, 0), then **DROP TABLE** (BLOCKED), then **Needs approval: autoscale to 50** (APPROVAL REQUIRED).
3. Pick a rule in the inspector and watch the editor line and the map outline follow it.
4. Open the destructive migration, flip the map to **After containment**, read the diff, then apply the safe plan (ALLOW, 0).
5. Click the typed action gate presets: the test run is allowed, network egress and the path escape are denied.
6. Replay the dry-run and confirm the printed seed and curve summary never change.
7. Generate a local receipt and check its SHA-256 digest.

## Competition positioning

The strongest demonstrated contribution is the separation between generated plans, mathematical verification and a typed authorization boundary. The action-group adapter is a contract; cloud execution is not implemented.

Local engineering specs and an automated test hook are retained, with no fabricated usage log. Contest eligibility and any required provider use must be checked against current rules before entry. No winning or participant status is implied.

## Project layout

```
index.html              verdict console and three column workbench
styles.css              dark security console visual system
gate.py                 Python default-deny decision engine
action_handler.py       offline function action-group response adapter
js/manifest-gate.js     browser default-deny decision engine
js/policy-engine.js     deterministic heuristic scanner and blast scoring
js/telemetry.js         verdict, line diff, containment, curves, breakdown, fingerprint
js/scenarios.js         four illustrative incidents plus a custom composer
js/app.js               controller, topology, chart, diagnostics, exports
js/vultr-sandbox.js     honest local analysis receipts
tests/                  Node and Python regression, parity, UI and demo-script suites
video/                  demo video, narration.txt, steps.json and build_steps.py (regenerates both)
```

## License

MIT.

## November 20 local verification

82 Node tests and 72 Python cases passed, 0 failed (Node v26.8.1, Python 3.9.6, pytest 8.4.2). Two Python cases rerun the Node suite, so the runner totals overlap. The Wave 1 revamp added the impact strip, live policy toggles, SARIF in-page preview, the normalized adversarial scanner and 9 new Node regression tests.

The revamped page was loaded in headless Chrome at 1440x900, 390x844 and 1920x1080. Each capture showed no console error, no failed request, no request outside the page's own origin and no page-level horizontal scroll (long code lines scroll inside the editor and diff boxes). Keyboard Tab order reaches the console controls, the editor toolbar, the map toggle and the map nodes, and Enter on a map node selects the rule that reaches it. The 32-bit analysis value is labeled as a fingerprint, not a digital signature. No physical hardware session was run.

The incident panel, log stream, map and recovery curves are labelled as simulations. No active agent swarm or cloud execution is claimed.
