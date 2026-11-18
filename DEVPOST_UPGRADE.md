# BlastRadius Zero submission upgrade

## Inspiration

Autonomous agents now propose real infrastructure changes during incidents. One bad command can drop a table, flush a cache under load or send every secret to an outside host. A safety gate is only convincing if a judge can change the input and watch the decision change for a visible reason. BlastRadius Zero shows that reason in one screen, offline.

## What it does

The page opens on a verdict console: **ALLOW**, **APPROVAL REQUIRED** or **BLOCKED**, the blast score, and the exact rule and line that decided it. One-click controls inject attacks (`rm -rf /`, `DROP TABLE`, an `iam:*` wildcard, a `curl` secret exfiltration), load benign or approval-level plans, and apply the scenario's safe plan. The rule inspector explains every finding (matched text, policy, effect, resources reached, fix) and highlights the same line in the plan editor and the reached resources on the blast-radius map. The map toggles between the proposed plan and the state after containment, and a line diff shows exactly what the safe plan changes. A typed action gate decides structured actions with a default-deny policy, and the page exports unsigned JSON, Markdown and SARIF audits plus a local SHA-256 receipt.

## How we built it

`js/policy-engine.js` runs a heuristic rule scanner that fails closed on rule exceptions. `js/telemetry.js` is a pure module with the verdict function, the line diff, the containment calculation and the deterministic modeled curves (a Mulberry32 generator seeded by an FNV-1a hash of the real findings). `gate.py` and `js/manifest-gate.js` implement the same closed action vocabulary with exact per-replica cost boundaries. `js/app.js` renders only engine outputs, so the interface never invents a number, and it writes every piece of editor text through `textContent` or an HTML escaper.

## Challenges

The safe plans for three of the four incidents still tripped the scanner (scores 60, 35 and 89) because comments mentioned `FLUSHALL` or a dropped column and autoscaler blocks used `replicas = N`. The "apply safe plan" moment therefore never reached a clean result. The plans were rewritten so all four now scan clean, and a regression test keeps it that way.

The header, verdict pill and SARIF export also disagreed for low scores (REVIEW, WARN and BLOCKED for the same plan). One verdict function now drives all of them.

## Accomplishments

- A three-tier verdict that a real one-click plan reaches at every tier.
- A rule inspector linked to the editor gutter and the map.
- Before and after containment on the map plus a line-level containment diff.
- No external script, style, font or image: the page works from a file or any static host.
- An escaping probe in headless Chrome found no injected element from `<img>`, `<svg>`, `<iframe>` or `<script>` payloads.
- A demo script (`video/steps.json`, `video/narration.txt`) whose selectors and test-count claims are checked by tests.

## Verification numbers

Verified on Node v26.8.1 and Python 3.9.6 with pytest 8.4.2:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
npm test
.venv/bin/python -m pytest -q -p no:cacheprovider --import-mode=importlib
```

**73 Node tests passed, 0 failed. 72 Python tests passed, 0 failed.** Two Python cases rerun the Node suite, so the runner totals overlap.

| Check | Verified result |
| --- | --- |
| Node policy, receipt, telemetry, UI contract and console tests | 73 passed |
| Python gate parity, handler, telemetry parity, content and demo-script tests | 72 passed |
| Incident safe plans that scan clean | 4 of 4 (score 0, ALLOW) |
| One-click plan labels that match the engine verdict | 3 of 3 |
| Attack buttons that block a clean plan on their own | 4 of 4 |
| Structured manifest presets | 3 permitted, 2 denied, all agree with the Python gate |
| Headless Chrome captures (1440x900, 390x844, 1920x1080) | 0 console errors, 0 outside requests, no page-level horizontal scroll |
| Injected elements found by the escaping probe | 0 |
| Forbidden dashes, vendor names and disclosures in shipped text | 0 |

## Devpost description

**BlastRadius Zero: a blast-radius firewall for agent-proposed infrastructure changes.** Paste or load a plan and the console answers at once: ALLOW, APPROVAL REQUIRED or BLOCKED, with the exact rule and line that decided it. Inject a `DROP TABLE` or a `curl` secret exfiltration and the verdict flips on the spot. The rule inspector explains every finding, the map shows which resources the plan would reach and what the safe plan contains, and a line diff shows what changes. A typed, default-deny action gate decides structured actions, and every audit export is labelled unsigned. Everything runs offline in one page, with 73 Node tests and 72 Python tests passing.

## What's next

Validate a real downstream executor, replace the heuristic scanner with real shell, SQL and Terraform parsers, and run a deployed adapter against an actual action-group service. Topology, telemetry and recovery curves are deterministic simulations, not production measurements. Receipts are local digests, not signatures from a trusted runner.
