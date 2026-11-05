# BlastRadius Zero

A deterministic action boundary for developer agents, with an interactive cloud-incident diagnostic studio.

The enforcement layer accepts structured actions and denies everything outside its policy. The text scanner helps explain suspicious plans but is a heuristic, not a shell, SQL or Terraform AST parser.

## Run locally

```bash
python3 -m http.server 8000
npm test
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

The static studio needs no backend, provider key or infrastructure account.

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

Compute cost is checked per replica, in integer cents. Five replicas at 1000 cents each meet the hourly boundary; increasing per-replica cost to 1001 cents fails. Unknown keys or action types never inherit a default approval.

These are authorization decisions over descriptions. The project does not execute commands, delete files, grant roles or allocate compute. A downstream executor must enforce the same scope, prevent symlink escapes and avoid translating approved paths into shell strings.

## Actual integration with AWS Bedrock

`bedrock_action_handler.py` implements the Bedrock function-action-group Lambda response contract without an AWS SDK dependency. The function `authorizeAgentAction` accepts one string manifest parameter and returns the deterministic gate decision.

Malformed events fail closed. The handler logs no incoming event or payload and performs no AWS calls. It is locally contract-tested, not a deployed or load-tested AWS service. Deploying it requires a reviewed execution role and the actual provider's configuration.

## Incident studio

Four illustrative scenarios cover a runaway GPU billing loop, destructive database migration, cache stampede and prompt-injection exfiltration. Editable plans are scanned by the actual policy rules; clean scores are always zero and identical findings receive identical scores.

Scanner faults create a blocking finding. Obfuscation can evade a text scanner, and quoted documentation can produce false positives. The research package includes both examples rather than claiming perfect text understanding.

Topology diagrams, incident telemetry and recovery curves are simulations. They are not measurements of a production outage. The companion MuseWeaver verifier supplies the mathematical layer for the combined developer-agent experiment.

## Honest receipts and exports

The local receipt panel uses WebCrypto SHA-256 over the actual proposal and policy findings and reports measured analysis time. It explicitly records that no cloud connection or execution occurred.

Previously displayed gVisor lifecycle, memory, runtime and container-destruction numbers were not execution evidence. They have been removed. A SHA-256 digest detects a change to the serialized material; it is not a signature or an attestation from a trusted cloud runner.

Diagnostic JSON and Markdown exports are unsigned and labelled that way. SARIF exports remain available for rule diagnostics. Do not publish an export containing private pasted source or credentials.

## Judge walkthrough

1. Load a scenario and inspect its labelled simulated telemetry.
2. Edit the proposal and inspect deterministic text findings.
3. Expand Structured Developer Agent Boundary and validate a permitted test action.
4. Change its kind, add an unknown parameter or request network egress to observe denial.
5. Generate a local receipt and independently verify its SHA-256 format.
6. Run the companion free Z3/policy benchmark and inspect the decision ledger.

## Competition positioning

The strongest demonstrated contribution is the separation between generated plans, mathematical verification and a typed authorization boundary. AWS integration is an adapter contract; Vultr execution is not implemented.

Kiro specs and an actual test hook are retained, with no fabricated usage log. Kiroween, AWS MSP AI, Lablab and DoraHacks eligibility and required provider use must be checked against their current rules before entry. No winning or participant status is implied.

MIT licensed. AI-assisted implementation and documentation are disclosed.
