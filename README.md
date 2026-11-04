# BlastRadius Zero - Autonomous Multi-Agent Cloud Incident & Policy Gatekeeper

Deterministic in-browser policy gatekeeper that intercepts unsafe remediation plans proposed by autonomous cloud agents - parses shell / Terraform / SQL / JSON, computes a **Blast Radius Score (0-100)**, highlights affected resources on an interactive topology, and synthesizes a **zero-blast-radius remediation** with shadow dry-run simulation.

Built for **Vultr Agent Rush Hackathon** · **Next Byte Hacks V5** · **Remote Control AI** (Devpost).

---

## Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────────────┐
│  Header · Gate Status · Blast Score · Dry-Run · Export Bundle       │
├─────────────────────────────────────────────────────────────────────┤
│  Scenario Switcher - 4 Incidents + Custom Composer                  │
├──────────────┬──────────────────────────┬───────────────────────────┤
│ ① Incident   │ ② AST & Blast-Radius     │ ③ Shadow Dry-Run &        │
│   Telemetry  │   Simulator              │   Safe Remediation        │
│              │                          │                           │
│ • Metrics    │ • Blast Score ring       │ • Blocked vs Safe diff    │
│ • Log stream │ • 4 Policy cards         │ • Latency / error chart   │
│ • Agent      │ • Resource topology SVG  │ • Audit exports           │
│   proposals  │ • Findings list          │   (JSON / MD / SARIF)    │
│ • Editable   │                          │                           │
│   proposal   │                          │                           │
└──────────────┴──────────────────────────┴───────────────────────────┘
```

No backend, no LLM calls, no build step - pure static site. The policy engine is a deterministic parser that runs entirely in the browser.

---

## Quick Start

```bash
# Clone
git clone <repo-url> blast-radius-zero
cd blast-radius-zero

# Serve (any static server)
npx serve .
# or
python3 -m http.server 8000
# then open http://localhost:8000
```

No install, no env vars, no API keys.

---

## Features

### Scenario Switcher - 4 Realistic Cloud Incidents

| # | Scenario | Risk | What the gatekeeper catches |
|---|----------|------|-----------------------------|
| 1 | **Runaway Recursive Subagent Billing Loop on GPU Cluster** | COST CRITICAL | Cyclic tool-graph, 48× GPU spinup ($14,200/hr), `FLUSHALL` | 
| 2 | **Destructive Production Migration (DROP COLUMN + IAM Wildcard)** | DATA LOSS | `DROP COLUMN`, `iam:*` + `AdministratorAccess`, `DELETE` without `WHERE` |
| 3 | **BGP Route Leak & Redis Cache Stampede** | AVAILABILITY P1 | `FLUSHALL` under thundering-herd, unbounded autoscale (200 replicas), `rm -rf /etc/haproxy` |
| 4 | **Supply-Chain Prompt Injection in PR Triage Agent** | SECURITY P0 | `curl $(env \| base64)` to attacker domain, `iam:*` escalation, `cat /proc/self/environ` exfil |

Plus a **Custom Incident Composer** - define any incident, edit the proposal, and test the gatekeeper live.

### Deterministic Policy Engine (`js/policy-engine.js`)

Real parser covering shell, SQL, Terraform, and JSON:

| Policy | What it blocks |
|--------|----------------|
| **POL-01 No Unbounded Deletion** | `rm -rf`, `DROP TABLE/DATABASE/COLUMN`, `TRUNCATE`, `DELETE` without `WHERE`, `FLUSHALL`, `kubectl delete --all`, `terraform destroy` |
| **POL-02 Least Privilege IAM** | `iam:*`, `AdministratorAccess`, `Resource "*"`, `sts:AssumeRole` wildcards |
| **POL-03 Cost Cap ≤ $50/hr** | GPU scale bursts, replica surges, `count > 10`, `maxReplicas > 20`, `$…/hr` over cap |
| **POL-04 Zero Secret Exfiltration** | `curl`/`wget` with secrets to external hosts, `env | base64 | curl`, markdown image exfil, secrets in URLs |

Each rule reports severity, line number, snippet, and a concrete remediation. Findings are deduplicated and scored into the **Blast Radius Score (0-100)** with affected-resource mapping.

### Interactive Studio

- **Left - Incident Telemetry & Swarm Proposal:** live metrics, log stream, three agent cards (Triage / Infra Patch / Rollback), and a fully **editable proposal editor** - the gatekeeper re-analyzes on every keystroke. Inject chips and quick-inject buttons for testing.
- **Center - Blast-Radius Simulator:** animated score ring, four policy cards (PASS/WARN/BLOCK), interactive SVG topology (Load Balancer → Compute/GPU → Postgres → Redis → IAM → Storage), and detailed findings with remediation guidance.
- **Right - Shadow Dry-Run & Remediation:** side-by-side diff (blocked vs synthesized safe plan), animated latency/error-rate recovery chart (gate block point + safe-path overlay), and **one-click exports**: Signed Audit JSON, Markdown report, and SARIF bundle.

### Exports

- **Signed Audit JSON** - full bundle: scenario, gate status, findings, policy states, raw + safe proposal, HMAC note.
- **Markdown Audit Report** - human-readable tables + code blocks.
- **SARIF 2.1.0** - import into GitHub Code Scanning, VS Code SARIF Viewer, or any SARIF consumer.

---

## File Map

```
blast-radius-zero/
├── index.html          # Mission-control dark UI (header + switcher + 3-column studio)
├── styles.css          # Technical dark theme (#0A0E17 / #3B82F6 / #10B981 / #EF4444 / #F59E0B)
├── js/
│   ├── policy-engine.js  # Deterministic parser + scorer + resource mapper
│   ├── scenarios.js      # 4 incidents + custom template (metrics / logs / topology)
│   └── app.js            # Controller: scenario switching, live analysis, SVG, chart, exports
└── README.md
```

---

## Hackathon Alignment

### Vultr Agent Rush - Autonomous Multi-Agent Systems with Real Guardrails & Cloud Infrastructure Execution

- **Autonomous swarm:** Triage Agent → Infra Patch Agent → Rollback Synthesizer, each with distinct failure modes (cost loop, privilege escalation, destructive fallback).
- **Real guardrails:** deterministic AST/policy engine - not a prompt, not a heuristic. Every violation is a rule with severity, line, and remediation.
- **Cloud execution:** Vultr GPU clusters, Kubernetes autoscalers, Terraform plans, BGP/HAProxy, Redis - modeled concretely per scenario with cost and resource topology.
- **Shadow dry-run:** simulated canary with latency/error recovery curves that diverge at the gate block point.

### Next Byte Hacks V5 & Remote Control AI

- Zero-backend, zero-cost, zero-setup - runs on any device with a browser.
- Fully keyboard-accessible; export bundles for CI/CD integration.

---

## Browser Support

Modern evergreen browsers (Chrome, Firefox, Safari, Edge). No polyfills.

---

*BlastRadius Zero - because autonomous agents should not have autonomous blast radius.*
