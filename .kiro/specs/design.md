# BlastRadius Zero - Architecture & Design Specification

## 1. Three-Stage Deterministic Gatekeeper Pipeline
1. **Stage 1 (Incident Telemetry & Swarm Proposal Ingestion):** Ingests P95 latency, error-rate spikes, and multi-agent remediation proposals from AWS Bedrock AgentCore, Vultr Serverless Inference, or open-weight models.
2. **Stage 2 (Deterministic AST & Blast-Radius Simulator):** Evaluates 5 orthogonal policy rules (`POL-DESTRUCT-01`, `POL-IAM-02`, `POL-NET-03`, `POL-EXFIL-04`, `POL-QUOTA-05`) and computes cascading blast radius across the 10-node infrastructure dependency DAG.
3. **Stage 3 (Shadow Dry-Run & Zero-Downtime Remediation Synthesis):** Rewrites unsafe commands into canary/rolling/snapshot-first alternatives, simulates P95 latency & error-rate recovery curves, and exports JSON/Markdown/SARIF audit bundles.

## 2. Data Model
- `Scenario`: `{ id, title, severity, metrics, logs, agents, unsafeProposal, safeRemediation, affectedNodes }`
- `EvaluationResult`: `{ score, verdict, findings[], policyStatuses{}, affectedNodes[], synthesizedSafePlan }`
