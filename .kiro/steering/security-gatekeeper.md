# Kiro Steering Rules - BlastRadius Zero

## Core Engineering Principles
1. **Containment First:** Never execute raw LLM-generated infrastructure commands on the host runtime. Every command must pass `PolicyEngine.analyzeProposal()` before dispatch.
2. **Deterministic Verification:** All blast-radius scoring, AST pattern matching, and dependency graph traversal must be 100% deterministic, offline-capable, and side-effect free.
3. **Zero Credentials in Sandbox:** Ephemeral verification containers must run with `--network=none` and `env_mounted=0` so API keys and cloud credentials cannot be exfiltrated.
4. **Accessible & Auditable UI:** Maintain high-contrast dark telemetry surfaces (`#0A0E17`), `tabular-nums` alignment on all numeric metrics, and verifiable SARIF 2.1.0 export bundles.
