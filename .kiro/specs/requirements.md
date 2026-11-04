# BlastRadius Zero &mdash; Requirements Specification (Kiro Spec-Driven Architecture)

## 1. Overview
BlastRadius Zero is a deterministic AST & policy gatekeeper for autonomous cloud incident-response and FinOps MSP agents. Every proposed remediation script, Terraform plan, SQL migration, or AWS/Vultr CLI command is intercepted before execution, scored across five deterministic security policies, and verified inside an ephemeral gVisor sandbox.

## 2. EARS Requirements

### REQ-1: Deterministic AST Destructive Command Interception
- **WHEN** an autonomous agent proposes a shell, SQL, Kubernetes, or cloud CLI command, **THE SYSTEM SHALL** parse the command stream deterministically in `< 5 ms` with zero network calls and assign a Blast Score in `[0, 100]`.
- **IF** any command matches a destructive state-loss signature (`rm -rf /`, `DROP TABLE`, `aws rds delete-db-instance --skip-final-snapshot`, `kubectl delete namespace prod`), **THEN THE SYSTEM SHALL** transition the gate status to `BLOCKED` and prevent host execution.

### REQ-2: Privilege Escalation & Secret Exfiltration Prevention
- **WHEN** an agent proposal modifies IAM policies (`iam:*`, `AdministratorAccess`, `sts:AssumeRole` wildcard) or pipes environment variables/metadata (`169.254.169.254`, `env`, `/etc/shadow`) to outbound network sockets (`curl`, `wget`, `nc`), **THE SYSTEM SHALL** flag `POL-IAM-02` and `POL-EXFIL-04` and synthesize a least-privilege, zero-exfiltration alternative.

### REQ-3: Ephemeral Sandbox Containment & Cryptographic Audit Receipts
- **WHEN** a remediation plan is dispatched for verification, **THE SYSTEM SHALL** execute it inside an isolated container (`runsc` gVisor, `--network=none`, `env_mounted=0`, `512 MB` memory cap, `15,000 ms` timeout) and emit a signed JSON/SARIF audit receipt containing the FNV-1a/SHA-256 digest of the blocked vs. safe diff.
