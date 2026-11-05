# BlastRadius Zero policy requirements

## Scope

Structured authorization and heuristic diagnostics. No host, cloud or container action is executed by the studio.

## EARS requirements

- WHEN a manifest kind or field is unknown, THE SYSTEM SHALL deny authorization.
- WHEN a path is outside the canonical virtual scope, THE SYSTEM SHALL deny the action.
- WHEN deletion is requested without a permitted preview, THE SYSTEM SHALL deny the action.
- WHEN compute cost exceeds the exact per-replica cap, THE SYSTEM SHALL deny the action.
- WHEN network access is requested, THE SYSTEM SHALL deny it under the default offline policy.
- WHEN the scanner faults, THE SYSTEM SHALL produce a blocking finding rather than a clean result.
- WHEN a local receipt is generated, THE SYSTEM SHALL report real digest and timing evidence and SHALL identify execution as not performed.

## Acceptance evidence

Python/browser policy parity, invalid schemas, boundary values, scanner faults and genuine SHA-256 receipts are covered by regression tests. Bedrock response shape is contract-tested without a deployment claim. Actual Kiro use and entrant eligibility require separate evidence.
