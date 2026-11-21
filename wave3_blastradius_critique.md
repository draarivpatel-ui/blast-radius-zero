# BlastRadius Zero: Wave 3 critique

Scope: `js/policy-engine.js` text scanner, `js/app.js` SARIF builder, `tests/wave3.test.cjs`. Everything below was verified against the live engine in Node, not inferred from reading code. The scanner remains local and deterministic: it executes nothing, calls nothing, and reads only the plan text it is given.

## What probing found

Two probe corpora were run before any fix landed. My own 60-payload adversarial harness scored 54 ALLOW on the Wave 2 engine, including every continuation, quoting, indirection and policy-format vector listed below. The lead-e hydra file (`wave3-lead-e/brz-hydra-probes.md`, 38 probes, BRZ-01 through BRZ-38) was read before implementation and again before commit; its file was unchanged at commit time. Of its 37 scannable payloads, 36 now reach BLOCKED and one (BRZ-26, `templatefile` referencing a destroy script) is a documented boundary: the destructive text lives in a file the plan never contains, so no text scanner can see it. That is what the typed manifest gate is for.

One false positive was confirmed and fixed: `DELETE FROM users` followed by `WHERE id = 1` on the next physical line was flagged as WHERE-less because the old regex stopped at the newline.

## Defects closed

Parser and line mapping (5):

- Backslash-newline continuations are spliced before scanning and every finding maps back to its original physical line, so `rm -rf \` + newline + `/` and `git push \` + newline + `--force` can no longer split a command past the rules.
- The doc-line filter now reads the normalized text, closing the `\u000a` desync where an escaped newline moved a finding onto a `#` comment line and silently dropped it (BRZ-05).
- Quoted, escaped and interleaved command names (`"rm"`, `'rm'`, `\rm`, `r\m`, `/bin/rm` inside JSON strings) resolve to `rm` again.
- ANSI-C `$'...'` quoting is decoded (`\xHH`, octal, `\n`, `\\`, `\'`), braced `\u{...}` escapes decode, and backtick command substitutions are captured as arguments, closing `rm -rf ` + backtick + `echo /` + backtick (BRZ-13/14/15/16/17).

rm target handling (6):

- Lexical path canonicalization resolves `./`, `..`, `//` and trailing slashes before root checks.
- Lowercase and braced variables (`$dir`, `${dir}`, `${root:-/}`, `${!REF}`), positional parameters (`$1`), `~user`/`~+`/`~-`, home globs (`~*`) and command-substitution targets all count as unbounded.
- A new `R01-indirect-command` rule catches `$CMD -rf /` and `${CMD} -rf /` where the command word itself is a variable or substitution, while `echo $CMD -rf /` and other printer arguments stay clean.

Command surface (12):

- `find -execdir`, `-ok`, `-okdir` and non-rm exec payloads.
- `kubectl`/`oc` global flags, plural `namespaces`/`projects`, `--all`/`-A`/`delete all` selector checks, `oc delete project`.
- `terraform`/`tofu`/`tf` global flags (`-chdir`) before `destroy`/`apply -auto-approve`.
- Git: combined `-fu`/`-ufv` flag clusters, `+refspec` forced updates, `--mirror`, `clean --force`, `switch -f`, `--discard-changes`, `checkout .`/`restore .` (new `R01-git-destructive` rule at WARN severity for reviewable discards).
- `xargs` flag variants, `docker ps | xargs docker rm`, remote `curl | sh`, host power commands (`shutdown`, `poweroff`, `reboot`, `halt`, `init 0/6`), `dd of=/dev/...` and device redirects, recursive permissive `chmod`, autoscale ceilings (`maxReplicas`, `max_size`, `MaxSize`, `--max-nodes`, `--max-size`), `count = length(range(...))` computed counts, and `tar | nc` remote extraction.

IAM and Kubernetes policy (8):

- `Action`/`Actions` values are scanned in scalar, array, plural, HCL, YAML, JSON and `jsonencode` forms; service wildcards (`s3:*`, `ec2:*`, `iam:*`) and `sts:AssumeRole*` all flag.
- A bare `"*"` assembled inside an Action value expression (`replace(jsonencode(...), "x", "*")`, `for`/`join` expressions) flags even though no literal `Action = "*"` exists (BRZ-27/28).
- `Resource`/`resources`/`NotResource` get the same treatment: exact `"*"`, `NotResource "*"` inversion review, and `"*"` buried in for-expressions or dynamic blocks (BRZ-30/34).
- ARN wildcards in any quoted position, including inside `Condition` blocks like `aws:PrincipalArn` (BRZ-35).
- New `R02-k8s-rbac-wildcard` rule: `apiGroups`/`verbs`/`resources` set to `"*"`, `cluster-admin` bindings, and the `impersonate`/`bind`/`escalate` privilege-escalation verb set on identity resources (BRZ-32/33).

Exfiltration and SQL (12):

- `nc`/`ncat`/`netcat`/`socat` pipes in both directions, `rsync`/`sftp -b`/`lftp --files-from` scripted transfers, `/proc/N/environ`, bare `env`/`export`/`set`/`printenv` dumps in command position, `compgen -e` pipes, URL userinfo credentials, secret query parameters, and `curl --key`/`--cert`/`-u`/`--netrc-file`/`--oauth2-bearer` credential flags.
- `SELECT ... INTO OUTFILE`/`DUMPFILE` and `LOAD_FILE()` (new `R01-sql-file-io`).
- DELETE analysis now uses statement windows: multiline `WHERE` counts, `WHERE` in a later statement cannot mask a bare DELETE, MySQL multi-table `DELETE u FROM ... JOIN` is covered, `RETURNING` and data-modifying CTEs (`WITH d AS (DELETE ...)`) flag, `0=0`/`2>1`/`id=id`/`TRUE` tautologies flag via `R01-delete-tautology`, `MERGE ... DELETE` flags, comment-split keywords like `DROP-- hidden\nTABLE` flag via `R01-sql-obfuscated`, and `EXECUTE IMMEDIATE`/`EXEC('...')` flag via `R01-sql-exec`.
- NoSQL `deleteMany({})`/`remove({})`/`deleteOne()` empty-filter deletes flag.

Verifier (1):

- SARIF `ruleIndex` no longer aliases unknown rules to index 0. `ENGINE-ERROR` and any future uncatalogued rule get a real driver rule entry, so `ruleId` and `rules[ruleIndex].id` always agree (BRZ-36).

## What survived probing

- `echo "rm -rf / is destructive"`, `echo $CMD -rf /`, `#`/`--`/`//`/`*` comment lines, and `printf` documentation stay clean; the benign corpus in `tests/wave3.test.cjs` pins 30 cases.
- `kubectl rollout restart`, `terraform plan`/`apply tfplan`, `git push origin feature/x`, `docker ps`, scoped IAM actions and resources, `env | grep TERM`, `scp` to an internal log host, `chmod 640` on a secrets file, and graceful `kubectl delete pod --grace-period=30` all stay clean.
- `NotResource: "*"` is flagged for review rather than scored as a wildcard: the inversion usually makes the statement inert, but a gatekeeper should not silently pass it.
- BRZ-26 (`templatefile`/`jsonencode`/`yamldecode` chains that build destructive text at apply time) and BRZ-38 (duplicate JSON keys) are honest limits: the first needs file contents the plan does not contain, the second collapses identically in `JSON.parse` and `json.loads` so JS/Python parity holds.
- A bare `--flag` line still reads as a SQL `--` comment to the doc filter; flags are always caught in real command position.

## Self-score

Wave 2 closed at 9.0/10. This wave removes an entire evasion class (parser-level splitting, encoding and indirection) rather than adding another round of keyword patterns, fixes a confirmed false positive, extends coverage to K8s RBAC and NoSQL surfaces the scanner never modeled, and hardens the SARIF contract. The remaining gaps are architectural (referenced-file contents, runtime-evaluated expressions) and are exactly what the typed action gate exists to bound. Self-score: 9.5/10. The half point stays because a text scanner can never prove a negative, and the demo's honesty depends on saying so.

## Verified counts

- Node: 104/104 passing (`node --test tests/`), including the new `tests/wave3.test.cjs` (11 tests, ~120 payloads).
- Python: 72/72 passing (`pytest`), unchanged.
- Rules: 57 scanner rules (49 before this wave, +8).
- UI: real-pointer CDP verification at 1440x900 and 390x844, zero console errors; scenario switch, what-if toggle, payload inject, finding select, safe-plan swap, and SARIF audit preview all exercised with real mouse events.
