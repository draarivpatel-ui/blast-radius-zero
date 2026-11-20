/**
 * BlastRadius Zero - Deterministic Policy Engine
 * Heuristic text scanner for shell / SQL / Terraform / JSON.
 * Pure deterministic, offline pattern analysis with no remote calls.
 * Exposes: window.BlastPolicy.analyze(text) -> { score, violations, affectedResources, findings }
 *
 * The scanner is a fast heuristic. It is deliberately conservative: it would
 * rather flag a quoted example than wave through a destructive command.
 * It is not a shell, SQL or Terraform parser, and it never executes anything.
 */

(function () {
  "use strict";

  // ── Policy definitions ───────────────────────────────────────────────
  const POLICIES = [
    { id: "POL-01", name: "No Unbounded Deletion", short: "No Unbounded Delete" },
    { id: "POL-02", name: "Least Privilege IAM", short: "Least Privilege" },
    { id: "POL-03", name: "Cost Cap <= $50/hr", short: "Cost Cap" },
    { id: "POL-04", name: "Zero Secret Exfiltration", short: "No Exfiltration" },
  ];

  // ── Resource catalogue ──────────────────────────────────────────────
  const ALL_RESOURCES = [
    { id: "lb", label: "Load Balancer", kind: "network" },
    { id: "gpu", label: "GPU Cluster", kind: "compute" },
    { id: "compute", label: "Vultr Compute", kind: "compute" },
    { id: "postgres", label: "Primary Postgres", kind: "database" },
    { id: "redis", label: "Redis Cluster", kind: "cache" },
    { id: "iam", label: "IAM Roles", kind: "security" },
    { id: "secrets", label: "Secrets / Env", kind: "security" },
    { id: "storage", label: "Object Storage", kind: "storage" },
  ];

  // ── Helpers ──────────────────────────────────────────────────────────
  function lineNo(text, idx) {
    return text.slice(0, idx).split("\n").length;
  }

  /*
   * Length-preserving normalization. Newline positions never move, so a
   * finding's line number always points at the same line in the editor.
   * Comment bodies become spaces so obfuscated tokens inside /* ... *\/
   * cannot hide a rule, while the original snippet is kept for display.
   */
  function normalize(text) {
    return String(text == null ? "" : text)
      .replace(/[\u0000​-‏﻿]/g, " ")
      .replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, " "))
      // Escapes never span lines, so shrinking them preserves line numbers.
      .replace(/\\u([0-9a-fA-F]{4})/g, (all, hex) => String.fromCharCode(parseInt(hex, 16)))
      .replace(/[！-～]/g, ch =>
        String.fromCharCode(ch.charCodeAt(0) - 0xfee0));
  }

  function isDocLine(text, line) {
    if (!(line > 0)) return false;
    const src = String(text == null ? "" : text).split("\n")[line - 1] || "";
    return /^\s*(?:#|--|\/\/|\*|echo\s|printf\s)/i.test(src);
  }

  function rmParts(cmd) {
    const flags = (cmd.match(/-(?:[A-Za-z][A-Za-z0-9]*|-[\w-]+)/g) || []).join(" ");
    const lower = flags.toLowerCase();
    const recursive = /(^|\s)-[a-z]*r/.test(lower) || /--recursive/.test(lower);
    const force = /(^|\s)-[a-z]*f/.test(lower) || /--force/.test(lower);
    const args = cmd.replace(/-(?:[A-Za-z][A-Za-z0-9]*|-[\w-]+)/g, " ")
      .split(/\s+/).filter(Boolean);
    return { recursive, force, args };
  }

  function rmTouchesRoot(parts) {
    return parts.args.some(a => a === "/" || a.startsWith("/*"));
  }

  function rmTouchesAbsolute(parts) {
    return parts.args.some(a => a.startsWith("/"));
  }

  function rmCommandHits(text, rule, message, wantRoot) {
    const hits = [];
    const re = /(?:^|[\s;&|])((?:(?:sudo|env)\s+)?(?:\/bin\/)?(?:sudo\s+)?rm\b[^\n|;&]*)/gim;
    let m;
    while ((m = re.exec(text))) {
      const cmd = m[1];
      const lineStart = text.lastIndexOf("\n", m.index) + 1;
      const prefix = text.slice(lineStart, m.index);
      if (/^\s*(?:echo|printf|#|--|\/\/|\*)/i.test(prefix)) continue;
      const parts = rmParts(cmd);
      if (!parts.recursive) continue;
      const root = rmTouchesRoot(parts);
      if (wantRoot) {
        // Root, root globs and shell-expanded home directories all count.
        if (!root && !/\$HOME|\$\{HOME\}|~(?:\/|$)/.test(cmd)) continue;
      } else {
        // Non-root forced deletion of an absolute path or an environment var.
        if (root) continue;
        if (!parts.force) continue;
        if (!rmTouchesAbsolute(parts) && !/\$HOME|\$\{HOME\}|~(?:\/|$)/.test(cmd)) continue;
      }
      hits.push(hit(rule, text, { 0: cmd, index: m.index + m[0].indexOf(cmd) }, message));
    }
    return hits;
  }

  function numeric(text) {
    const n = Number(text);
    return Number.isFinite(n) ? n : 0;
  }

  // ── Rule implementations ───────────────────────────────────────────
  // Each rule: { id, policy, severity(1-10), test(text)->finding[] }
  // finding: { rule, policy, severity, message, line, remediation }

  const RULES = [
    // ── POL-01 : No Unbounded Deletion ──────────────────────────────
    {
      id: "R01-rm-rf",
      policy: "POL-01",
      severity: 10,
      label: "Recursive filesystem deletion",
      test(text) {
        // Any flag order, wrappers (sudo, env, /bin/), grouped short flags and
        // long flags are covered. Only root or root-glob targets count here.
        return rmCommandHits(text, this,
          "Unbounded filesystem deletion - would destroy host filesystem", true);
      }
    },
    {
      id: "R01-rm-rf-any",
      policy: "POL-01",
      severity: 9,
      label: "Recursive rm -rf",
      test(text) {
        // Non-root recursive forced deletion is still dangerous. Root cases
        // are reported once by R01-rm-rf, never twice.
        return rmCommandHits(text, this,
          "Recursive forced deletion requires an explicit allowlist", false);
      }
    },
    {
      id: "R01-drop-table",
      policy: "POL-01",
      severity: 10,
      label: "DROP TABLE",
      test(text) {
        const re = /\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?["'`\w.]+/gi;
        return matchRule(text, re, this, "Irreversible DROP TABLE - use expand-contract migration");
      }
    },
    {
      id: "R01-drop-column",
      policy: "POL-01",
      severity: 9,
      label: "DROP COLUMN",
      test(text) {
        const re = /\bALTER\s+TABLE\s+[^;]+\bDROP\s+COLUMN\b[^;]*/gi;
        return matchRule(text, re, this, "DROP COLUMN is non-reversible - use phased column deprecation");
      }
    },
    {
      id: "R01-drop-database",
      policy: "POL-01",
      severity: 10,
      label: "DROP DATABASE",
      test(text) {
        const re = /\bDROP\s+DATABASE\s+["'`\w-]+/gi;
        return matchRule(text, re, this, "DROP DATABASE - catastrophic data loss");
      }
    },
    {
      id: "R01-drop-schema",
      policy: "POL-01",
      severity: 10,
      label: "DROP SCHEMA",
      test(text) {
        const re = /\bDROP\s+SCHEMA\b[^;\n]*/gi;
        return matchRule(text, re, this, "DROP SCHEMA cascades to every object it contains");
      }
    },
    {
      id: "R01-truncate",
      policy: "POL-01",
      severity: 9,
      label: "TRUNCATE TABLE",
      test(text) {
        const re = /\bTRUNCATE\s+(?:TABLE\s+)?["'`\w.]+/gi;
        return matchRule(text, re, this, "TRUNCATE TABLE - unbounded row deletion without WHERE clause");
      }
    },
    {
      id: "R01-delete-no-where",
      policy: "POL-01",
      severity: 8,
      label: "DELETE without WHERE",
      test(text) {
        const re = /\bDELETE\s+FROM\s+["'`\w.]+\s*(?:;|\n|$|LIMIT\s+\d+)/gi;
        const hits = [];
        let m;
        while ((m = re.exec(text))) {
          if (!/WHERE/i.test(m[0])) {
            hits.push(hit(this, text, m,
              `DELETE without WHERE clause - would remove all rows: \`${m[0].trim().slice(0, 70)}\``));
          }
        }
        return hits;
      }
    },
    {
      id: "R01-flushall",
      policy: "POL-01",
      severity: 8,
      label: "Redis FLUSHALL",
      test(text) {
        const re = /\bFLUSHALL\b|\bFLUSHDB\b/gi;
        return matchRule(text, re, this, "Redis FLUSHALL/FLUSHDB - wipes entire cache, causes thundering-herd stampede");
      }
    },
    {
      id: "R01-find-delete",
      policy: "POL-01",
      severity: 10,
      label: "find -delete",
      test(text) {
        const re = /\bfind\b[^\n]*\s(?:-delete\b|-exec\b[^\n]*\brm\b)/gi;
        return matchRule(text, re, this, "find -delete is an unbounded recursive deletion");
      }
    },
    {
      id: "R01-disk-wipe",
      policy: "POL-01",
      severity: 10,
      label: "Disk wipe",
      test(text) {
        const re = /\b(?:shred|wipefs|mkfs(?:\.[\w-]+)?|dd\s+if=[^\n]*of=\/dev\/)\b[^\n]*/gi;
        return matchRule(text, re, this, "Destructive disk operation - irreversible device wipe");
      }
    },
    {
      id: "R01-kubectl-delete-ns",
      policy: "POL-01",
      severity: 9,
      label: "kubectl delete namespace",
      test(text) {
        const re = /\bkubectl\s+delete\s+(?:ns|namespace)\b[^\n]*/gi;
        return matchRule(text, re, this, "kubectl delete namespace - destroys all workloads in namespace");
      }
    },
    {
      id: "R01-kubectl-delete-all",
      policy: "POL-01",
      severity: 9,
      label: "kubectl delete --all",
      test(text) {
        const re = /\bkubectl\s+delete[^\n]*--all\b[^\n]*/gi;
        return matchRule(text, re, this, "kubectl delete --all - unbounded resource deletion");
      }
    },
    {
      id: "R01-terraform-destroy",
      policy: "POL-01",
      severity: 9,
      label: "terraform destroy",
      test(text) {
        const re = /\bterraform\s+destroy\b[^\n]*/gi;
        return matchRule(text, re, this, "terraform destroy - deletes all managed infrastructure");
      }
    },

    // ── POL-02 : Least Privilege IAM ────────────────────────────────
    {
      id: "R02-iam-wildcard-action",
      policy: "POL-02",
      severity: 10,
      label: "IAM wildcard action (iam:*)",
      test(text) {
        const hits = [];
        const seen = new Set();
        let m;
        const precise = /["']iam:\*["']|action\s*=\s*["']iam:\*["']|actions\s*=\s*\[[^\]]*iam:\*[^\]]*\]/gi;
        while ((m = precise.exec(text))) {
          hits.push(hit(this, text, m, "IAM wildcard action `iam:*` - grants full IAM control"));
          for (let i = m.index; i < m.index + m[0].length; i++) seen.add(i);
        }
        // Bare iam:* in shell, HCL or prose about a policy statement.
        const bare = /\biam:\*/gi;
        while ((m = bare.exec(text))) {
          if (seen.has(m.index)) continue;
          hits.push(hit(this, text, m, "IAM wildcard action `iam:*` in policy statement"));
          seen.add(m.index);
        }
        const admin = /aws\s+iam\s+attach[^\n]*AdministratorAccess|policy_arn\s*=\s*["'][^"']*AdministratorAccess["']/gi;
        while ((m = admin.exec(text))) {
          if (seen.has(m.index)) continue;
          hits.push(hit(this, text, m, "AdministratorAccess policy attachment - full account takeover"));
          seen.add(m.index);
        }
        return hits;
      }
    },
    {
      id: "R02-admin-access",
      policy: "POL-02",
      severity: 10,
      label: "AdministratorAccess",
      test(text) {
        const re = /\bAdministratorAccess\b/gi;
        return matchRule(text, re, this, "AdministratorAccess grant - violates least-privilege principle");
      }
    },
    {
      id: "R02-action-all",
      policy: "POL-02",
      severity: 10,
      label: 'Action "*"',
      test(text) {
        const re = /\baction["']?\s*[:=]\s*["']\*["']/gi;
        return matchRule(text, re, this, 'Action "*" grants every API operation');
      }
    },
    {
      id: "R02-wildcard-resource",
      policy: "POL-02",
      severity: 8,
      label: 'IAM Resource "*"',
      test(text) {
        const re = /\bresource\s*=\s*["']\*["']|"Resource"\s*:\s*["']\*["']/gi;
        return matchRule(text, re, this, 'IAM Resource "*" - policy applies to every resource in the account');
      }
    },
    {
      id: "R02-assume-role-wildcard",
      policy: "POL-02",
      severity: 9,
      label: "sts:AssumeRole wildcard",
      test(text) {
        const re = /\bsts:AssumeRole[^"']*["'][^"']*\*[^"']*["']/gi;
        const re2 = /\bAction[^\n]*sts:\*/gi;
        let hits = matchRule(text, re, this, "sts:AssumeRole with wildcard - privilege escalation vector");
        hits = hits.concat(matchRule(text, re2, { ...this, severity: 8 }, "sts:* wildcard - overly broad STS permission"));
        return hits;
      }
    },

    // ── POL-03 : Cost Cap ───────────────────────────────────────────
    {
      id: "R03-gpu-scale",
      policy: "POL-03",
      severity: 9,
      label: "GPU autoscale / spinup",
      test(text) {
        const hits = [];
        const num = "(\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?)";
        const patterns = [
          { re: new RegExp("replicas\\s*=" + num, "gi"), threshold: 5, msg: n => `Replica count ${n} exceeds cost-safe limit` },
          { re: new RegExp("count\\s*=" + num + "[^\\n]*gpu", "gi"), threshold: 4, msg: n => `GPU count ${n} - estimated cost breach` },
          { re: new RegExp("gpus?\\s*[:=]\\s*" + num, "gi"), threshold: 4, msg: n => `GPU allocation ${n} exceeds budget` },
        ];
        for (const p of patterns) {
          let m;
          while ((m = p.re.exec(text))) {
            const n = numeric(m[1]);
            if (n > p.threshold) hits.push(hit(this, text, m, p.msg(n)));
          }
        }
        const gpuRe = /\b(?:vultr[^\n]*gpu[^\n]*(?:spinup|create|deploy|provision)|gpu[^\n]*cluster[^\n]*spinup|spinup[^\n]*gpu)\b/gi;
        let m;
        while ((m = gpuRe.exec(text))) {
          hits.push(hit(this, text, m, "GPU cluster spinup detected - verify cost cap before approval"));
        }
        const costRe = /\$\s*[\d,]+\s*\/\s*hr/gi;
        while ((m = costRe.exec(text))) {
          const val = numeric(m[0].replace(/[^0-9.]/g, ""));
          if (val > 50) hits.push(hit(this, text, m, `Estimated cost ${m[0].trim()} exceeds $50/hr cap`));
        }
        const tfCount = /\bresource\s+"[^"]+"\s+"[^"]+"\s*\{[^}]*?\bcount\s*=\s*(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/gi;
        while ((m = tfCount.exec(text))) {
          const n = numeric(m[1]);
          if (n > 10) hits.push(hit(this, text, m, `Terraform count = ${n} - potential cost explosion`));
        }
        return hits;
      }
    },
    {
      id: "R03-unbounded-autoscale",
      policy: "POL-03",
      severity: 7,
      label: "Unbounded autoscale",
      test(text) {
        const re = /\bmaxReplicas\s*:\s*(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|max_replicas\s*=\s*(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|autoscal\w+[^\n]*max[^\n]*(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/gi;
        const hits = [];
        let m;
        while ((m = re.exec(text))) {
          const n = numeric(m[1] || m[2] || m[3]);
          if (n > 20) hits.push(hit(this, text, m, `Autoscale maxReplicas=${n} - unbounded scaling risk`));
        }
        return hits;
      }
    },

    // ── POL-04 : Zero Secret Exfiltration ───────────────────────────
    {
      id: "R04-curl-exfil",
      policy: "POL-04",
      severity: 10,
      label: "curl exfiltration",
      test(text) {
        const hits = [];
        let m;
        const curlRe = /\bcurl\b[^\n]*/gi;
        while ((m = curlRe.exec(text))) {
          const line = m[0];
          const hasSecretRef = /\$(?:\{)?[A-Z_]*(?:SECRET|TOKEN|KEY|PASSWORD|ENV|CREDENTIAL|AWS_|GITHUB_)/.test(line)
            || /\benv\b/i.test(line) || /\$\(/.test(line);
          const hasExternal = /https?:\/\//.test(line);
          const hasPipe = /\|\s*(?:bash|sh|python|node)\b/.test(line);
          const hasAtFile = /(?:^|\s)(?:-d|--data(?:-binary)?|--form|-F)\s+@[^\s"']+/.test(line);
          if ((hasExternal && (hasSecretRef || hasAtFile)) || hasPipe) {
            hits.push(hit(this, text, m,
              `Potential secret exfiltration via curl: \`${line.trim().slice(0, 90)}\``));
          } else if (hasExternal && /exfil|attacker|ngrok|oast|burpcollaborator|webhook/i.test(text)) {
            hits.push(hit(this, text, m, "curl to external host in untrusted context - possible exfiltration"));
          }
        }
        const mdExfil = /!\[[^\]]*\]\([^)]*\$\{?[A-Z_]+[^)]*\)/gi;
        while ((m = mdExfil.exec(text))) {
          hits.push(hit(this, text, m, "Markdown image with secret interpolation - covert exfiltration channel"));
        }
        return hits;
      }
    },
    {
      id: "R04-env-dump",
      policy: "POL-04",
      severity: 9,
      label: "Environment dump",
      test(text) {
        const re = /\bprintenv\b[^\n]*|\b(?:env|printenv)\b[^\n]*\|\s*(?:base64|curl|nc)\b|\bexport\b[^\n]*\|\s*curl\b|\bcat\s+\/proc\/self\/environ\b/gi;
        return matchRule(text, re, this, "Environment variable dump - would expose secrets");
      }
    },
    {
      id: "R04-secret-in-url",
      policy: "POL-04",
      severity: 9,
      label: "Secret in URL",
      test(text) {
        const re = /https?:\/\/[^\s"'`]*[?&](?:token|key|secret|password|api_key)=[^\s"'`&]+/gi;
        return matchRule(text, re, this, "Secret material embedded in URL query string");
      }
    },
    {
      id: "R04-egress-channel",
      policy: "POL-04",
      severity: 10,
      label: "Covert egress channel",
      test(text) {
        const re = /\b(?:nc|ncat|netcat|socat)\b[^\n]*<\s*[^\s]*|\/dev\/tcp\/|\b(?:bash|sh|zsh)\b[^\n]*-i\b[^\n]*>\s*&\s*\/dev\/tcp/gi;
        return matchRule(text, re, this, "Covert network egress or reverse shell - blocks all outbound channels");
      }
    },
    {
      id: "R04-wget-exfil",
      policy: "POL-04",
      severity: 10,
      label: "wget exfiltration",
      test(text) {
        const re = /\bwget\b[^\n]*/gi;
        const hits = [];
        let m;
        while ((m = re.exec(text))) {
          if (/\$(?:\{)?[A-Z_]*(?:SECRET|TOKEN|KEY|PASSWORD)/.test(m[0]) || /https?:\/\//.test(m[0])) {
            hits.push(hit(this, text, m, `wget with secret/external URL: \`${m[0].trim().slice(0, 80)}\``));
          }
        }
        return hits;
      }
    },
  ];

  // ── Shared helpers ─────────────────────────────────────────────────
  function hit(rule, text, match, message) {
    return {
      rule: rule.id,
      policy: rule.policy,
      severity: rule.severity,
      label: rule.label,
      message: message || match[0].trim().slice(0, 120),
      snippet: match[0].trim().slice(0, 140),
      line: lineNo(text, match.index),
      remediation: remediationFor(rule.id),
      _start: match.index,
      _len: match[0].length,
    };
  }

  function matchRule(text, re, rule, message) {
    const hits = [];
    let m;
    while ((m = re.exec(text))) {
      hits.push(hit(rule, text, m, message));
    }
    return hits;
  }

  function remediationFor(ruleId) {
    const map = {
      "R01-rm-rf": "Replace with scoped delete targeting an explicit path allowlist; require --dry-run preview.",
      "R01-rm-rf-any": "Scope deletion to an allowlisted directory; add pre-flight `ls` dry-run.",
      "R01-drop-table": "Use expand-contract: create new table, dual-write, backfill, cutover, then drop in a later release.",
      "R01-drop-column": "Add new column nullable, backfill, switch reads, then drop old column in next release.",
      "R01-drop-database": "Never auto-drop databases; require manual approval and a snapshot restore point.",
      "R01-drop-schema": "Migrate objects individually; require explicit approval and a restorable snapshot.",
      "R01-truncate": "Use batched DELETE with LIMIT + WHERE predicate; or create replacement table.",
      "R01-delete-no-where": "Add explicit WHERE clause or use LIMIT 1; require row-count preview.",
      "R01-flushall": "Use token-bucket coalescing and read-replica autoscale; never flush cache under load.",
      "R01-find-delete": "Target an explicit allowlist and preview matched paths before any recursive delete.",
      "R01-disk-wipe": "Require a separately approved maintenance window and verified device identifier.",
      "R01-kubectl-delete-ns": "Cordon and drain, then delete workloads individually with PDBs respected.",
      "R01-kubectl-delete-all": "Target specific label selectors; require namespace and resource-type scope.",
      "R01-terraform-destroy": "Use targeted `terraform destroy -target=...` after state backup.",
      "R02-iam-wildcard-action": "Replace `iam:*` with explicit action list such as `iam:GetRole` or `iam:ListRoles`.",
      "R02-admin-access": "Grant minimal managed policy with a permission boundary.",
      "R02-action-all": "Replace the wildcard action with the exact API calls the task needs.",
      "R02-wildcard-resource": "Scope Resource to specific ARNs instead of a wildcard.",
      "R02-assume-role-wildcard": "Restrict `sts:AssumeRole` to specific role ARNs.",
      "R03-gpu-scale": "Cap replicas at budget limit; require cost-approval gate for GPU scale above the cap.",
      "R03-unbounded-autoscale": "Set maxReplicas ceiling aligned to cost cap; add HPA with cost webhook.",
      "R04-curl-exfil": "Block outbound curl/wget in agent sandbox; redact secrets before any network call.",
      "R04-env-dump": "Never dump env; use scoped secret accessor with audit log.",
      "R04-secret-in-url": "Move secrets to Authorization header or env; never embed in URL.",
      "R04-egress-channel": "Disable raw sockets and reverse shells in the agent sandbox; allowlist destinations.",
      "R04-wget-exfil": "Block outbound wget in sandbox; strip secrets before network egress.",
    };
    return map[ruleId] || "Review and apply least-privilege / safe-default remediation.";
  }

  // ── Blast radius scoring ───────────────────────────────────────────
  function scoreFromFindings(findings) {
    if (findings.length === 0) return 0;
    let raw = 0;
    for (const f of findings) raw += f.severity * 3.2;
    const policyCount = new Set(findings.map(f => f.policy)).size;
    raw += (policyCount - 1) * 6;
    const floor = findings.some(f => f.severity >= 8) ? 35 : 12;
    return Math.min(100, Math.max(floor, Math.round(raw)));
  }

  function affectedFromFindings(findings) {
    if (findings.length === 0) return [];
    const policyToResources = {
      "POL-01": ["postgres", "compute", "storage", "redis"],
      "POL-02": ["iam", "compute", "secrets"],
      "POL-03": ["gpu", "compute", "lb"],
      "POL-04": ["secrets", "iam", "compute"],
    };
    const ruleToResources = {
      "R01-flushall": ["redis"],
      "R01-rm-rf": ["compute", "storage"],
      "R01-rm-rf-any": ["compute", "storage"],
      "R01-drop-table": ["postgres"],
      "R01-drop-column": ["postgres"],
      "R01-drop-database": ["postgres"],
      "R01-drop-schema": ["postgres"],
      "R01-truncate": ["postgres"],
      "R01-delete-no-where": ["postgres"],
      "R01-find-delete": ["storage", "compute"],
      "R01-disk-wipe": ["compute", "storage"],
      "R02-iam-wildcard-action": ["iam", "secrets"],
      "R02-admin-access": ["iam", "secrets", "compute"],
      "R02-action-all": ["iam", "secrets"],
      "R02-wildcard-resource": ["iam", "secrets"],
      "R03-gpu-scale": ["gpu", "compute"],
      "R04-curl-exfil": ["secrets", "iam"],
      "R04-env-dump": ["secrets"],
      "R04-egress-channel": ["secrets", "iam", "compute"],
    };
    const ids = new Set();
    for (const f of findings) {
      const specific = ruleToResources[f.rule];
      if (specific) specific.forEach(id => ids.add(id));
      else (policyToResources[f.policy] || []).forEach(id => ids.add(id));
    }
    return [...ids];
  }

  function emptyPolicyStates() {
    return POLICIES.map(p => ({ ...p, status: "pass", count: 0 }));
  }

  function buildPolicyStates(findings) {
    const byPolicy = {};
    for (const f of findings) {
      byPolicy[f.policy] = byPolicy[f.policy] || [];
      byPolicy[f.policy].push(f);
    }
    return POLICIES.map(p => {
      const hits = byPolicy[p.id] || [];
      if (hits.length === 0) return { ...p, status: "pass", count: 0 };
      const maxSev = Math.max(...hits.map(h => h.severity));
      return { ...p, status: maxSev >= 8 ? "block" : "warn", count: hits.length, maxSeverity: maxSev };
    });
  }

  // ── Public API ─────────────────────────────────────────────────────
  function analyze(text) {
    const input = String(text == null ? "" : text).trim();
    if (!input) {
      return { score: 0, violations: [], findings: [], affected: [], clean: true, policyStates: emptyPolicyStates() };
    }
    const norm = normalize(input);
    const findings = [];
    for (const rule of RULES) {
      try {
        const hits = rule.test(norm);
        if (hits && hits.length) findings.push(...hits);
      } catch (_) {
        findings.push({
          rule: "ENGINE-ERROR", policy: "POL-01", severity: 10,
          label: "Analysis failed", message: "Rule evaluation failed; approval denied",
          snippet: "", line: 0, remediation: "Repair the scanner before approving this plan",
        });
      }
    }
    // Recover the original snippet when normalization preserved offsets.
    // Unicode escape decoding can shift columns, so keep the normalized
    // snippet in that case; it still shows the decoded dangerous command.
    const offsetsStable = input.length === norm.length;
    for (const f of findings) {
      if (typeof f._start === "number") {
        if (offsetsStable) {
          f.snippet = input.slice(f._start, f._start + f._len).trim().slice(0, 140) || f.snippet;
        }
        delete f._start;
        delete f._len;
      }
    }
    // Quoted documentation and shell echoes are not proposed actions.
    const kept = findings.filter(f => f.rule === "ENGINE-ERROR" || !isDocLine(input, f.line));
    const seen = new Set();
    const deduped = kept.filter(f => {
      const k = f.rule + ":" + f.line + ":" + f.snippet.slice(0, 40);
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });

    const score = scoreFromFindings(deduped);
    const affected = affectedFromFindings(deduped);
    const policyStates = buildPolicyStates(deduped);
    const violations = [...new Set(deduped.map(f => f.policy))];

    return {
      score,
      violations,
      findings: deduped,
      affected,
      clean: deduped.length === 0,
      policyStates,
    };
  }

  /*
   * What-if view used by the policy toggles. Disabled policies contribute no
   * findings, no score and no affected resources. Engine errors always stay.
   */
  function withDisabledPolicies(analysis, disabled) {
    if (!analysis || !disabled || (disabled.size !== undefined && disabled.size === 0)) return analysis;
    const set = disabled instanceof Set ? disabled : new Set(disabled);
    if (!set.size) return analysis;
    const copy = { ...analysis };
    copy.findings = (analysis.findings || []).filter(f =>
      f.rule === "ENGINE-ERROR" || !set.has(f.policy));
    copy.score = scoreFromFindings(copy.findings);
    copy.violations = [...new Set(copy.findings.map(f => f.policy))];
    copy.affected = affectedFromFindings(copy.findings);
    copy.clean = copy.findings.length === 0;
    copy.policyStates = buildPolicyStates(copy.findings).map(p =>
      set.has(p.id) ? { ...p, status: "off", count: 0, disabled: true } : p);
    copy.disabledPolicies = [...set];
    return copy;
  }

  window.BlastPolicy = {
    analyze, affectedFromFindings, withDisabledPolicies,
    scoreFromFindings, buildPolicyStates, remediationFor,
    POLICIES, ALL_RESOURCES, RULES,
  };

})();
