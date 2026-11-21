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

  /*
   * An echo/printf line is documentation only when it prints a single quoted
   * literal and nothing else. Chained commands, redirects and interpolated
   * substitutions ($(...), backticks, ${var}) are live actions, never
   * documentation - `echo hi && rm -rf /` must never be exempted.
   */
  function echoDocOnly(src) {
    const m = src.match(/^\s*(?:echo|printf)\s+("([^"\\]|\\.)*"|'([^'\\]|\\.)*')(?:\s*#.*)?$/i);
    return Boolean(m) && !/\$+\(|`|\$\{/.test(m[1]);
  }

  function isDocLine(text, line) {
    if (!(line > 0)) return false;
    const src = String(text == null ? "" : text).split("\n")[line - 1] || "";
    if (/^\s*(?:#|--|\/\/|\*)/i.test(src)) return true;
    return echoDocOnly(src);
  }

  function rmParts(cmd) {
    const flags = (cmd.match(/-(?:[A-Za-z][A-Za-z0-9]*|-[\w-]+)/g) || []).join(" ");
    const lower = flags.toLowerCase();
    const recursive = /(^|\s)-[a-z]*r/.test(lower) || /--recursive/.test(lower);
    const force = /(^|\s)-[a-z]*f/.test(lower) || /--force/.test(lower);
    const args = cmd.replace(/-(?:[A-Za-z][A-Za-z0-9]*|-[\w-]+)/g, " ")
      .split(/\s+/).filter(Boolean)
      .map(a => a.replace(/^["'`(]+|[)"'`]+$/g, ""))
      .filter(Boolean);
    return { recursive, force, args };
  }

  // Root-equivalent targets: /, globs off /, //, the whole tree (., .., ./),
  // bare wildcards (./*, ../*, *), an unknown uppercase environment variable
  // or bare home. Each can expand to an unbounded deletion target.
  function rmTouchesRoot(parts) {
    return parts.args.some(a =>
      a === "/" || a.startsWith("/*") || /^\/{2,}$/.test(a) ||
      /^\.{1,2}\/?$/.test(a) || /^\.{1,2}\/\*$|^\*$/.test(a) ||
      /^\$\{?[A-Z_][A-Z0-9_]*\}?$/.test(a) || a === "~");
  }

  function rmTouchesAbsolute(parts) {
    return parts.args.some(a => a.startsWith("/"));
  }

  // A shell-expanded home or any uppercase variable reference in the command
  // text, even when it is not a standalone argument.
  function rmHasExpandable(cmd) {
    return /~(?:\/|$|\s)|\$\{?[A-Z_][A-Z0-9_]*\}?/.test(cmd);
  }

  function rmCommandHits(text, rule, message, wantRoot) {
    const hits = [];
    // Command words may start after whitespace, chaining (;, &, |), command
    // substitution ($(, `), subshell ( ( ) or grouping ({ - never mid-word.
    const re = /(?:^|[\s;&|(`{])((?:(?:sudo|env)\s+)?(?:\/bin\/)?(?:sudo\s+)?rm\b[^\n|;&`]*)/gim;
    let m;
    while ((m = re.exec(text))) {
      const cmd = m[1];
      const lineStart = text.lastIndexOf("\n", m.index) + 1;
      const prefix = text.slice(lineStart, m.index);
      if (/^\s*(?:#|--|\/\/|\*)/i.test(prefix)) continue;
      if (echoDocOnly(prefix + cmd)) continue;
      const parts = rmParts(cmd);
      if (!parts.recursive) continue;
      const root = rmTouchesRoot(parts);
      if (wantRoot) {
        // Root, root globs and shell-expanded home directories all count.
        if (!root && !rmHasExpandable(cmd)) continue;
      } else {
        // Non-root forced deletion of an absolute path or an environment var.
        if (root) continue;
        if (!parts.force) continue;
        if (!rmTouchesAbsolute(parts) && !rmHasExpandable(cmd)) continue;
      }
      hits.push(hit(rule, text, { 0: cmd, index: m.index + m[0].indexOf(cmd) }, message));
    }
    return hits;
  }

  function numeric(text) {
    const n = Number(text);
    return Number.isFinite(n) ? n : 0;
  }

  /*
   * Comment-split keywords (DR/**\/OP) survive the comment-to-space
   * normalization as spaced-out tokens. When collapsing whitespace reveals
   * a destructive keyword that the plain rules cannot see (and the line was
   * actually changed by collapsing), fire one conservative finding with the
   * original snippet and the real line number.
   */
  function obfuscatedSqlHits(text, rule, message) {
    const hits = [];
    const lines = String(text).split("\n");
    const plain = /DROP\s+TABLE|DROP\s+DATABASE|DROP\s+SCHEMA|TRUNCATE|FLUSHALL/i;
    const hidden = /DROPTABLE|DROPDATABASE|DROPSCHEMA|TRUNCATE|FLUSHALL/i;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const compact = line.replace(/[\t ]+/g, "");
      if (compact === line || plain.test(line)) continue;
      if (hidden.test(compact)) {
        hits.push({
          rule: rule.id,
          policy: rule.policy,
          severity: rule.severity,
          label: rule.label,
          message,
          snippet: line.trim().slice(0, 140),
          line: i + 1,
          remediation: remediationFor(rule.id),
        });
      }
    }
    return hits;
  }

  /* One finding per rule per line: the first (plain-text) match wins. */
  function onePerLine(hits) {
    const byLine = new Map();
    for (const h of hits) if (!byLine.has(h.line)) byLine.set(h.line, h);
    return [...byLine.values()];
  }

  /*
   * git push with force (-f, --force, --force-with-lease) against a
   * protected branch (main, master, prod*, release*, deploy*) is a
   * destructive rewrite of shared history.
   */
  function gitForceHits(text, rule, message, wantProtected) {
    const hits = [];
    const re = /(?:^|[\s;&|])((?:git\b[^\n|;&]*)?\bpush\b[^\n|;&]*(?:--force(?:-with-lease)?|-f)\b[^\n|;&]*)/gim;
    let m;
    while ((m = re.exec(text))) {
      const cmd = m[1];
      const lineStart = text.lastIndexOf("\n", m.index) + 1;
      const prefix = text.slice(lineStart, m.index);
      if (/^\s*(?:#|--|\/\/|\*)/i.test(prefix)) continue;
      if (echoDocOnly(prefix + cmd)) continue;
      const protectedBranch = /\b(?:origin|upstream)\s+\S*(?:\bmain\b|\bmaster\b|\bprod\w*|\brelease[\w./-]*|\bdeploy\w*)/i.test(cmd)
        || /\b(?:main|master|prod\w*|release[\w./-]*|deploy\w*)\s*$/i.test(cmd.trim());
      if (wantProtected && !protectedBranch) continue;
      if (!wantProtected && protectedBranch) continue;
      hits.push(hit(rule, text, { 0: cmd.trim(), index: m.index + m[0].indexOf(cmd) }, message));
    }
    return hits;
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
    {
      id: "R01-terraform-auto-approve",
      policy: "POL-01",
      severity: 8,
      label: "terraform apply -auto-approve",
      test(text) {
        const re = /\bterraform\s+apply\b[^\n]*-auto-approve/gi;
        return matchRule(text, re, this, "terraform apply -auto-approve skips the plan review step entirely");
      }
    },
    {
      id: "R01-sql-obfuscated",
      policy: "POL-01",
      severity: 10,
      label: "Comment-split SQL keyword",
      test(text) {
        // DR/**/OP-style splits survive comment stripping as spaced tokens.
        // Only lines where whitespace collapsing reveals a keyword the plain
        // rules cannot see are flagged, so well-formed SQL never double-fires.
        return obfuscatedSqlHits(text, this,
          "SQL keyword hidden by comment splitting - comment-stripped match");
      }
    },
    {
      id: "R01-sql-exec",
      policy: "POL-01",
      severity: 9,
      label: "Dynamic SQL EXEC",
      test(text) {
        const re = /\bEXEC(?:UTE)?\s*\(\s*@|\bEXEC(?:UTE)?\s+(?:xp_|sp_)\w+/gi;
        return matchRule(text, re, this, "Dynamic or system SQL execution - xp_cmdshell and EXEC(@sql) run arbitrary commands");
      }
    },
    {
      id: "R01-drop-object",
      policy: "POL-01",
      severity: 8,
      label: "DROP VIEW / FUNCTION / INDEX",
      test(text) {
        const re = /\bDROP\s+(?:VIEW|FUNCTION|INDEX|SEQUENCE|PROCEDURE|TRIGGER)\b/gi;
        return matchRule(text, re, this, "Dropping a schema object destroys its definition - require an expand-contract migration");
      }
    },
    {
      id: "R01-delete-tautology",
      policy: "POL-01",
      severity: 9,
      label: "DELETE with tautology WHERE",
      test(text) {
        const re = /\bDELETE\s+FROM\b[^;\n]*\bWHERE\b[^;\n]*\b(?:1\s*=\s*1|TRUE)\b|\bDELETE\s+FROM\b[^;\n]*'[^']*'\s*=\s*'[^']*'/gi;
        return matchRule(text, re, this, "WHERE clause is always true - the DELETE removes every row");
      }
    },
    {
      id: "R01-script-destruct",
      policy: "POL-01",
      severity: 10,
      label: "Script-language recursive delete",
      test(text) {
        const re = /shutil\.rmtree\s*\(|\brmSync\s*\(|\brimraf\b|FileUtils\.rm_(?:rf|r)\s*\(|remove_tree\s*\(|\brmtree\s*\(/gi;
        return matchRule(text, re, this, "Destructive recursive delete through a scripting runtime - shutil.rmtree, fs.rmSync, rimraf or File::Path");
      }
    },
    {
      id: "R01-script-unlink",
      policy: "POL-01",
      severity: 8,
      label: "Script-language unlink",
      test(text) {
        const re = /\bos\.(?:remove|unlink)\s*\(|\bunlinkSync\s*\(|\bperl\b[^\n]*\bunlink\b/gi;
        return matchRule(text, re, this, "File removal through a scripting runtime requires an explicit allowlist");
      }
    },
    {
      id: "R01-obfuscated-exec",
      policy: "POL-01",
      severity: 10,
      label: "Encoded command execution",
      test(text) {
        const re = /base64[^\n]*(?:-d|--decode)[^\n]*\|\s*(?:sh|bash|zsh|ksh|dash|python\d*|perl|ruby|node)\b|\bopenssl\s+(?:enc|base64)\b[^\n]*\|\s*(?:sh|bash|zsh|ksh|dash)\b|\beval\b\s*(?:"[^"]*\$\(|'[^']*\$\(|\$\()/gi;
        return matchRule(text, re, this, "Base64-decoded payload piped into an interpreter - hidden destructive command");
      }
    },
    {
      id: "R01-curl-tar-pipe",
      policy: "POL-01",
      severity: 9,
      label: "curl piped to tar -C /",
      test(text) {
        const re = /\bcurl\b[^\n]*\|\s*tar\s+x[^\n]*-C\s+\/(?:\s|$)/gi;
        return matchRule(text, re, this, "Remote archive extracted into the filesystem root - arbitrary file write");
      }
    },
    {
      id: "R01-git-force-protected",
      policy: "POL-01",
      severity: 10,
      label: "Force push to protected branch",
      test(text) {
        return gitForceHits(text, this,
          "Force push rewrites history on a protected branch - destroys commits and reviews", true);
      }
    },
    {
      id: "R01-git-force-any",
      policy: "POL-01",
      severity: 8,
      label: "Force push",
      test(text) {
        return gitForceHits(text, this,
          "Force push rewrites remote history - require a reviewed rewind plan", false);
      }
    },
    {
      id: "R01-git-clean",
      policy: "POL-01",
      severity: 8,
      label: "git clean -fdx",
      test(text) {
        const re = /\bgit\s+clean\b[^\n]*\s-[A-Za-z]*[fdx]/gi;
        return matchRule(text, re, this, "git clean with -f/-d/-x deletes untracked and ignored files unconditionally");
      }
    },
    {
      id: "R01-xargs-rm",
      policy: "POL-01",
      severity: 8,
      label: "xargs rm",
      test(text) {
        const re = /\bxargs\s+(?:\S+\s+)?rm\b/gi;
        return matchRule(text, re, this, "Deletion targets piped through xargs are unbounded - enumerate and allowlist paths first");
      }
    },
    {
      id: "R01-permissive-chmod",
      policy: "POL-01",
      severity: 8,
      label: "Recursive chmod 777",
      test(text) {
        const re = /\bchmod\b(?=[^\n]*\s-[A-Za-z]*R)(?=[^\n]*\b(?:777|666)\b)/gi;
        return matchRule(text, re, this, "Recursive world-writable permissions expose every file to modification");
      }
    },
    {
      id: "R01-process-kill",
      policy: "POL-01",
      severity: 8,
      label: "Forced process kill",
      test(text) {
        const re = /\bpkill\s+-9\b|\bkillall\b|\bkill\s+-9\s+(?:1|-1|\$\$)\b/gi;
        return matchRule(text, re, this, "SIGKILL against every matching process or PID 1 - destroys the agent runtime and init");
      }
    },
    {
      id: "R01-container-wipe",
      policy: "POL-01",
      severity: 8,
      label: "docker system prune",
      test(text) {
        const re = /\bdocker\s+(?:system|container|image|volume)\s+prune\b/gi;
        return matchRule(text, re, this, "docker prune deletes stopped containers and unused images or volumes in one shot");
      }
    },
    {
      id: "R01-nosql-drop",
      policy: "POL-01",
      severity: 9,
      label: "NoSQL drop",
      test(text) {
        const re = /\bdropDatabase\s*\(|\.\s*drop\s*\(\s*\)/gi;
        return matchRule(text, re, this, "Database or collection drop through a NoSQL shell - irreversible data loss");
      }
    },
    {
      id: "R01-cluster-resize",
      policy: "POL-01",
      severity: 8,
      label: "CLI cluster resize",
      test(text) {
        const re = /\b(?:vultr(?:-cli)?|doctl|gcloud|aws)\s+\S+(?:\s\S+)*\s+(?:scale|resize)\b[^\n]*--count\s+(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/gi;
        const hits = [];
        let m;
        while ((m = re.exec(text))) {
          const n = numeric(m[1]);
          if (n > 10) hits.push(hit(this, text, m, `CLI resize to ${n} nodes breaches the cost-safe ceiling`));
        }
        return hits;
      }
    },
    {
      id: "R01-force-delete-pod",
      policy: "POL-01",
      severity: 8,
      label: "Force delete without grace",
      test(text) {
        const re = /\bkubectl\s+delete\b[^;\n]*--force\b[^;\n]*--grace-period=0|--grace-period=0[^;\n]*--force\b/gi;
        return matchRule(text, re, this, "Zero-grace forced deletion skips finalizers and can strand dependent state");
      }
    },
    {
      id: "R01-helm-uninstall",
      policy: "POL-01",
      severity: 8,
      label: "helm uninstall",
      test(text) {
        const re = /\bhelm\s+(?:uninstall|delete)\b/gi;
        return matchRule(text, re, this, "helm uninstall removes the whole release - verify scope and backups first");
      }
    },
    {
      id: "R01-recursive-chown",
      policy: "POL-01",
      severity: 8,
      label: "Recursive chown",
      test(text) {
        const re = /\bchown\b(?=[^\n]*\s-[A-Za-z]*R)[^\n]*/gi;
        return matchRule(text, re, this, "Recursive ownership change rewrites every file under the target path");
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
          const fedFromPipe = /(?:^|\n)[^\n]*\|\s*curl\b/.test(text.slice(0, m.index) + line);
          if ((hasExternal && (hasSecretRef || hasAtFile)) || hasPipe || fedFromPipe) {
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
    {
      id: "R04-scp-exfil",
      policy: "POL-04",
      severity: 10,
      label: "scp file transfer out",
      test(text) {
        const re = /\bscp\b[^\n]*/gi;
        const hits = [];
        let m;
        while ((m = re.exec(text))) {
          const line = m[0];
          if (!(/@|\b[\w.-]+:\//.test(line))) continue; // needs a remote host target
          const secretish = /(?:^|\s)(?:\/etc\/(?:shadow|passwd)|~\/\.ssh\/|\/root\/|\/home\/)\S*|\.(?:pem|key|id_rsa|env)\b|credential/i.test(line);
          if (secretish || /https?:\/\//.test(line) || /\$\{?[A-Z_]/.test(line)) {
            hits.push(hit(this, text, m, `scp copies credential material to a remote host: \`${line.trim().slice(0, 80)}\``));
          }
        }
        return hits;
      }
    },
    {
      id: "R04-curl-upload",
      policy: "POL-04",
      severity: 9,
      label: "curl upload exfiltration",
      test(text) {
        const re = /\bcurl\b[^\n]*(?:-T|--upload-file|-F\s+(?:"[^"]*)?@|--form\s+(?:"[^"]*)?@)[^\n]*/gi;
        return matchRule(text, re, this, "curl upload (-T/-F @file) sends local files to a remote endpoint");
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
      "R04-scp-exfil": "Deny scp egress to unmanaged hosts; move files through an audited transfer service.",
      "R04-curl-upload": "Deny curl -T/-F uploads to unmanaged endpoints; require a signed, allowlisted sink.",
      "R01-terraform-auto-approve": "Run terraform plan, attach the plan for review, then apply behind an approval gate.",
      "R01-sql-obfuscated": "Remove comment-splitting obfuscation; express the migration in plain reviewed SQL.",
      "R01-sql-exec": "Ban dynamic EXEC and xp_cmdshell; use parameterized stored procedures with review.",
      "R01-drop-object": "Recreate the object under a new name, cut over, then drop the old one in a later release.",
      "R01-delete-tautology": "Replace the always-true predicate with a real key-scoped WHERE clause and a row preview.",
      "R01-script-destruct": "Use the structured delete manifest with dry_run=true and a workspace-scoped path.",
      "R01-script-unlink": "Route file removal through the typed delete action; never unlink from a scripting runtime.",
      "R01-obfuscated-exec": "Decode, inspect and review the payload as plain text; never pipe decoders into interpreters.",
      "R01-curl-tar-pipe": "Download to a quarantined path, verify a checksum, then extract with an explicit target list.",
      "R01-git-force-protected": "Revert with a reviewed commit; protected branches require a merge, never a force push.",
      "R01-git-force-any": "Push to a new branch and open a review; never rewrite shared history.",
      "R01-git-clean": "Scope clean to named paths after a dry-run (-n) review; never combine -f with -x on a workspace root.",
      "R01-xargs-rm": "Replace xargs rm with a manifest-driven delete action over an explicit path list.",
      "R01-permissive-chmod": "Grant the narrow mode bits needed (755 for dirs, 640 for secrets) on specific paths.",
      "R01-process-kill": "Stop services with their supervisor's graceful shutdown; SIGKILL is a human-only action.",
      "R01-container-wipe": "Remove named containers or volumes individually after confirming they are unused.",
      "R01-nosql-drop": "Export a snapshot first; drop collections through a reviewed migration, never a shell eval.",
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
      "R01-delete-tautology": ["postgres"],
      "R01-find-delete": ["storage", "compute"],
      "R01-disk-wipe": ["compute", "storage"],
      "R01-terraform-destroy": ["compute", "storage"],
      "R01-terraform-auto-approve": ["compute", "storage"],
      "R01-sql-obfuscated": ["postgres"],
      "R01-sql-exec": ["postgres"],
      "R01-drop-object": ["postgres"],
      "R01-script-destruct": ["compute", "storage"],
      "R01-script-unlink": ["compute", "storage"],
      "R01-obfuscated-exec": ["compute", "storage"],
      "R01-curl-tar-pipe": ["compute", "storage"],
      "R01-git-force-protected": ["compute", "storage"],
      "R01-git-force-any": ["compute", "storage"],
      "R01-git-clean": ["compute", "storage"],
      "R01-xargs-rm": ["compute", "storage"],
      "R01-permissive-chmod": ["compute", "storage"],
      "R01-process-kill": ["compute"],
      "R01-container-wipe": ["compute"],
      "R01-nosql-drop": ["postgres", "redis"],
      "R02-iam-wildcard-action": ["iam", "secrets"],
      "R02-admin-access": ["iam", "secrets", "compute"],
      "R02-action-all": ["iam", "secrets"],
      "R02-wildcard-resource": ["iam", "secrets"],
      "R03-gpu-scale": ["gpu", "compute"],
      "R04-curl-exfil": ["secrets", "iam"],
      "R04-curl-upload": ["secrets", "compute"],
      "R04-env-dump": ["secrets"],
      "R04-egress-channel": ["secrets", "iam", "compute"],
      "R04-scp-exfil": ["secrets", "compute"],
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
