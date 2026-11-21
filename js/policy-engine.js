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
      .replace(/\\u\{([0-9a-fA-F]+)\}/g, (all, hex) => String.fromCodePoint(parseInt(hex, 16)))
      // ANSI-C $'...' quoting decodes escapes a shell would resolve:
      // \xHH, \NNN octal, \n \t \\ \' \" and friends. The decoded text
      // replaces the whole quoted span so DR\117P-style splits surface.
      .replace(/\$'((?:[^'\\]|\\.)*)'/g, (all, inner) => inner.replace(
        /\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[0-7]{1,3}|n|r|t|a|b|e|E|f|v|\\|'|"|\?)/g,
        (m, e) => {
          if (/^x[0-9a-fA-F]{1,2}$/.test(e)) return String.fromCharCode(parseInt(e.slice(1), 16));
          if (/^u[0-9a-fA-F]{4}$/.test(e)) return String.fromCharCode(parseInt(e.slice(1), 16));
          if (/^U[0-9a-fA-F]{8}$/.test(e)) return String.fromCodePoint(parseInt(e.slice(1), 16));
          if (/^[0-7]{1,3}$/.test(e)) return String.fromCharCode(parseInt(e, 8));
          const map = { n: "\n", r: "\r", t: "\t", a: "\x07", b: "\x08", e: "\x1b", E: "\x1b", f: "\x0c", v: "\x0b", "\\": "\\", "'": "'", '"': '"', "?": "?" };
          return map[e] != null ? map[e] : m;
        }))
      .replace(/[！-～]/g, ch =>
        String.fromCharCode(ch.charCodeAt(0) - 0xfee0));
  }

  /*
   * Shell splices backslash-newline pairs before tokenizing, so `rm -rf \`
   * <newline> `/` is one command. Rules scan the spliced text; scanLines[i]
   * maps every scanned character back to its true 1-based source line so
   * findings still point at the editor line the user sees.
   */
  let scanLines = null;

  function spliceContinuations(text) {
    let out = "";
    const lines = [];
    let line = 1;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (ch === "\\" && text[i + 1] === "\n") { i++; line++; continue; }
      out += ch;
      lines.push(line);
      if (ch === "\n") line++;
    }
    return { text: out, lines };
  }

  function scannedLine(index, fallbackText) {
    if (scanLines && typeof index === "number" && index >= 0 && index < scanLines.length) {
      return scanLines[index];
    }
    return lineNo(fallbackText, index);
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
      .map(a => a.replace(/^["'`(\\{[\],]+|[)"'`\\}\],]+$/g, ""))
      .filter(Boolean);
    return { recursive, force, args };
  }

  /*
   * Lexical path canonicalization: ./, .., // and trailing slashes resolve
   * before the root checks, so `rm -rf ././` or `rm -rf sub/..` cannot hide
   * a cwd deletion. A relative result that still leads with .. escapes the
   * working directory upward and counts as unbounded too.
   */
  function canonRmPath(a) {
    const abs = a.startsWith("/");
    const out = [];
    for (const p of a.split("/")) {
      if (p === "" || p === ".") continue;
      if (p === "..") {
        if (out.length && out[out.length - 1] !== "..") out.pop();
        else if (!abs) out.push("..");
      } else out.push(p);
    }
    const joined = out.join("/");
    if (abs) return "/" + joined;
    return joined === "" ? "." : joined;
  }

  // Root-equivalent targets: /, globs off /, //, the whole tree (., .., ./),
  // bare wildcards (./*, ../*, *), an unknown variable or bare home. Each
  // can expand to an unbounded deletion target.
  function rmTouchesRoot(parts) {
    return parts.args.some(a => {
      const c = canonRmPath(a);
      return c === "/" || c.startsWith("/*") || c === "." || c === ".." ||
        c.startsWith("../") || c === "*" || c.startsWith("~") ||
        (c.startsWith("/") && /[*?[\]]/.test(c.slice(1))) ||
        /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(c) || /^\$.+\)$/.test(c) ||
        /^\$\(.+\)$/.test(c);
    });
  }

  function rmTouchesAbsolute(parts) {
    return parts.args.some(a => canonRmPath(a).startsWith("/"));
  }

  // A shell-expanded home (~, ~user, ~+, ~-) or any variable reference in
  // the command text, even when it is not a standalone argument.
  function rmHasExpandable(cmd) {
    return /(?:^|\s)~[^\s]|\$\{[^}\n]*\}|\$(?!\{|\()\w+|\$\(|`/.test(cmd);
  }

  function rmCommandHits(text, rule, message, wantRoot) {
    const hits = [];
    // Command words may start after whitespace, chaining (;, &, |), command
    // substitution ($(, `), subshell ( ( ) or grouping ({, a quote or
    // backslash (so "rm", 'rm', \rm and r\m still resolve to rm), or JSON
    // punctuation - never mid-word. The rm token itself may carry
    // interleaved quote/backslash characters and an obfuscated /bin/ or
    // sudo prefix.
    const re = /(?:^|[\s;&|(`{'"\\])((?:(?:sudo|env)\s+)?(?:["'`\\/$]*bin["'`\\/$]*)?(?:["'`\\/\s]+sudo["'`\\/\s]+)?["'`\\$]*r["'`\\$]*m["'`\\$]*\b[^\n|;&]*)/gim;
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

  /*
   * DELETE ... FROM <table> statements with the text that follows the table
   * name, cut at the next ; or the next DML/DDL keyword. A WHERE clause on
   * a following line still counts, and a WHERE belonging to a later
   * statement cannot mask a bare DELETE.
   */
  function deleteStatements(text) {
    const out = [];
    // MySQL multi-table DELETE puts aliases between DELETE and FROM
    // (DELETE u, v FROM t1 JOIN t2); an optional alias list covers it.
    const re = /\bDELETE\s+(?:["'`\w]+\.?\*?\s*,?\s+)*FROM\s+["'`\w"]+(?:\s*\.\s*["'`\w"]+)*/gi;
    let m;
    while ((m = re.exec(text))) {
      const rest = text.slice(m.index + m[0].length);
      const semi = rest.indexOf(";");
      let win = semi === -1 ? rest : rest.slice(0, semi);
      const kw = win.search(/\b(?:INSERT|UPDATE|DELETE|SELECT|DROP|CREATE|ALTER|TRUNCATE|MERGE|GRANT|REVOKE)\b/i);
      if (kw !== -1) win = win.slice(0, kw);
      out.push({ index: m.index, head: m[0], window: win });
    }
    return out;
  }

  /*
   * A WHERE body that can only evaluate to true: TRUE literals, NOT FALSE,
   * self-equalities (id = id, 1 = 1) and identical quoted comparisons,
   * joined by AND/OR. Anything else (a real column predicate, a LIMIT, a
   * FALSE literal) leaves residue and is treated as bounded.
   */
  function isTautWhere(wb) {
    let w = String(wb || "").replace(/\bLIMIT\b[\s\S]*$/i, "").replace(/\s+/g, " ").trim();
    if (!w) return false;
    // Negated-true or bare-false bodies delete nothing; they are not the
    // unbounded-delete bypass this rule exists for.
    const deNeg = w.replace(/\bNOT\s+FALSE\b/gi, " ");
    if (/\bNOT\s+TRUE\b|\bFALSE\b/i.test(deNeg)) return false;
    let prev;
    do {
      prev = w;
      w = w
        .replace(/'((?:[^'\\]|\\.)*)'\s*=\s*'\1'/g, " ")
        .replace(/"((?:[^"\\]|\\.)*)"\s*=\s*"\1"/g, " ")
        .replace(/\b([\w.]+)\s*=\s*\1\b/g, " ")
        // Numeric comparisons that always hold: 0=0, 2>1, 3>=3, 1<2.
        .replace(/\b(\d+(?:\.\d+)?)\s*(>=|<=|>|<|=)\s*(\d+(?:\.\d+)?)\b/g,
          (all, a, op, b) => {
            const x = +a, y = +b;
            const t = op === ">" ? x > y : op === "<" ? x < y
              : op === ">=" ? x >= y : op === "<=" ? x <= y : x === y;
            return t ? " " : all;
          })
        .replace(/\bTRUE\b/gi, " ")
        .replace(/\bNOT\s+FALSE\b/gi, " ")
        .replace(/[()]/g, " ");
    } while (w !== prev);
    return w.replace(/\b(?:AND|OR|NOT|WHERE|IS|NULL|IN|EXISTS|LIKE|BETWEEN)\b/gi, " ").trim() === "";
  }

  /*
   * Classify one IAM Action value. Returns a risk tag or null. Bare "*" is
   * left to the dedicated Action "*" rule; service wildcards (s3:*, ec2:*),
   * iam:* family, sts:* and sts:AssumeRole* all violate least privilege.
   */
  function iamActionRisk(v) {
    const s = String(v || "").trim().replace(/^["'`]+|["'`,}\]]+$/g, "");
    if (!s || s === "*" || !s.includes("*")) return null;
    if (/^iam:/i.test(s)) return "iam-wildcard";
    if (/^sts:/i.test(s)) return "sts-wildcard";
    if (/^[a-z][a-z0-9-]*:/i.test(s)) return "service-wildcard";
    return null;
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
    const byLine = new Set();
    const push = (index, snippet) => {
      const line = scannedLine(index, text);
      if (byLine.has(line)) return;
      byLine.add(line);
      hits.push({
        rule: rule.id,
        policy: rule.policy,
        severity: rule.severity,
        label: rule.label,
        message,
        snippet: String(snippet).trim().slice(0, 140),
        line,
        remediation: remediationFor(rule.id),
      });
    };
    const plain = /DROP\s+TABLE|DROP\s+DATABASE|DROP\s+SCHEMA|TRUNCATE|FLUSHALL/i;
    const hidden = /DROPTABLE|DROPDATABASE|DROPSCHEMA|TRUNCATE|FLUSHALL/i;
    const lines = String(text).split("\n");
    let offset = 0;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const compact = line.replace(/[\t ]+/g, "");
      if (compact !== line && !plain.test(line) && hidden.test(compact)) {
        push(offset, line);
      }
      offset += line.length + 1;
    }
    /*
     * SQL line comments split keywords the same way block comments do:
     * `DROP-- x` <newline> `TABLE t` is DROP TABLE in Postgres-style dialects
     * and `DROP#x` does it in MySQL. Per physical line this never compacts to
     * a keyword, so each ;-delimited statement is comment-stripped and fully
     * whitespace-collapsed before the hidden-keyword test.
     */
    let cursor = 0;
    for (const seg of String(text).split(";")) {
      const segStart = cursor;
      cursor += seg.length + 1;
      const stripped = seg.replace(/--[^\n]*/g, " ").replace(/#[^\n]*/g, " ");
      const compactAll = stripped.replace(/\s+/g, "");
      if (hidden.test(compactAll) && !plain.test(seg)) {
        push(segStart, seg);
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
  /*
   * git push force indicators, checked on the captured segment rather than
   * inside the regex so combined short flags (-fu, -ufv), +refspec force
   * updates and --mirror all count. --force-with-lease and
   * --force-if-includes still rewrite remote history.
   */
  function gitPushIsForce(cmd) {
    return /(?:^|\s)--force(?:-[\w-]+)?(?=[\s"'`\\)}\]]|$)/i.test(cmd)
      || /(?:^|\s)--mirror(?=[\s"'`\\)}\]]|$)/i.test(cmd)
      || /(?:^|\s)-[A-Za-z]*f[A-Za-z]*(?=[\s"'`\\)}\]]|$)/.test(cmd)
      || /\s\+\S/.test(cmd);
  }

  function gitForceHits(text, rule, message, wantProtected) {
    const hits = [];
    const re = /(?:^|[\s;&|(`{'"\\])((?:git\b[^\n|;&]*)?\bpush\b[^\n|;&]*)/gim;
    let m;
    while ((m = re.exec(text))) {
      const cmd = m[1];
      const lineStart = text.lastIndexOf("\n", m.index) + 1;
      const prefix = text.slice(lineStart, m.index);
      if (/^\s*(?:#|--|\/\/|\*)/i.test(prefix)) continue;
      if (echoDocOnly((prefix + m[0]).trimEnd())) continue;
      if (!gitPushIsForce(cmd)) continue;
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
      id: "R01-indirect-command",
      policy: "POL-01",
      severity: 9,
      label: "Variable command, destructive flags",
      test(text) {
        // $CMD / ${CMD} / $(...) / `...` as the command word hides what runs.
        // Recursive+force flags on an absolute, root or expandable target is
        // an rm-shaped payload regardless of the hidden binary's name.
        const re = /(?:^|[\s;&|(`{'"\\])(\$\{?[A-Za-z_]\w*\}?|\$\([^)\n]*\)|`[^`\n]*`)\s+([^\n|;&]*)/g;
        const hits = [];
        let m;
        while ((m = re.exec(text))) {
          const varWord = m[1];
          const lineStart = text.lastIndexOf("\n", m.index) + 1;
          const prefix = text.slice(lineStart, m.index);
          if (/^\s*(?:#|--|\/\/|\*)/i.test(prefix)) continue;
          if (echoDocOnly((prefix + m[0]).trimEnd())) continue;
          // echo/printf/cat-style printers take the variable as an argument,
          // never as a command word - but only while no ; | & separates them.
          if (/^\s*(?:echo|printf|cat|yes|seq|printenv|type|which)\b\s*[^|;&]*$/i.test(prefix)) continue;
          const argsText = m[2];
          const flags = (argsText.match(/-(?:[A-Za-z][A-Za-z0-9]*|-[\w-]+)/g) || []).join(" ").toLowerCase();
          const recursive = /(^|\s)-[a-z]*r/.test(flags) || /--recursive/.test(flags);
          const force = /(^|\s)-[a-z]*f/.test(flags) || /--force/.test(flags);
          if (!recursive || !force) continue;
          const targets = argsText.replace(/-(?:[A-Za-z][A-Za-z0-9]*|-[\w-]+)/g, " ")
            .split(/\s+/)
            .map(a => a.replace(/^["'`(\\{[\],]+|[)"'`\\}\],]+$/g, ""))
            .filter(Boolean);
          const parts = { args: targets };
          const dangerous = rmTouchesRoot(parts)
            || /\$\{|\$\(|`|(?:^|\s)~/.test(argsText);
          if (!dangerous) continue;
          hits.push(hit(this, text, { 0: (varWord + " " + argsText.trim()), index: m.index + m[0].indexOf(varWord) },
            "Command name resolved at runtime runs recursive force flags on an unbounded target - pin the binary and target explicitly"));
        }
        return hits;
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
        const hits = [];
        for (const st of deleteStatements(text)) {
          if (/\bWHERE\b/i.test(st.window)) continue;
          hits.push(hit(this, text, { 0: st.head + st.window, index: st.index },
            `DELETE without WHERE clause - would remove all rows: \`${(st.head + st.window).trim().slice(0, 70)}\``));
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
        // -delete, -exec/-execdir/-ok/-okdir running a destructive payload.
        const re = /\bfind\b[^\n]*\s(?:-delete\b|-exec(?:dir)?\b[^\n]*(?:\brm\b|\b(?:ba)?sh\b|\bzsh\b|\bdd\b)|-o(?:k|kdir)\b)/gi;
        return matchRule(text, re, this, "find -delete is an unbounded recursive deletion");
      }
    },
    {
      id: "R01-disk-wipe",
      policy: "POL-01",
      severity: 10,
      label: "Disk wipe",
      test(text) {
        const re = /\b(?:shred|wipefs|mkfs(?:\.[\w-]+)?)\b[^\n]*|\bdd\b[^\n]*\bof\s*=\s*["']?\/dev\/|[^\n>]*>\s*\/dev\/(?:sd[a-z]|nvme\d|vd[a-z]|xvd[a-z]|mapper\/)/gi;
        return matchRule(text, re, this, "Destructive disk operation - irreversible device wipe");
      }
    },
    {
      id: "R01-kubectl-delete-ns",
      policy: "POL-01",
      severity: 9,
      label: "kubectl delete namespace",
      test(text) {
        // kubectl/oc global flags (-n ns, --context=x, -A) may sit before or
        // after delete; plural resource names and oc projects count too.
        const flag = String.raw`(?:-{1,2}[\w-]+(?:=\S+|\s+\S+)?\s+)*`;
        const re = new RegExp(String.raw`\b(?:kubectl|oc)\s+` + flag + String.raw`delete\s+` + flag + String.raw`(?:namespaces?|projects?|ns)\b[^\n]*`, "gi");
        return matchRule(text, re, this, "kubectl delete namespace - destroys all workloads in namespace");
      }
    },
    {
      id: "R01-kubectl-delete-all",
      policy: "POL-01",
      severity: 9,
      label: "kubectl delete --all",
      test(text) {
        // Capture each kubectl/oc delete segment, then check for an
        // unbounded selector wherever the flags landed.
        const re = /\b(?:kubectl|oc)\b[^\n|;&`]*?\bdelete\b[^\n|;&`]*/gi;
        const hits = [];
        let m;
        while ((m = re.exec(text))) {
          const seg = m[0];
          if (/\bdelete\s+all\b/i.test(seg)
            || /(?:^|\s)(?:--all|--all-namespaces|-A)(?=[\s"'`\\)\]}]|$)/.test(seg)) {
            hits.push(hit(this, text, m, "kubectl delete --all - unbounded resource deletion"));
          }
        }
        return hits;
      }
    },
    {
      id: "R01-terraform-destroy",
      policy: "POL-01",
      severity: 9,
      label: "terraform destroy",
      test(text) {
        // Global flags such as -chdir=dir may precede the subcommand, and
        // OpenTofu and the tf binary alias share the same destroy semantics.
        const re = /\b(?:terraform|tofu|tf)\s+(?:(?:-{1,2}[\w-]+)(?:=\S+)?\s+)*destroy\b[^\n]*/gi;
        return matchRule(text, re, this, "terraform destroy - deletes all managed infrastructure");
      }
    },
    {
      id: "R01-terraform-auto-approve",
      policy: "POL-01",
      severity: 8,
      label: "terraform apply -auto-approve",
      test(text) {
        const re = /\b(?:terraform|tofu|tf)\s+(?:(?:-{1,2}[\w-]+)(?:=\S+)?\s+)*apply\b[^\n]*-auto-approve(?:=\S+)?/gi;
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
        const re = /\bEXEC(?:UTE)?\s*\(\s*@|\bEXEC(?:UTE)?\s+(?:xp_|sp_|IMMEDIATE\b)\w*|\bEXEC\s*\(\s*['"]/gi;
        return matchRule(text, re, this, "Dynamic or system SQL execution - xp_cmdshell, EXECUTE IMMEDIATE and EXEC(@sql) run arbitrary commands");
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
        const hits = [];
        for (const st of deleteStatements(text)) {
          const wi = st.window.search(/\bWHERE\b/i);
          if (wi === -1) continue;
          const wb = st.window.slice(wi + 5);
          if (isTautWhere(wb)) {
            const frag = (st.head + st.window.slice(0, wi + 5 + wb.length)).trim();
            hits.push(hit(this, text, { 0: frag, index: st.index },
              `WHERE clause is always true - the DELETE removes every row: \`${frag.slice(0, 70)}\``));
          }
        }
        return hits;
      }
    },
    {
      id: "R01-merge-delete",
      policy: "POL-01",
      severity: 9,
      label: "MERGE ... DELETE",
      test(text) {
        const re = /\bMERGE\s+INTO\b[^;]*\bWHEN\s+MATCHED\b[^;]*\bDELETE\b|\bMERGE\b[^;\n]*\bDELETE\s+(?:WHEN|THEN|ELSE)\b/gi;
        return matchRule(text, re, this, "MERGE with a DELETE action removes matched rows in bulk - require a key-scoped predicate and row preview");
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
        // curl or wget feeding tar/bsdtar/gtar extraction into /, with -C,
        // --directory or a bare `tar x..` operand list.
        const re = /\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:bsdtar|gtar|tar)\b[^\n]*(?:(?:\s-[a-zA-Z]*x[a-zA-Z]*|\s--extract\b|\sx[a-z]*\s)[^\n]*(?:-C\s+\/|--directory[=\s]+\/)(?:\s|$))/gi;
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
        // Anything may sit between git and clean (-C dir, --git-dir=...),
        // and both short clusters (-fdx) and --force count. A single-dash
        // short flag carrying f, d or x is required so --dry-run stays clean.
        const re = /\bgit\b[^\n|;&`]*?\bclean\b[^\n|;&`]*/gi;
        const hits = [];
        let m;
        while ((m = re.exec(text))) {
          const seg = m[0];
          if (/(?:\s-(?!-)[A-Za-z]*[fdx][A-Za-z]*|\s--force\b)/i.test(seg)) {
            hits.push(hit(this, text, m, "git clean with -f/-d/-x deletes untracked and ignored files unconditionally"));
          }
        }
        return hits;
      }
    },
    {
      id: "R01-git-destructive",
      policy: "POL-01",
      severity: 7,
      label: "Destructive git operation",
      test(text) {
        const hits = [];
        const re = /\bgit\b[^\n|;&`]*?(?:\breset\b[^\n|;&`]*--hard\b|\bbranch\b[^\n|;&`]*?(?:\s-D\b|\s--delete\b(?=[^\n|;&`]*--force\b)|\s--force\b(?=[^\n|;&`]*--delete\b))|\bpush\b[^\n|;&`]*(?:--delete\b|\s:\S)|\bfilter-branch\b|\bfilter-repo\b|\bstash\s+(?:drop|clear)\b|\bupdate-ref\s+-d\b|\btag\s+-d\b|\b(?:checkout|switch)\b[^\n|;&`]*\s(?:-[fF]|--force|--discard-changes)\b)/gi;
        let m;
        while ((m = re.exec(text))) {
          hits.push(hit(this, text, m, "Destructive git operation discards work or deletes refs - prefer a reviewed, reversible path"));
        }
        // Bare-path discards: git checkout . / git checkout -- . / git restore .
        // git restore --staged (or -S) only unstages; it destroys nothing.
        const dotRe = /\bgit\b[^\n|;&`]*?\b(?:checkout|restore)\b[^\n|;&`]*?(?:\s--\s+|\s)\.(?=[\s"'`\\)\]}]|$)/gi;
        while ((m = dotRe.exec(text))) {
          const seg = m[0];
          if (/\brestore\b/i.test(seg) && /--staged\b|\s-S\b/.test(seg)) continue;
          hits.push(hit(this, text, m, "git checkout/restore on . discards uncommitted changes across the tree"));
        }
        return hits;
      }
    },
    {
      id: "R01-xargs-rm",
      policy: "POL-01",
      severity: 8,
      label: "xargs rm",
      test(text) {
        // Flag clusters with separate values (-I {}, -P 4, --replace={})
        // may sit between xargs and rm.
        const re = /\bxargs\s+(?:(?:-{1,2}[\w-]+)(?:=\S+|\s+\S+)?\s+)*rm\b/gi;
        return matchRule(text, re, this, "Deletion targets piped through xargs are unbounded - enumerate and allowlist paths first");
      }
    },
    {
      id: "R01-permissive-chmod",
      policy: "POL-01",
      severity: 8,
      label: "Recursive chmod 777",
      test(text) {
        // Recursive (-R/--recursive) world-writable modes: 777, 0777, 666,
        // 0666 and the sticky 1777 all expose files to modification.
        const re = /\bchmod\b(?=[^\n]*(?:\s-[A-Za-z]*R|\s--recursive\b))(?=[^\n]*\b1?0{0,2}(?:777|666)\b)/gi;
        return matchRule(text, re, this, "Recursive world-writable permissions expose every file to modification");
      }
    },
    {
      id: "R01-process-kill",
      policy: "POL-01",
      severity: 8,
      label: "Forced process kill",
      test(text) {
        const re = /\bpkill\s+(?:-[a-zA-Z]*9|-[a-zA-Z]*KILL|-[a-zA-Z]*f\b|--full\b)|\bkillall\b|\bkill\s+(?:-[a-zA-Z]*9|-[a-zA-Z]*KILL|-[a-zA-Z]*SIGKILL)\s+(?:1|-1|\$\$)\b/gi;
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
        // drop()/dropDatabase() plus filter-less deletes: deleteMany({}),
        // remove({}), deleteOne() with no predicate all remove everything.
        const re = /\bdropDatabase\s*\(|\.\s*(?:drop|deleteMany|removeMany|deleteOne|remove)\s*\(\s*(?:\{\s*\}|null|undefined)?\s*\)/gi;
        return matchRule(text, re, this, "Database or collection drop through a NoSQL shell - irreversible data loss");
      }
    },
    {
      id: "R01-cluster-resize",
      policy: "POL-01",
      severity: 8,
      label: "CLI cluster resize",
      test(text) {
        const num = "(\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?)";
        const patterns = [
          new RegExp("\\b(?:vultr(?:-cli)?|doctl|gcloud|aws)\\s+\\S+(?:\\s\\S+)*\\s+(?:scale|resize)\\b[^\\n]*--count\\s+" + num, "gi"),
          new RegExp("\\baws\\s+autoscaling\\s+set-desired-capacity\\b[^\\n]*--desired-capacity\\s+" + num, "gi"),
          new RegExp("\\bdoctl\\s+kubernetes\\s+cluster\\s+node-pool\\s+update\\b[^\\n]*--size\\s+" + num, "gi"),
          new RegExp("\\bgcloud\\s+container\\s+clusters\\s+update\\b[^\\n]*--num-nodes\\s+" + num, "gi"),
        ];
        const hits = [];
        for (const re of patterns) {
          let m;
          while ((m = re.exec(text))) {
            const n = numeric(m[1]);
            if (n > 10) hits.push(hit(this, text, m, `CLI resize to ${n} nodes breaches the cost-safe ceiling`));
          }
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
        const re = /\b(?:kubectl|oc)\b[^\n|;&`]*?\bdelete\b[^\n|;&`]*/gi;
        const hits = [];
        let m;
        while ((m = re.exec(text))) {
          const seg = m[0];
          if (/(?:^|\s)--force(?=[\s"'`\\)\]}]|$)/.test(seg) && /--grace-period=0\b/.test(seg)) {
            hits.push(hit(this, text, m, "Zero-grace forced deletion skips finalizers and can strand dependent state"));
          }
        }
        return hits;
      }
    },
    {
      id: "R01-helm-uninstall",
      policy: "POL-01",
      severity: 8,
      label: "helm uninstall",
      test(text) {
        const re = /\bhelm\s+(?:(?:-{1,2}[\w-]+)(?:=\S+|\s+\S+)?\s+)*(?:uninstall|delete)\b/gi;
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
    {
      id: "R01-remote-exec",
      policy: "POL-01",
      severity: 10,
      label: "Remote script execution",
      test(text) {
        // eval of a command substitution, process-substitution shells,
        // /dev/stdin sourcing and curl|wget piped into an interpreter all
        // run attacker-controlled code.
        const re = /\beval\s+["'`]*\$\(|\beval\s+`|\.\s+\/dev\/stdin\b|\bsource\s+\/dev\/stdin\b|\b(?:bash|sh|zsh|dash|ksh)\s+<\(|\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|ksh|python[\d.]*|perl|ruby|node|php)\b(?=\s*(?:$|[;|&]|\s+-{1,2}[\w-]*\b|\s+-\s|\s*-\s*$))/gi;
        return matchRule(text, re, this, "Remote or substituted payload executed directly - review the decoded script before running it");
      }
    },
    {
      id: "R01-host-power",
      policy: "POL-01",
      severity: 9,
      label: "Host power control",
      test(text) {
        // Only command position counts: line start, chaining operators or
        // wrappers, so prose like "the pod will reboot" stays quiet.
        const re = /(?:^|[\n;&|(`{]|\|\||&&)\s*(?:(?:sudo|doas)(?:\s+-{1,2}[\w-]+)*\s+|env\s+(?:[A-Za-z_]\w*=\S+\s+)*|[A-Za-z_]\w*=\S+\s+)*(?:shutdown|reboot|poweroff|halt|init\s+[06]\b|telinit\s+[06]\b|systemctl\s+(?:poweroff|reboot|halt|kexec|isolate)\b|echo\s+[bo]\s*>\s*\/proc\/sysrq-trigger|:\(\)\s*\{\s*:\|:&\s*\};:)/gi;
        return matchRule(text, re, this, "Host power or fork-bomb command - takes the whole runtime down");
      }
    },
    {
      id: "R01-docker-bulk",
      policy: "POL-01",
      severity: 8,
      label: "Bulk container operation",
      test(text) {
        // Mass rm/kill/stop driven by docker ps output, or ps -aq piped to
        // xargs docker - every container goes at once.
        const re = /\bdocker\s+(?:rm|rmi|kill|stop|pause|restart|rename)\b[^\n]*\$\(\s*docker\s+ps|\bdocker\s+(?:ps|container\s+ls)\b[^\n]*\|\s*xargs\b[^\n]*\bdocker\s+(?:rm|rmi|kill|stop)\b/gi;
        return matchRule(text, re, this, "Bulk container deletion or kill via docker ps - enumerate and allowlist targets first");
      }
    },
    {
      id: "R01-sql-file-io",
      policy: "POL-01",
      severity: 8,
      label: "SQL file read/write",
      test(text) {
        // INTO OUTFILE/DUMPFILE writes server-side files; LOAD_FILE() reads
        // arbitrary server paths into query results (exfiltration primitive).
        const re = /\bSELECT\b[^;]{0,400}?\bINTO\s+(?:OUTFILE|DUMPFILE)\b|\bLOAD_FILE\s*\(/gi;
        return matchRule(text, re, this, "SQL file IO reads or writes server filesystem paths - require an allowlisted, reviewed statement");
      }
    },

    // ── POL-02 : Least Privilege IAM ────────────────────────────────
    {
      id: "R02-iam-wildcard-action",
      policy: "POL-02",
      severity: 10,
      label: "IAM wildcard action",
      test(text) {
        const hits = [];
        const seen = new Set();
        const push = (idx, len, msg) => {
          if (seen.has(idx)) return;
          seen.add(idx);
          hits.push(hit(this, text, { 0: text.substr(idx, len), index: idx }, msg));
        };
        /*
         * Action/Actions assignments in JSON, YAML, HCL, TOML or inline
         * jsonencode: scalar, array and block-list forms all land here. The
         * value span runs until the next policy key so "Resource" or
         * "Effect" entries are never mistaken for actions.
         */
        const keyRe = /\bactions?["'`]?\s*[:=]/gi;
        let m;
        while ((m = keyRe.exec(text))) {
          const start = m.index + m[0].length;
          let span = text.slice(start, start + 500);
          const stop = span.search(/\b(?:resources?|effect|sid|condition|principal|notaction|notresources?)\b|["'`](?:resources?|effect|sid|condition|principal)["'`]\s*:/i);
          if (stop !== -1) span = span.slice(0, stop);
          const valRe = /"([^"\n]{1,160})"|'([^'\n]{1,160})'|`([^`\n]{1,160})`|([A-Za-z0-9*][A-Za-z0-9*:_-]*)/g;
          let vm;
          while ((vm = valRe.exec(span))) {
            const v = vm[1] || vm[2] || vm[3] || vm[4] || "";
            // A bare "*" sitting deep inside the value span is being
            // assembled by an expression (replace/jsonencode/for/join)
            // rather than assigned directly; Action "*" itself is owned
            // by R02-action-all so direct values stay single-flagged.
            if (v === "*" && vm.index > 4) {
              push(start + vm.index, vm[0].length,
                "Action \"*\" assembled inside a policy expression - grants every API operation");
              continue;
            }
            const risk = iamActionRisk(v);
            if (!risk) continue;
            const label = risk === "iam-wildcard" ? "IAM wildcard action"
              : risk === "sts-wildcard" ? "STS wildcard action"
              : "AWS service wildcard action";
            push(start + vm.index, vm[0].length,
              `${label} \`${v}\` - grants far more than the task needs`);
          }
        }
        // Bare iam:* anywhere else (shell fragments, docs of live plans).
        const bare = /\biam:\*/gi;
        while ((m = bare.exec(text))) {
          if (seen.has(m.index)) continue;
          push(m.index, m[0].length, "IAM wildcard action `iam:*` in policy statement");
        }
        const admin = /aws\s+iam\s+attach[^\n]*AdministratorAccess|policy_arn\s*=\s*["'][^"']*AdministratorAccess["']/gi;
        while ((m = admin.exec(text))) {
          if (seen.has(m.index)) continue;
          push(m.index, m[0].length, "AdministratorAccess policy attachment - full account takeover");
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
        // Scalar, array and YAML block-list forms of Action/Actions = "*".
        const re = /\bactions?["'`]?\s*[:=]\s*[\[{]?\s*-?\s*["'`]\*["'`]/gi;
        return matchRule(text, re, this, 'Action "*" grants every API operation');
      }
    },
    {
      id: "R02-wildcard-resource",
      policy: "POL-02",
      severity: 8,
      label: 'IAM Resource "*"',
      test(text) {
        const hits = [];
        const seen = new Set();
        const push = (idx, len, msg) => {
          if (seen.has(idx)) return;
          seen.add(idx);
          hits.push(hit(this, text, { 0: text.substr(idx, len), index: idx }, msg));
        };
        const exact = /\bresources?["'`]?\s*[:=]\s*[\[{]?\s*-?\s*["'`]\*["'`]/gi;
        let m;
        while ((m = exact.exec(text))) {
          push(m.index, m[0].length, 'IAM Resource "*" - policy applies to every resource in the account');
        }
        // NotResource "*" inverts the statement; it is usually inert but
        // always worth a human look before it ships.
        const notExact = /\bnot_?resources?["'`]?\s*[:=]\s*[\[{]?\s*-?\s*["'`]\*["'`]/gi;
        while ((m = notExact.exec(text))) {
          push(m.index, m[0].length, 'NotResource "*" inverts the resource scope - verify the statement is not inert or over-broad');
        }
        // A "*" buried inside a resource value expression (for-expressions,
        // dynamic blocks, replace chains) is the same wildcard deferred.
        const resKey = /\b(?:not_?resources?|resources?)["'`]?\s*[:=]/gi;
        while ((m = resKey.exec(text))) {
          const start = m.index + m[0].length;
          const span = text.slice(start, start + 240);
          const starRe = /["'`]\*["'`]/g;
          let sm;
          while ((sm = starRe.exec(span))) {
            if (sm.index <= 4) continue; // direct value: exact rules own it
            push(start + sm.index, sm[0].length,
              'Resource "*" assembled inside a policy expression - wildcard scope deferred to evaluation');
          }
        }
        // ARN wildcards: a * account or a bare * resource segment scopes the
        // policy account-wide. bucket/* object prefixes stay allowed.
        const arnRe = /["'`]arn:aws:[a-z0-9-]*:[^"'`\n]*["'`]/gi;
        while ((m = arnRe.exec(text))) {
          const arn = m[0].slice(1, -1);
          const segs = arn.split(":");
          const account = segs[4];
          const resource = segs.slice(5).join(":");
          if (account === "*" || resource === "*") {
            push(m.index, m[0].length, `IAM resource ARN wildcard \`${arn.slice(0, 60)}\` - policy applies account-wide`);
          }
        }
        return hits;
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
    {
      id: "R02-k8s-rbac-wildcard",
      policy: "POL-02",
      severity: 9,
      label: "Kubernetes RBAC wildcard",
      test(text) {
        const hits = [];
        const rbacCtx = /\b(?:ClusterRole|RoleBinding|roleRef|subjects|rbac|apiGroups|kind\s*:\s*\w*Role)\b/i;
        // verbs/resources/apiGroups set to "*" inside an RBAC object.
        const wildRe = /\b(?:apiGroups|verbs|resources)\b["'`]?\s*[:=]\s*[\[{]?\s*-?\s*["'`]?\*/gi;
        let m;
        while ((m = wildRe.exec(text))) {
          const ctx = text.slice(Math.max(0, m.index - 300), m.index + 300);
          if (!rbacCtx.test(ctx)) continue;
          hits.push(hit(this, text, m, "RBAC rule grants wildcard apiGroups/verbs/resources - violates least privilege"));
        }
        // Binding to the cluster-admin role anywhere in an RBAC manifest.
        const adminRe = /\bcluster-admin\b/gi;
        while ((m = adminRe.exec(text))) {
          const ctx = text.slice(Math.max(0, m.index - 300), m.index + 300);
          if (!/\b(?:ClusterRoleBinding|RoleBinding|roleRef|kind\s*:\s*\w*Role|subjects)\b/i.test(ctx)) continue;
          hits.push(hit(this, text, m, "Binding to cluster-admin grants unrestricted cluster access"));
        }
        // Privilege-escalation verbs (impersonate/bind/escalate) aimed at
        // identity resources hand out rights without any wildcard token.
        const privRe = /\bverbs\b["'`]?\s*[:=][\s\S]{0,300}?\b(?:impersonate|bind|escalate)\b[\s\S]{0,300}?\b(?:users?|groups?|clusterroles?|serviceaccounts?|roles?)\b/gi;
        const privCtx = /\b(?:ClusterRole|RoleBinding|roleRef|subjects|rbac|apiGroups|kind\s*:\s*\w*Role|clusterroles?|serviceaccounts?)\b/i;
        while ((m = privRe.exec(text))) {
          const ctx = text.slice(Math.max(0, m.index - 300), m.index + m[0].length + 300);
          // impersonate is RBAC vocabulary on its own; bind/escalate need
          // a Kubernetes marker nearby so generic config verbs stay clean.
          if (!privCtx.test(ctx) && !/\bimpersonate\b/i.test(m[0])) continue;
          hits.push(hit(this, text, m, "RBAC verbs impersonate/bind/escalate on identity resources - privilege escalation without wildcards"));
        }
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
        // count = length(range(0, N)) and friends hide the number behind a
        // function; the evaluated value still multiplies the bill.
        const computed = /\bcount\s*=\s*(?:length|range|ceil|floor|max|min|abs|tonumber|try|can|coalesce)\s*\([^\n)]*\)/gi;
        while ((m = computed.exec(text))) {
          hits.push(hit(this, text, m, `count computed by function \`${m[0].trim().slice(0, 50)}\` - pin the evaluated value before apply`));
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
        // maxReplicas/max_replicas, K8s/VPA max_size/maxSize, AWS-style
        // --max-size, ASG MaxSize and cluster-autoscaler max-nodes all cap
        // the same runaway spend.
        const num = String.raw`(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)`;
        const re = new RegExp(
          String.raw`(?:\b(?:max_?replicas|max[_-]?size|max[_-]?capacity|max[_-]?nodes|maxNodeCount|MaxSize)\b|--max-size)["']?\s*[:=]?\s*["']?` + num
          + String.raw`|autoscal\w+[^\n]*max[^\n]*?` + num, "gi");
        const hits = [];
        let m;
        while ((m = re.exec(text))) {
          const n = numeric(m[1] || m[2]);
          if (n > 20) hits.push(hit(this, text, m, `Autoscale ceiling ${n} - unbounded scaling risk`));
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
          const varRefs = [...line.matchAll(/\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)/g)].map(x => x[1]);
          const hasSecretRef = varRefs.some(n => /(?:^|_)(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD|CREDENTIAL|AWS|GITHUB)/i.test(n))
            || /\benv\b/i.test(line) || /\$\(/.test(line);
          const hasExternal = /https?:\/\//.test(line);
          const hasPipe = /\|\s*(?:bash|sh|python|node)\b/.test(line);
          const hasAtFile = /(?:^|\s)(?:-d|--data(?:-binary|-raw|-ascii)?|--form|-F|--data-urlencode|--json|-T|--upload-file)\s+["']?@[^\s"']+/.test(line)
            || /\s-[dFT]\S*@/.test(line)
            || /\s--(?:data|form|json|upload-file|data-urlencode)\S*@/.test(line)
            || /[\w"'.-]*=@[\/~.\w-]/.test(line);
          // Client certs, netrc files and inline credentials leave the host.
          const hasCredFlags = /\s(?:--key|--cert|--cacert|--user|-u|--proxy-user|-U|--netrc-file|--login-options|--mail-[\w-]+|--oauth2-bearer)\b/.test(line);
          const fedFromPipe = /(?:^|\n)[^\n]*\|\s*curl\b/.test(text.slice(0, m.index) + line);
          if ((hasExternal && (hasSecretRef || hasAtFile || hasCredFlags)) || hasPipe || fedFromPipe) {
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
        const re = /\bprintenv\b[^\n]*|\b(?:env|printenv)\b[^\n]*\|\s*(?:base64|curl|nc|ncat|wget|xxd|openssl)\b|\bexport\b[^\n]*\|\s*(?:curl|wget|nc|ncat|base64|xxd)\b|\bset\b[^\n]*\|\s*(?:curl|wget|nc|ncat|base64)\b|\bcat\s+\/proc\/(?:self|\d+)\/environ\b|\bcompgen\s+-e\b[^\n]*\|\s*(?:curl|nc|base64)|(?:^|[\n;&|])\s*(?:env|export|set|printenv)\b[ \t]*(?:#[^\n]*)?(?=\n|$)/gi;
        return matchRule(text, re, this, "Environment variable dump - would expose secrets");
      }
    },
    {
      id: "R04-secret-in-url",
      policy: "POL-04",
      severity: 9,
      label: "Secret in URL",
      test(text) {
        const hits = [];
        const re = /https?:\/\/[^\s"'`]*[?&](?:token|key|secret|password|passwd|api_key|api-key|access_token|auth|sig|signature|credential|private_key|privatekey)=[^\s"'`&]+/gi;
        hits.push(...matchRule(text, re, this, "Secret material embedded in URL query string"));
        // user:pass@host userinfo carries credentials in the clear.
        const ui = /https?:\/\/[^\s/"'`]*:[^\s/"'@]*@/gi;
        hits.push(...matchRule(text, ui, this, "Credentials embedded in URL userinfo - sent to the remote host in cleartext"));
        return hits;
      }
    },
    {
      id: "R04-egress-channel",
      policy: "POL-04",
      severity: 10,
      label: "Covert egress channel",
      test(text) {
        const re = /\b(?:nc|ncat|netcat|socat)\b[^\n]*<\s*[^\s]*|\/dev\/tcp\/|\b(?:bash|sh|zsh)\b[^\n]*-i\b[^\n]*>\s*&\s*\/dev\/tcp|\|\s*(?:nc|ncat|netcat|socat)\b[^\n]*|\b(?:nc|ncat|netcat)\b[^\n]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|ksh|python[\d.]*|perl|ruby|node|php)\b|\b(?:rsync|sftp|lftp)\b[^\n]*(?:~\/\.ssh|\/etc\/|\.aws\/|\.env\b|credential|secret|\.pem\b|\.key\b|id_rsa)|\bsftp\b[^\n]*\s-b\b|\brsync\b[^\n]*--files-from\b/gi;
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
      line: scannedLine(match.index, text),
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
      "R01-indirect-command": "Resolve the command name and target to literal values in the plan; never let a variable or substitution pick the binary.",
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
      "R01-merge-delete": "Scope the MERGE predicate to a key and preview matched rows before delete actions run.",
      "R01-git-destructive": "Recreate the state on a new branch and review the diff; never discard work or delete refs directly.",
      "R01-remote-exec": "Download the payload, decode and review it as plain text, then run the reviewed artifact.",
      "R01-host-power": "Schedule power actions through the platform's approved maintenance path with a human sign-off.",
      "R01-docker-bulk": "Stop or remove containers by explicit name after confirming each is unused; never drive mass ops from docker ps.",
      "R01-sql-file-io": "Ban INTO OUTFILE and LOAD_FILE; move file exchange through an audited, allowlisted job.",
      "R02-k8s-rbac-wildcard": "Enumerate the exact apiGroups, resources and verbs the workload needs; never bind cluster-admin.",
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
      "R01-indirect-command": ["compute", "storage"],
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
      "R01-merge-delete": ["postgres"],
      "R01-git-destructive": ["compute", "storage"],
      "R01-remote-exec": ["compute", "storage"],
      "R01-host-power": ["compute"],
      "R01-docker-bulk": ["compute"],
      "R01-sql-file-io": ["postgres", "storage"],
      "R02-k8s-rbac-wildcard": ["iam", "compute"],
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
    const scan = spliceContinuations(norm);
    scanLines = scan.lines;
    const findings = [];
    for (const rule of RULES) {
      try {
        const hits = rule.test(scan.text);
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
    // Unicode escape decoding can shift columns and continuation splices
    // remove characters, so keep the normalized snippet in those cases; it
    // still shows the decoded dangerous command.
    const offsetsStable = input.length === norm.length && scan.text.length === norm.length;
    for (const f of findings) {
      if (typeof f._start === "number") {
        if (offsetsStable) {
          f.snippet = input.slice(f._start, f._start + f._len).trim().slice(0, 140) || f.snippet;
        }
        delete f._start;
        delete f._len;
      }
    }
    // Quoted documentation and shell echoes are not proposed actions. The
    // check runs on the normalized text because \uXXXX escapes can add or
    // remove lines; the finding's line number is already in that space.
    const kept = findings.filter(f => f.rule === "ENGINE-ERROR" || !isDocLine(norm, f.line));
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
