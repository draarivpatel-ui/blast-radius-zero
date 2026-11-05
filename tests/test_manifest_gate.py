import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("blast_gate_test", ROOT / "gate.py")
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)


def action(kind, **parameters):
    return {"version": 1, "kind": kind, "parameters": parameters}


CASES = [
    (action("read", path="/workspace/src/main.py"), True),
    (action("read", path="/workspace/../private"), False),
    (action("read", path="/workspace-other/file"), False),
    (action("read", path="/workspace//file"), False),
    (action("test", argv=["npm", "test"], cwd="/workspace"), True),
    (action("test", argv=["sh", "-c", "pytest"], cwd="/workspace"), False),
    (action("delete", path="/workspace/build/cache", dry_run=True), True),
    (action("delete", path="/workspace/build/cache", dry_run=False), False),
    (action("iam", actions=["s3:GetObject"], resources=["arn:aws:s3:::contest-demo/*"], effect="Allow"), True),
    (action("iam", actions=["iam:*"], resources=["*"], effect="Allow"), False),
    (action("network", host="localhost", method="GET", data_class="public"), False),
    ({}, False), (None, False), (action("unknown"), False),
]
CASES += [(action("compute", replicas=replicas, hourly_cost_cents=cents, duration_minutes=minutes),
           type(replicas) is int and type(cents) is int and type(minutes) is int
           and 1 <= replicas <= 1000 and 0 <= cents <= 1000000 and 1 <= minutes <= 60 and replicas * cents <= 5000)
          for replicas in (1, 5, True) for cents in (0, 1000, 1001, 5001) for minutes in (1, 60, 61)]


@pytest.mark.parametrize("manifest,expected", CASES)
def test_policy_oracle_and_browser_parity(manifest, expected):
    result = gate.decide(manifest)
    assert result.allowed is expected
    script = "const fs=require('node:fs');const g=require(process.argv[1]);process.stdout.write(JSON.stringify(g.decide(JSON.parse(fs.readFileSync(0,'utf8')))));"
    node = subprocess.run(["node", "-e", script, str(ROOT / "js/manifest-gate.js")],
                          input=json.dumps(manifest), capture_output=True, text=True, check=True)
    browser = json.loads(node.stdout)
    assert browser["allowed"] is result.allowed
    assert browser["rules"] == list(result.rules)


def test_manifest_digest_and_policy_are_stable():
    original = action("read", path="/workspace/src/main.py")
    reordered = dict(reversed(list(original.items())))
    assert gate.decide(original).manifest_sha256 == gate.decide(reordered).manifest_sha256
    assert len(gate.decide(original).policy_sha256) == 64


def test_non_json_and_nan_fail_closed():
    assert not gate.decide(action("compute", replicas=1, hourly_cost_cents=float("nan"), duration_minutes=1)).allowed
    assert not gate.decide({"version": 1, "kind": "read", "parameters": {"path": object()}}).allowed
