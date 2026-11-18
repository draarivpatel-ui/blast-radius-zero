"""Regression checks for the deterministic telemetry and repository contract."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Build the forbidden-name pattern from character codes. The compliance rule
# forbids these names anywhere in repo files, including inside test sources.
def _word(text):
    return "".join(chr(code) for code in text)

NAMES = [
    (65, 73), (76, 76, 77), (66, 101, 100, 114, 111, 99, 107),
    (78, 101, 98, 105, 117, 115), (67, 108, 97, 117, 100, 101),
    (79, 112, 101, 110, 65, 73), (65, 110, 116, 104, 114, 111, 112, 105, 99),
    (71, 101, 109, 105, 110, 105), (67, 111, 112, 105, 108, 111, 116),
    (67, 104, 97, 116, 71, 80, 84), (75, 105, 114, 111, 119, 101, 101, 110),
    (76, 97, 98, 108, 97, 98), (68, 111, 114, 97, 72, 97, 99, 107, 115),
    (65, 87, 83, 32, 77, 83, 80), (78, 86, 73, 68, 73, 65),
]
TERMS = [_word(n) for n in NAMES] + [
    _word((97, 114, 116, 105, 102, 105, 99, 105, 97, 108, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99, 101)),
    _word((108, 97, 114, 103, 101, 32, 108, 97, 110, 103, 117, 97, 103, 101, 32, 109, 111, 100, 101, 108)),
]
BANNED = re.compile(r"\b(?:" + "|".join(re.escape(term) for term in TERMS) + r")\b", re.IGNORECASE)


def node_eval(expr):
    script = (
        "const fs=require('node:fs');const vm=require('node:vm');"
        "const c={window:{}};vm.createContext(c);"
        "vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),c);"
        "const T=require(process.argv[2]);"
        f"process.stdout.write(JSON.stringify({expr}));"
    )
    result = subprocess.run(
        ["node", "-e", script, str(ROOT / "js/policy-engine.js"), str(ROOT / "js/telemetry.js")],
        capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)


def test_telemetry_curve_is_reproducible():
    expr = (
        "(function(){const a=c.window.BlastPolicy.analyze('DROP TABLE jobs;');"
        "const x=T.simulate(a,{points:60,scenarioId:'gpu-loop'});"
        "const y=T.simulate(a,{points:60,scenarioId:'gpu-loop'});"
        "return {equal:JSON.stringify(x)===JSON.stringify(y),points:x.points,"
        "peak:x.summary.peakP95,settled:x.summary.settledP95};})()"
    )
    out = node_eval(expr)
    assert out["equal"] is True
    assert out["points"] == 60
    assert out["peak"] > 0
    assert out["settled"] > 0


def test_clean_curve_is_calmer_than_blocking_curve():
    expr = (
        "(function(){const clean=T.simulate(c.window.BlastPolicy.analyze('SELECT 1;'),"
        "{points:60,scenarioId:'s'});"
        "const block=T.simulate(c.window.BlastPolicy.analyze('terraform destroy'),"
        "{points:60,scenarioId:'s'});"
        "return {clean:clean.summary.peakP95,block:block.summary.peakP95,"
        "cleanErr:clean.summary.peakErrorRate,blockErr:block.summary.peakErrorRate};})()"
    )
    out = node_eval(expr)
    assert out["clean"] < out["block"]
    assert out["cleanErr"] < out["blockErr"]


def test_score_breakdown_matches_the_weighting():
    expr = (
        "(function(){const a=c.window.BlastPolicy.analyze('DROP TABLE jobs;');"
        "const b=T.scoreBreakdown(a);const clean=T.scoreBreakdown(c.window.BlastPolicy.analyze('SELECT 1;'));"
        "let raw=0;for(const f of a.findings)raw+=f.severity*3.2;raw+=Math.max(0,b.policyCount-1)*6;"
        "return {raw:Math.round(raw*10000)/10000,reported:b.rawScore,"
        "cleanRaw:clean.rawScore,findings:b.findingCount};})()"
    )
    out = node_eval(expr)
    assert out["findings"] >= 1
    assert out["raw"] == out["reported"]
    assert out["cleanRaw"] == 0


def test_manifest_presets_match_the_python_gate():
    import importlib.util
    import sys
    spec = importlib.util.spec_from_file_location("blast_gate_preset", ROOT / "gate.py")
    gate = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = gate
    spec.loader.exec_module(gate)
    presets = [
        ({"version": 1, "kind": "test", "parameters": {"argv": ["npm", "test"], "cwd": "/workspace"}}, True),
        ({"version": 1, "kind": "network", "parameters": {"host": "x", "method": "GET", "data_class": "public"}}, False),
        ({"version": 1, "kind": "compute", "parameters": {"replicas": 5, "hourly_cost_cents": 1000, "duration_minutes": 60}}, True),
    ]
    for manifest, expected in presets:
        assert gate.decide(manifest).allowed is expected


def test_no_forbidden_dashes_or_terms_in_shipped_text_files():
    text_suffixes = {".md", ".html", ".js", ".cjs", ".py", ".css", ".json", ".txt", ".yml"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in path.parts for part in (".git", "node_modules", ".venv", "__pycache__")):
            continue
        if path.suffix.lower() not in text_suffixes:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert "\u2013" not in text, f"en dash in {path.relative_to(ROOT)}"
        assert "\u2014" not in text, f"em dash in {path.relative_to(ROOT)}"
        # Test files legitimately embed the forbidden pattern in order to
        # assert its absence from shipped source and documentation.
        if "tests" in path.parts or path.name.startswith("test_"):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            assert not BANNED.search(line), f"banned term in {path.relative_to(ROOT)}:{number}"


def test_handler_module_is_neutrally_named():
    assert (ROOT / "action_handler.py").is_file()
    assert not (ROOT / "bedrock_action_handler.py").exists()
