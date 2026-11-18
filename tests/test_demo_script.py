"""Keeps the demo video script honest: valid steps, real selectors, true test counts."""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STEPS = json.loads((ROOT / "video/steps.json").read_text(encoding="utf-8"))
NARRATION = (ROOT / "video/narration.txt").read_text(encoding="utf-8")
HTML = (ROOT / "index.html").read_text(encoding="utf-8")
ALLOWED = {"at", "wait", "scrollTo", "scrollBy", "move", "click", "slide", "type", "select", "key", "eval"}


def test_steps_use_only_supported_actions():
    assert STEPS, "steps.json is empty"
    for step in STEPS:
        assert step["do"] in ALLOWED, step


def test_narration_marks_never_go_backwards():
    marks = [step["s"] for step in STEPS if step["do"] == "at"]
    assert marks == sorted(marks)
    assert 100 <= marks[-1] <= 360, "demo should run roughly two to six minutes"


def test_every_id_in_a_step_selector_exists_in_the_page():
    static_ids = set(re.findall(r'\bid="([^"]+)"', HTML))
    # Panels that a shipped script builds at load time (the receipt panel).
    for script in (ROOT / "js").glob("*.js"):
        static_ids |= set(re.findall(r'\bid="([A-Za-z][\w-]*)"', script.read_text(encoding="utf-8")))
    for step in STEPS:
        selector = step.get("selector", "")
        for ref in re.findall(r"#([A-Za-z][\w-]*)", selector):
            assert ref in static_ids, f"{selector} references missing #{ref}"


def test_narration_test_counts_match_the_real_suites():
    node = re.search(r"(\d+) Node tests", NARRATION)
    py = re.search(r"(\d+) Python tests", NARRATION)
    assert node and py, "narration must state both counts"
    result = subprocess.run(["npm", "test"], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    passed = int(re.search(r"^ℹ pass (\d+)$", result.stdout, re.M).group(1))
    assert int(node.group(1)) == passed
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", str(ROOT / "tests")],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    total = int(re.search(r"(\d+) tests? collected", collected.stdout).group(1))
    assert int(py.group(1)) == total
