# Builds video/narration.txt and video/steps.json for BlastRadius Zero.
# Usage: python3 video/build_steps.py <node test count> <python test count> video
# Times are estimates at RATE words per second until real narration audio exists;
# re-time the "at" marks against the recorded narration before the final capture.
import json, re, sys
RATE = 2.5      # words per second, typical narration pace
GAP = 0.7       # pause between paragraphs, seconds
LEAD = 1.5      # silence before the first word
paras = [
"Autonomous agents now propose real infrastructure changes in the middle of an incident. One bad command can wipe a database or leak every secret. BlastRadius Zero is a firewall that checks each plan before anything runs, and it works completely offline.",
"Here is a runaway GPU billing loop. The agents proposed scaling to 48 GPUs, flushing the cache and force deleting pods. The verdict is BLOCKED, with a blast score of 89. The console names the rule that decided it: R03 GPU scale, on line 6.",
"The rule inspector explains every finding. Click R01 flushall. It shows the matched line, the policy, the fix, and the resources it reaches. The same line is flagged in the plan editor, and the map outlines the Redis cluster.",
"Now load a benign plan, a rolling restart. ALLOW, score zero. Inject a DROP TABLE, and the gate flips to BLOCKED right away. An autoscaler with a ceiling of fifty is not destructive, but it can blow the budget, so the verdict is APPROVAL REQUIRED.",
"Switch to the destructive migration. Seven findings, score 100. Flip the map to after containment. The safe plan keeps all four resources out of the blast radius, and the diff shows exactly which lines change. Apply the safe plan, and the verdict drops to ALLOW, score zero.",
"Text scanning explains a plan, but the typed action gate makes the real decision, one structured action at a time. A test run is allowed. Network egress is denied. A path that escapes the workspace is denied.",
"Every number comes from the real rules and a fixed seed, so a replay is identical. The page exports JSON, Markdown and SARIF audits, plus a local SHA-256 receipt. Nothing is executed, and nothing leaves the browser. NODECOUNT Node tests and PYCOUNT Python tests pass.",
]
node_count, py_count = sys.argv[1], sys.argv[2]
paras = [p.replace("NODECOUNT", node_count).replace("PYCOUNT", py_count) for p in paras]
words = [p.split() for p in paras]
starts = []; t = LEAD
for w in words:
    starts.append(t); t += len(w) / RATE + GAP
total = t
def at(pi, phrase):
    """Estimated time the phrase starts being spoken inside paragraph pi."""
    toks = paras[pi].split(); ph = phrase.split()
    for i in range(len(toks)):
        if [re.sub(r'\W', '', x).lower() for x in toks[i:i+len(ph)]] == [re.sub(r'\W', '', x).lower() for x in ph]:
            return round(starts[pi] + i / RATE, 1)
    raise SystemExit(f"phrase not found: {phrase!r} in paragraph {pi}")
S = []
A = lambda s: S.append({"do": "at", "s": s})
S += [{"do": "eval", "js": "window.scrollTo(0, 0)"}, {"do": "wait", "ms": 600},
      {"do": "move", "selector": "#verdictWord", "ms": 1600}]
A(at(0, "BlastRadius Zero is")); S += [{"do": "move", "selector": "#hdrGateStatus", "ms": 1200}]
# Paragraph 1: the GPU loop
A(at(1, "Here is a runaway")); S += [{"do": "move", "selector": "#scenarioGrid button[data-id=\"gpu-loop\"]", "ms": 900}]
A(at(1, "The agents proposed")); S += [{"do": "move", "selector": "#proposalEditor", "ms": 1000}]
A(at(1, "The verdict is BLOCKED")); S += [{"do": "move", "selector": "#scoreNum", "ms": 900}]
A(at(1, "The console names")); S += [{"do": "move", "selector": "#blastTitle code", "ms": 1000}]
# Paragraph 2: inspector
A(at(2, "The rule inspector")); S += [{"do": "move", "selector": "#findingsList", "ms": 900}]
A(at(2, "Click R01 flushall")); S += [{"do": "click", "selector": "#findingsList .finding:nth-child(1)", "ms": 800}]
A(at(2, "It shows the matched")); S += [{"do": "move", "selector": "#ruleDetail .rd-match", "ms": 900}]
A(at(2, "The same line is flagged")); S += [{"do": "move", "selector": "#editorGutter span:nth-child(12)", "ms": 1000}]
A(at(2, "the map outlines")); S += [{"do": "move", "selector": ".topo-node[data-id=\"redis\"]", "ms": 1000}]
# Paragraph 3: benign, attack, approval
A(at(3, "Now load a benign")); S += [{"do": "click", "selector": "#injectRow button:nth-child(1)", "ms": 900}]
A(at(3, "ALLOW, score zero")); S += [{"do": "move", "selector": "#verdictWord", "ms": 900}]
A(at(3, "Inject a DROP TABLE")); S += [{"do": "click", "selector": "#btnInjectDrop", "ms": 900}]
A(at(3, "An autoscaler with")); S += [{"do": "click", "selector": "#injectRow button:nth-child(3)", "ms": 900}]
A(at(3, "so the verdict is")); S += [{"do": "move", "selector": "#verdictWord", "ms": 900}]
# Paragraph 4: containment
A(at(4, "Switch to the destructive")); S += [{"do": "click", "selector": "#scenarioGrid button[data-id=\"destructive-migration\"]", "ms": 900}]
A(at(4, "Seven findings")); S += [{"do": "move", "selector": "#ruleCount", "ms": 900}]
A(at(4, "Flip the map")); S += [{"do": "click", "selector": "#graphContained", "ms": 900}]
A(at(4, "The safe plan keeps")); S += [{"do": "move", "selector": "#graphNote", "ms": 900}]
A(at(4, "and the diff shows")); S += [{"do": "scrollTo", "selector": "#hDiff", "ms": 1400, "offset": 120}, {"do": "move", "selector": "#diffView", "ms": 800}]
A(at(4, "Apply the safe plan")); S += [{"do": "scrollTo", "selector": "#verdictConsole", "ms": 1200, "offset": 90}, {"do": "click", "selector": "#btnSafeFix", "ms": 800}]
A(at(4, "the verdict drops")); S += [{"do": "move", "selector": "#verdictWord", "ms": 800}]
# Paragraph 5: typed action gate
A(at(5, "Text scanning explains")); S += [{"do": "scrollTo", "selector": "#manifestPanel", "ms": 1800, "offset": 110}]
A(at(5, "A test run is allowed")); S += [{"do": "click", "selector": "#manifest-presets button:nth-child(1)", "ms": 900}]
A(at(5, "Network egress is denied")); S += [{"do": "click", "selector": "#manifest-presets button:nth-child(4)", "ms": 900}]
A(at(5, "A path that escapes")); S += [{"do": "click", "selector": "#manifest-presets button:nth-child(5)", "ms": 900}]
# Paragraph 6: determinism, exports, receipt, tests
A(at(6, "Every number comes")); S += [{"do": "scrollTo", "selector": "#hDry", "ms": 1500, "offset": 120}, {"do": "click", "selector": "#btnReplayDryRun", "ms": 900}]
A(at(6, "The page exports")); S += [{"do": "scrollTo", "selector": "#hExport", "ms": 1200, "offset": 360}, {"do": "move", "selector": "#btnExportSarif", "ms": 800}]
A(at(6, "plus a local")); S += [{"do": "scrollTo", "selector": "#receiptPanel", "ms": 1400, "offset": 110}, {"do": "move", "selector": "#receiptSummary", "ms": 800}]
A(at(6, "Nothing is executed")); S += [{"do": "scrollTo", "selector": "#verdictConsole", "ms": 1500, "offset": 90}, {"do": "move", "selector": "#verdictWord", "ms": 900}]
A(round(total + 1.0, 1))
open(sys.argv[3] + "/narration.txt", "w").write("\n\n".join(paras) + "\n")
open(sys.argv[3] + "/steps.json", "w").write("[\n" + ",\n".join("  " + json.dumps(s) for s in S) + "\n]\n")
print("words", sum(len(w) for w in words), "estimated seconds", round(total + 1.0, 1))
