/* Honest local analysis receipts. This module does not create cloud sandboxes. */
(function (root) {
  "use strict";
  let generation = 0;
  async function createReceipt(text) {
    const begin = performance.now();
    if (!root.BlastPolicy) throw new Error("Policy engine unavailable; approval denied");
    const analysis = root.BlastPolicy.analyze(text);
    const material = JSON.stringify({
      version: 2, proposal: text,
      rules: analysis.findings.map(f => ({rule: f.rule, line: f.line, severity: f.severity})),
      score: analysis.score,
    });
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material));
    return {
      receipt_version: 2, engine: "BlastPolicy heuristic diagnostics",
      score: analysis.score, findings: analysis.findings.map(f => ({rule: f.rule, line: f.line, severity: f.severity})),
      text_scan_clean: analysis.clean, execution_authorized: false,
      cloud_connection: "not_connected", execution: "not_performed",
      container_isolation: "not_demonstrated", receipt_sha256: Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join(""),
      elapsed_ms: performance.now() - begin,
      note: "A SHA-256 digest is not a digital signature or a cloud execution receipt",
    };
  }
  function createPanel() {
    const main = document.querySelector("main.studio");
    if (!main) return;
    const panel = document.createElement("section");
    panel.id = "vultrSandboxBar";
    panel.style.cssText = "grid-column:1/-1;padding:16px;border:1px solid #334155;border-radius:8px";
    panel.innerHTML = '<h2>Local Policy Analysis Receipt</h2>' +
      '<p>Real policy findings, measured analysis time and a WebCrypto SHA-256 digest. No Vultr container, gVisor process or cloud workload is launched.</p>' +
      '<button class="btn-primary btn-sm" id="btnDispatchSandbox">Generate Local Receipt</button>' +
      '<pre id="vultrSandboxReceipt" aria-live="polite" style="white-space:pre-wrap;overflow-wrap:anywhere"></pre>';
    main.appendChild(panel);
    const update = async () => {
      const current = ++generation;
      const output = document.getElementById("vultrSandboxReceipt");
      const editor = document.getElementById("proposalEditor");
      try {
        const receipt = await createReceipt(editor?.value || "");
        if (current === generation) output.textContent = JSON.stringify(receipt, null, 2);
      } catch (_) {
        if (current === generation) output.textContent = "Analysis failed. Execution remains unauthorized.";
      }
    };
    document.getElementById("btnDispatchSandbox").addEventListener("click", update);
    document.getElementById("proposalEditor")?.addEventListener("input", update);
    update();
  }
  root.BlastReceipt = { createReceipt };
  if (typeof module !== "undefined") module.exports = root.BlastReceipt;
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", createPanel);
    else createPanel();
  }
})(typeof window === "undefined" ? globalThis : window);
