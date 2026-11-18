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
    let panel = document.getElementById("receiptPanel");
    if (!panel) {
      const main = document.querySelector("main.studio");
      if (!main) return;
      panel = document.createElement("section");
      panel.id = "receiptPanel";
      panel.className = "panel";
      main.appendChild(panel);
    }
    const body = document.createElement("div");
    body.innerHTML =
      '<dl class="receipt-grid" id="receiptSummary"></dl>' +
      '<button type="button" class="btn btn-ghost btn-sm" id="btnDispatchSandbox">Generate local receipt</button>' +
      '<details class="receipt-raw"><summary>Raw receipt JSON</summary>' +
      '<pre id="vultrSandboxReceipt" aria-live="polite"></pre></details>' +
      '<p class="note">Real policy findings, measured analysis time and a WebCrypto SHA-256 digest. No Vultr container, gVisor process or cloud workload is launched, and a digest is not a signature.</p>';
    panel.appendChild(body);
    const summary = document.getElementById("receiptSummary");
    const row = (k, v, off) => {
      const dt = document.createElement("dt"); dt.textContent = k;
      const dd = document.createElement("dd"); dd.textContent = v;
      if (off) dd.className = "is-off";
      summary.appendChild(dt); summary.appendChild(dd);
    };
    const update = async () => {
      const current = ++generation;
      const output = document.getElementById("vultrSandboxReceipt");
      const editor = document.getElementById("proposalEditor");
      try {
        const receipt = await createReceipt(editor?.value || "");
        if (current !== generation) return;
        output.textContent = JSON.stringify(receipt, null, 2);
        summary.textContent = "";
        row("SHA-256", receipt.receipt_sha256);
        row("Score", String(receipt.score) + "/100, " + receipt.findings.length + " finding" + (receipt.findings.length === 1 ? "" : "s"));
        row("Analysis time", receipt.elapsed_ms.toFixed(2) + " ms (measured)");
        row("Execution", "not performed, not authorized", true);
        row("Cloud", "not connected", true);
      } catch (_) {
        if (current === generation) {
          output.textContent = "Analysis failed. Execution remains unauthorized.";
          summary.textContent = "";
          row("Status", "Analysis failed. Execution remains unauthorized.", true);
        }
      }
    };
    document.getElementById("btnDispatchSandbox").addEventListener("click", update);
    let timer = null;
    document.getElementById("proposalEditor")?.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(update, 200);
    });
    // Editor changes made by buttons do not fire "input"; refresh after any click in the studio.
    document.querySelector("main.studio")?.addEventListener("click", () => {
      clearTimeout(timer);
      timer = setTimeout(update, 200);
    });
    update();
  }
  root.BlastReceipt = { createReceipt };
  if (typeof module !== "undefined") module.exports = root.BlastReceipt;
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", createPanel);
    else createPanel();
  }
})(typeof window === "undefined" ? globalThis : window);
