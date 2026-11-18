/*
 * BlastRadius Zero - deterministic incident telemetry and scanner coverage.
 *
 * Every curve here is a reproducible function of the analysis score, the
 * scenario id and a fixed seed. No Math.random, no Date.now and no network.
 * The dry-run chart in app.js consumes these series so repeated replays of
 * the same proposal produce byte-identical numbers.
 *
 * Browser global: BlastTelemetry. Node: module.exports.
 */
(function (root) {
  "use strict";

  /* Mulberry32, kept local so this module has no load-order dependency. */
  function seeded(seed) {
    var a = seed >>> 0;
    return function () {
      a = (a + 0x6d2b79f5) >>> 0;
      var t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function hashString(str) {
    var h = 0x811c9dc5;
    var s = String(str);
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h >>> 0;
  }

  function round(value, places) {
    var f = Math.pow(10, places == null ? 4 : places);
    return Math.round(value * f) / f;
  }

  /*
   * Reproducible dry-run curves. `analysis` is the real policy engine result.
   * A clean proposal starts at a healthy baseline; findings raise the incident
   * severity in proportion to the actual blast score. All jitter comes from a
   * seed derived from the scenario id and the serialized findings.
   */
  function simulate(analysis, options) {
    var opts = options || {};
    var points = Math.max(10, Math.min(240, Math.floor(opts.points || 60)));
    var gateIndex = Math.floor(points * (opts.gateFraction == null ? 0.42 : opts.gateFraction));
    var score = analysis ? Math.max(0, Math.min(100, analysis.score || 0)) : 0;
    var clean = analysis ? Boolean(analysis.clean) : true;
    var findings = analysis && Array.isArray(analysis.findings) ? analysis.findings.length : 0;
    var scenarioId = opts.scenarioId || "default";
    var seedMaterial = scenarioId + "|" + score + "|" + findings + "|" +
      (analysis && analysis.findings ? analysis.findings.map(function (f) {
        return f.rule + ":" + f.line;
      }).join(",") : "");
    var rand = seeded(hashString(seedMaterial) ^ (opts.seed == null ? 0x5eed : opts.seed >>> 0));

    /* Small deterministic wobble in [-1, 1]. */
    function wobble() { return rand() * 2 - 1; }

    var baselineP95 = clean ? 240 : 420 + score * 6.2;
    var peakP95 = clean ? 320 : 900 + score * 9.5;
    var baselineError = clean ? 0.25 : 0.9 + score * 0.025;
    var peakError = clean ? 0.55 : 2.4 + score * 0.035;

    var t = [];
    var p95 = [];
    var errorRate = [];
    var safePath = [];
    var queueDepth = [];

    for (var i = 0; i < points; i++) {
      var phase = i / (points - 1);
      var pre = i < gateIndex;
      t.push(i);
      if (pre) {
        var ramp = gateIndex > 1 ? i / gateIndex : 0;
        p95.push(round(baselineP95 + (peakP95 - baselineP95) * ramp + wobble() * 28, 3));
        errorRate.push(round(baselineError + (peakError - baselineError) * ramp + wobble() * 0.18, 4));
        queueDepth.push(round(12 + (peakP95 / 12) * ramp + wobble() * 6, 2));
        safePath.push(round(baselineP95 + (peakP95 - baselineP95) * ramp, 3));
      } else {
        var decay = (i - gateIndex) / Math.max(1, points - gateIndex - 1);
        var recovery = Math.exp(-decay * (clean ? 4.5 : 3.1));
        p95.push(round(240 + (peakP95 - 240) * recovery + wobble() * 9, 3));
        errorRate.push(round(Math.max(0.08, peakError * Math.exp(-decay * 3.9) + wobble() * 0.05), 4));
        queueDepth.push(round(Math.max(2, (peakP95 / 12) * Math.exp(-decay * 3.4) + wobble() * 2), 2));
        safePath.push(round(220 + 160 * Math.exp(-decay * 4.8) + wobble() * 4, 3));
      }
    }

    var peak = Math.max.apply(null, p95);
    var settled = p95[points - 1];
    var recovered = safePath[points - 1];
    return {
      points: points,
      gateIndex: gateIndex,
      score: score,
      clean: clean,
      findingCount: findings,
      seed: hashString(seedMaterial),
      t: t,
      p95: p95,
      errorRate: errorRate,
      safePath: safePath,
      queueDepth: queueDepth,
      summary: {
        peakP95: round(peak, 3),
        settledP95: round(settled, 3),
        safeSettledP95: round(recovered, 3),
        peakErrorRate: round(Math.max.apply(null, errorRate), 4),
        settledErrorRate: round(errorRate[points - 1], 4),
        recoveryRatio: peak > 0 ? round(settled / peak, 5) : 1,
        latencySavedMs: round(peak - recovered, 3),
        simulated: true,
        note: "Deterministic modeled curves from the real policy score, not a production measurement"
      }
    };
  }

  /*
   * Decompose a blast score into per-policy contributions using the actual
   * findings. Severity weighting mirrors the policy engine, but the result is
   * broken out so the interface can explain where the number came from.
   */
  function scoreBreakdown(analysis) {
    var byPolicy = {};
    var bySeverity = { block: 0, warn: 0, note: 0 };
    var findings = analysis && Array.isArray(analysis.findings) ? analysis.findings : [];
    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      var bucket = byPolicy[f.policy] || (byPolicy[f.policy] = { count: 0, severitySum: 0, maxSeverity: 0, rules: [] });
      bucket.count += 1;
      bucket.severitySum += f.severity;
      if (f.severity > bucket.maxSeverity) bucket.maxSeverity = f.severity;
      if (bucket.rules.indexOf(f.rule) === -1) bucket.rules.push(f.rule);
      if (f.severity >= 8) bySeverity.block += 1;
      else if (f.severity >= 6) bySeverity.warn += 1;
      else bySeverity.note += 1;
    }
    var raw = 0;
    for (var j = 0; j < findings.length; j++) raw += findings[j].severity * 3.2;
    raw += Math.max(0, Object.keys(byPolicy).length - 1) * 6;
    return {
      findingCount: findings.length,
      policyCount: Object.keys(byPolicy).length,
      byPolicy: byPolicy,
      bySeverity: bySeverity,
      rawScore: round(raw, 4),
      reportedScore: analysis ? analysis.score : 0,
      affectedCount: analysis && analysis.affected ? analysis.affected.length : 0,
      distinctRules: (function () {
        var set = {};
        for (var k = 0; k < findings.length; k++) set[findings[k].rule] = 1;
        return Object.keys(set).length;
      }())
    };
  }

  /* Which scanner rules fired, which stayed silent, and per-policy coverage. */
  function scannerCoverage(analysis, rules) {
    var all = rules || [];
    var fired = {};
    var findings = analysis && Array.isArray(analysis.findings) ? analysis.findings : [];
    for (var i = 0; i < findings.length; i++) {
      if (findings[i].rule === "ENGINE-ERROR") continue;
      fired[findings[i].rule] = (fired[findings[i].rule] || 0) + 1;
    }
    var byPolicy = {};
    for (var a = 0; a < all.length; a++) {
      var r = all[a];
      var p = byPolicy[r.policy] || (byPolicy[r.policy] = { total: 0, fired: 0, hits: 0 });
      p.total += 1;
      if (fired[r.id]) { p.fired += 1; p.hits += fired[r.id]; }
    }
    return {
      ruleCount: all.length,
      firedRuleCount: Object.keys(fired).length,
      totalHits: findings.length,
      byPolicy: byPolicy,
      errorFindings: findings.filter(function (f) { return f.rule === "ENGINE-ERROR"; }).length,
      fired: fired
    };
  }

  /* FNV-1a fingerprint of the analysis. This uint32 is not a digital signature. */
  function analysisSignature(analysis) {
    if (!analysis) return hashString("empty");
    var material = (analysis.findings || []).map(function (f) {
      return [f.rule, f.policy, f.severity, f.line, f.snippet].join("|");
    }).join(";") + "#" + analysis.score;
    return hashString(material);
  }

  var api = {
    seeded: seeded,
    hashString: hashString,
    simulate: simulate,
    scoreBreakdown: scoreBreakdown,
    scannerCoverage: scannerCoverage,
    analysisSignature: analysisSignature
  };
  root.BlastTelemetry = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window === "undefined" ? globalThis : window);
