/**
 * Scoring.js — Risk scoring engine
 * Aggregates findings from all analysis layers into a single weighted score + verdict.
 */

/**
 * Category weights — controls how much each detection layer contributes.
 * Weight 1.0 = full trust in the signal.
 * Weight < 1.0 = discount for higher false-positive rates.
 */
var CATEGORY_WEIGHTS = {
  'authentication': 1.0,   // SPF/DKIM/DMARC — binary, high confidence
  'sender':         1.0,   // Reply-to mismatch, spoofing — direct trust signal
  'content':        0.7,   // Keywords, URLs — heuristic, can have false positives
  'attachment':     1.0,   // Dangerous files — high confidence when triggered
  'enrichment':     0.9,   // VirusTotal — depends on API availability
  'blacklist':      1.0    // User explicit intent
};

/**
 * Calculates the final risk score from an array of findings.
 * @param {Object[]} findings - Array of finding objects from analysis modules
 * @return {Object} { score, verdict, verdictIcon, color, findings, summary }
 */
function calculateScore(findings) {
  if (!findings || findings.length === 0) {
    return {
      score: 0,
      verdict: getVerdict(0),
      verdictIcon: getVerdictIcon(0),
      color: getScoreColor(0),
      findings: [],
      summary: 'No suspicious signals detected.'
    };
  }

  var totalScore = 0;

  for (var i = 0; i < findings.length; i++) {
    var f = findings[i];
    var weight = CATEGORY_WEIGHTS[f.category] || 1.0;
    totalScore += f.score * weight;
  }

  // Cap score at 0-100
  var finalScore = Math.min(100, Math.max(0, Math.round(totalScore)));

  // Build summary narrative
  var summary = buildThreatNarrative(findings, finalScore);

  return {
    score: finalScore,
    verdict: getVerdict(finalScore),
    verdictIcon: getVerdictIcon(finalScore),
    color: getScoreColor(finalScore),
    findings: findings,
    summary: summary
  };
}

/**
 * Builds a human-readable threat narrative from findings.
 * Inspired by Upwind's Threat Stories — correlates signals into an explanation.
 * @param {Object[]} findings - Array of findings
 * @param {number} score - Final score
 * @return {string} Narrative text
 */
function buildThreatNarrative(findings, score) {
  if (findings.length === 0) {
    return 'No suspicious signals detected. This email appears safe.';
  }

  // Group findings by category
  var groups = {};
  for (var i = 0; i < findings.length; i++) {
    var cat = findings[i].category;
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(findings[i]);
  }

  var parts = [];

  if (groups['authentication']) {
    var authSignals = groups['authentication'].map(function(f) { return f.signal; });
    parts.push('Email authentication issues detected (' + authSignals.join(', ') + ')');
  }

  if (groups['sender']) {
    var senderSignals = groups['sender'].map(function(f) { return f.signal; });
    parts.push('Sender anomalies found (' + senderSignals.join(', ') + ')');
  }

  if (groups['content']) {
    parts.push(groups['content'].length + ' suspicious content signal' + (groups['content'].length > 1 ? 's' : '') + ' detected');
  }

  if (groups['attachment']) {
    parts.push(groups['attachment'].length + ' attachment risk' + (groups['attachment'].length > 1 ? 's' : '') + ' identified');
  }

  if (groups['enrichment']) {
    var vtMalicious = groups['enrichment'].some(function(f) { return f.score > 0; });
    if (vtMalicious) {
      parts.push('External threat intelligence flagged this email');
    } else {
      parts.push('VirusTotal scan came back clean');
    }
  }

  if (groups['blacklist']) {
    parts.push('Sender matches your personal blacklist');
  }

  var narrative = parts.join('. ') + '.';

  if (score >= 66) {
    narrative += ' Exercise extreme caution with this email.';
  } else if (score >= 41) {
    narrative += ' Review this email carefully before taking any action.';
  }

  return narrative;
}

/**
 * Groups findings by category for display.
 * @param {Object[]} findings - Array of finding objects
 * @return {Object} Map of category → findings[]
 */
function groupFindingsByCategory(findings) {
  var groups = {};
  for (var i = 0; i < findings.length; i++) {
    var cat = findings[i].category;
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(findings[i]);
  }
  return groups;
}

/**
 * Returns a status label for a category based on its findings.
 * @param {Object[]} categoryFindings - Findings for one category (may be undefined)
 * @return {string} "PASS", "WARNING", "FAIL", or "OK"
 */
function getCategoryStatus(categoryFindings) {
  if (!categoryFindings || categoryFindings.length === 0) return 'PASS';

  var maxSeverity = 'info';
  for (var i = 0; i < categoryFindings.length; i++) {
    var sev = categoryFindings[i].severity;
    if (sev === 'critical') return 'FAIL';
    if (sev === 'high') maxSeverity = 'high';
    else if (sev === 'medium' && maxSeverity !== 'high') maxSeverity = 'medium';
    else if (sev === 'low' && maxSeverity === 'info') maxSeverity = 'low';
  }

  if (maxSeverity === 'high') return 'FAIL';
  if (maxSeverity === 'medium') return 'WARNING';
  if (maxSeverity === 'low') return 'WARNING';
  return 'PASS';
}
