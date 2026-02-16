/**
 * Utils.js — Shared utility functions
 */

/**
 * Extracts the domain from an email address.
 * "John Doe <john@example.com>" → "example.com"
 * "john@example.com" → "example.com"
 * @param {string} emailStr - Raw email string (may include display name)
 * @return {string} The domain, or empty string if not found
 */
function extractDomain(emailStr) {
  if (!emailStr) return '';
  var match = emailStr.match(/@([^\s>]+)/);
  return match ? match[1].toLowerCase() : '';
}

/**
 * Extracts the raw email address from a display string.
 * "John Doe <john@example.com>" → "john@example.com"
 * "john@example.com" → "john@example.com"
 * @param {string} emailStr - Raw email string
 * @return {string} The email address, or the original string
 */
function extractEmail(emailStr) {
  if (!emailStr) return '';
  var match = emailStr.match(/<([^>]+)>/);
  return match ? match[1].toLowerCase() : emailStr.toLowerCase().trim();
}

/**
 * Creates a standardized finding object.
 * All analysis modules produce findings in this format.
 * @param {string} category - e.g., "authentication", "sender", "content", "attachment", "enrichment", "blacklist"
 * @param {string} signal - Short signal name, e.g., "SPF Fail"
 * @param {string} detail - Human-readable explanation
 * @param {number} score - Points to add (0-100)
 * @param {string} severity - "low", "medium", "high", or "critical"
 * @return {Object} A finding object
 */
function createFinding(category, signal, detail, score, severity) {
  return {
    category: category,
    signal: signal,
    detail: detail,
    score: score,
    severity: severity
  };
}

/**
 * Returns a color hex code based on a score.
 * @param {number} score - 0 to 100
 * @return {string} Hex color code
 */
function getScoreColor(score) {
  if (score <= 15) return '#4CAF50';  // Green — safe
  if (score <= 40) return '#8BC34A';  // Yellow-green — low risk
  if (score <= 65) return '#FF9800';  // Orange — medium risk
  if (score <= 85) return '#F44336';  // Red — high risk
  return '#B71C1C';                   // Dark red — critical
}

/**
 * Returns a verdict label based on a score.
 * @param {number} score - 0 to 100
 * @return {string} Verdict text
 */
function getVerdict(score) {
  if (score <= 15) return 'SAFE';
  if (score <= 40) return 'LOW RISK';
  if (score <= 65) return 'MEDIUM RISK';
  if (score <= 85) return 'HIGH RISK';
  return 'CRITICAL';
}

/**
 * Returns a verdict icon based on a score.
 * @param {number} score - 0 to 100
 * @return {string} Icon character
 */
function getVerdictIcon(score) {
  if (score <= 15) return '✅';
  if (score <= 40) return '⚠️';
  if (score <= 65) return '🔶';
  if (score <= 85) return '🔴';
  return '🚨';
}

/**
 * Builds a simple text-based progress bar.
 * @param {number} score - 0 to 100
 * @return {string} Visual bar like "████████░░░░░░░░░░░░ 40%"
 */
function buildScoreBar(score) {
  var filled = Math.round(score / 5);
  var empty = 20 - filled;
  return '█'.repeat(filled) + '░'.repeat(empty) + ' ' + score + '%';
}
