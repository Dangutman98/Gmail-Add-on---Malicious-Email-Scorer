/**
 * History.js — Scan history and action tracking
 * Saves scan results and user actions to PropertiesService.
 * Provides adaptive scoring data based on past behavior.
 *
 * Storage keys:
 *   'scan_history'  → JSON array of scan entries (capped at 50)
 *   'action_history' → JSON array of action entries (capped at 100)
 */

var MAX_SCAN_HISTORY = 50;
var MAX_ACTION_HISTORY = 100;

// ============================================================
// SCAN HISTORY
// ============================================================

/**
 * Saves a scan result to history.
 * @param {GmailMessage} message - The scanned email
 * @param {Object} scoreResult - Result from calculateScore()
 */
function saveScanHistory(message, scoreResult) {
  try {
    var from = message.getFrom() || '';
    var entry = {
      timestamp: new Date().toISOString(),
      messageId: message.getId(),
      subject: (message.getSubject() || '').substring(0, 80),
      from: from,
      email: extractEmail(from),
      domain: extractDomain(from),
      score: scoreResult.score,
      verdict: scoreResult.verdict,
      signalCount: scoreResult.findings.length,
      categories: getUniqueCategories(scoreResult.findings)
    };

    var history = getScanHistory();
    history.unshift(entry);

    // Cap at max entries
    if (history.length > MAX_SCAN_HISTORY) {
      history = history.slice(0, MAX_SCAN_HISTORY);
    }

    PropertiesService.getUserProperties().setProperty('scan_history', JSON.stringify(history));
  } catch (e) {
    console.error('Error saving scan history: ' + e.toString());
  }
}

/**
 * Gets the scan history array.
 * @return {Object[]} Array of scan entries, newest first
 */
function getScanHistory() {
  try {
    var val = PropertiesService.getUserProperties().getProperty('scan_history');
    return val ? JSON.parse(val) : [];
  } catch (e) { return []; }
}

/**
 * Gets unique categories from findings array.
 * @param {Object[]} findings
 * @return {string[]}
 */
function getUniqueCategories(findings) {
  var cats = {};
  for (var i = 0; i < findings.length; i++) {
    if (findings[i].score > 0) {
      cats[findings[i].category] = true;
    }
  }
  return Object.keys(cats);
}

// ============================================================
// ACTION HISTORY
// ============================================================

/**
 * Logs a user action (blacklist, whitelist, etc.)
 * @param {string} action - Action type: 'blacklist_add', 'whitelist_add', 'blacklist_remove', 'whitelist_remove', 'mark_safe', 'report_phishing'
 * @param {string} targetType - 'email' or 'domain'
 * @param {string} targetValue - The email or domain acted upon
 */
function logAction(action, targetType, targetValue) {
  try {
    var entry = {
      timestamp: new Date().toISOString(),
      action: action,
      targetType: targetType,
      targetValue: targetValue
    };

    var history = getActionHistory();
    history.unshift(entry);

    if (history.length > MAX_ACTION_HISTORY) {
      history = history.slice(0, MAX_ACTION_HISTORY);
    }

    PropertiesService.getUserProperties().setProperty('action_history', JSON.stringify(history));
  } catch (e) {
    console.error('Error logging action: ' + e.toString());
  }
}

/**
 * Gets the action history array.
 * @return {Object[]} Array of action entries, newest first
 */
function getActionHistory() {
  try {
    var val = PropertiesService.getUserProperties().getProperty('action_history');
    return val ? JSON.parse(val) : [];
  } catch (e) { return []; }
}

// ============================================================
// ADAPTIVE SCORING
// ============================================================

/**
 * Calculates adaptive score adjustments based on history.
 * - Repeat offenders: if a domain/email was previously flagged, boost the score
 * - Previously safe: if sender was consistently safe, no adjustment
 * @param {GmailMessage} message - The current email
 * @return {Object[]} Array of findings (adjustments)
 */
function getAdaptiveFindings(message) {
  var findings = [];
  var from = message.getFrom() || '';
  var email = extractEmail(from).toLowerCase();
  var domain = extractDomain(from).toLowerCase();
  var history = getScanHistory();

  if (history.length === 0) return findings;

  // Count past scans from this sender
  var domainScans = [];
  var emailScans = [];

  for (var i = 0; i < history.length; i++) {
    if (history[i].domain === domain) domainScans.push(history[i]);
    if (history[i].email === email) emailScans.push(history[i]);
  }

  // Repeat offender: domain has been flagged multiple times
  var flaggedCount = 0;
  for (var j = 0; j < domainScans.length; j++) {
    if (domainScans[j].score >= 40) flaggedCount++;
  }

  if (flaggedCount >= 2) {
    findings.push(createFinding(
      'blacklist',
      'Repeat offender domain',
      'Domain "' + domain + '" has been flagged ' + flaggedCount + ' time(s) in your scan history. Elevated risk based on past behavior.',
      Math.min(flaggedCount * 5, 15),
      'medium'
    ));
  }

  // First-time sender detection
  if (domainScans.length === 0) {
    findings.push(createFinding(
      'blacklist',
      'First-time sender',
      'This is the first email scanned from domain "' + domain + '". No historical baseline available.',
      0,
      'info'
    ));
  } else if (flaggedCount === 0 && domainScans.length >= 3) {
    // Consistently safe domain
    findings.push(createFinding(
      'blacklist',
      'Known safe domain',
      'Domain "' + domain + '" has been scanned ' + domainScans.length + ' time(s) with no flags. Established trust baseline.',
      0,
      'info'
    ));
  }

  return findings;
}

// ============================================================
// HISTORY CARD UI
// ============================================================

/**
 * Builds the history viewing card.
 * Shows recent scans and actions.
 * @return {CardService.Card}
 */
function buildHistoryCard() {
  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle('Scan History')
        .setSubtitle('Recent scans and actions')
    );

  // --- Recent Scans ---
  var scans = getScanHistory();
  var scanSection = CardService.newCardSection().setHeader('📊 Recent Scans (' + scans.length + ')');

  if (scans.length === 0) {
    scanSection.addWidget(CardService.newTextParagraph().setText('No scans yet. Open emails to start building history.'));
  } else {
    var showCount = Math.min(scans.length, 10);
    for (var i = 0; i < showCount; i++) {
      var scan = scans[i];
      var icon = scan.score <= 15 ? '✅' : (scan.score <= 40 ? '⚠️' : (scan.score <= 65 ? '🔶' : '🔴'));
      var dateStr = formatRelativeDate(scan.timestamp);

      scanSection.addWidget(
        CardService.newDecoratedText()
          .setText(icon + ' ' + scan.score + '/100 — ' + (scan.subject || '(no subject)'))
          .setBottomLabel(scan.email + ' • ' + dateStr)
          .setWrapText(true)
      );
    }

    if (scans.length > 10) {
      scanSection.addWidget(
        CardService.newTextParagraph()
          .setText('... and ' + (scans.length - 10) + ' more scans in history.')
      );
    }
  }
  card.addSection(scanSection);

  // --- Recent Actions ---
  var actions = getActionHistory();
  var actionSection = CardService.newCardSection().setHeader('📋 Recent Actions (' + actions.length + ')');

  if (actions.length === 0) {
    actionSection.addWidget(CardService.newTextParagraph().setText('No actions recorded yet.'));
  } else {
    var showActions = Math.min(actions.length, 10);
    for (var j = 0; j < showActions; j++) {
      var act = actions[j];
      var actionIcon = act.action.indexOf('blacklist') > -1 ? '🚫' : '✅';
      var actionLabel = formatActionLabel(act.action);
      var actDate = formatRelativeDate(act.timestamp);

      actionSection.addWidget(
        CardService.newDecoratedText()
          .setText(actionIcon + ' ' + actionLabel)
          .setBottomLabel(act.targetValue + ' (' + act.targetType + ') • ' + actDate)
          .setWrapText(true)
      );
    }
  }
  card.addSection(actionSection);

  // --- Stats ---
  if (scans.length > 0) {
    var statsSection = CardService.newCardSection().setHeader('📈 Statistics');
    var totalScans = scans.length;
    var avgScore = 0;
    var safeCount = 0;
    var riskyCount = 0;

    for (var k = 0; k < scans.length; k++) {
      avgScore += scans[k].score;
      if (scans[k].score <= 15) safeCount++;
      if (scans[k].score >= 41) riskyCount++;
    }
    avgScore = Math.round(avgScore / totalScans);

    statsSection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Total Scans')
        .setText(totalScans.toString())
    );

    statsSection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Average Score')
        .setText(avgScore + '/100')
    );

    statsSection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Safe / Risky')
        .setText('✅ ' + safeCount + ' safe • 🔴 ' + riskyCount + ' risky')
    );

    card.addSection(statsSection);
  }

  // --- Clear History ---
  var clearSection = CardService.newCardSection();
  clearSection.addWidget(
    CardService.newTextButton()
      .setText('🗑️ Clear All History')
      .setOnClickAction(CardService.newAction().setFunctionName('onClearHistory'))
  );
  clearSection.addWidget(
    CardService.newTextButton()
      .setText('← Back')
      .setOnClickAction(CardService.newAction().setFunctionName('onBackToHome'))
  );
  card.addSection(clearSection);

  return card.build();
}

/**
 * Opens the history card. Called from score card button.
 * @return {CardService.ActionResponse}
 */
function onOpenHistory() {
  var card = buildHistoryCard();
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card))
    .build();
}

/**
 * Clears all scan and action history.
 * @return {CardService.ActionResponse}
 */
function onClearHistory() {
  PropertiesService.getUserProperties().deleteProperty('scan_history');
  PropertiesService.getUserProperties().deleteProperty('action_history');

  var card = buildHistoryCard();
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('History cleared.'))
    .setNavigation(CardService.newNavigation().updateCard(card))
    .build();
}

// ============================================================
// HELPERS
// ============================================================

/**
 * Formats an ISO timestamp as a relative date string.
 * @param {string} isoTimestamp
 * @return {string} e.g. "2 hours ago", "3 days ago"
 */
function formatRelativeDate(isoTimestamp) {
  try {
    var then = new Date(isoTimestamp);
    var now = new Date();
    var diffMs = now - then;
    var diffMins = Math.floor(diffMs / 60000);
    var diffHours = Math.floor(diffMs / 3600000);
    var diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return diffMins + ' min ago';
    if (diffHours < 24) return diffHours + 'h ago';
    if (diffDays < 7) return diffDays + 'd ago';
    return then.toLocaleDateString();
  } catch (e) {
    return isoTimestamp;
  }
}

/**
 * Formats an action type into a readable label.
 * @param {string} action
 * @return {string}
 */
function formatActionLabel(action) {
  var labels = {
    'blacklist_add': 'Added to blacklist',
    'blacklist_remove': 'Removed from blacklist',
    'whitelist_add': 'Marked as trusted',
    'whitelist_remove': 'Removed from trusted',
    'mark_safe': 'Marked as safe',
    'report_phishing': 'Reported as phishing'
  };
  return labels[action] || action;
}
