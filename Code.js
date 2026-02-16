/**
 * Code.js — Main entry point and orchestrator
 * Receives Gmail trigger events, runs the analysis pipeline,
 * and returns CardService cards to the Gmail sidebar.
 */

/**
 * Contextual trigger: fires when the user opens an email.
 * This is the main analysis pipeline.
 * @param {Object} e - Gmail event object
 * @return {CardService.Card[]}
 */
function onGmailMessageOpen(e) {
  try {
    var messageId = e.gmail.messageId;
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

    var message = GmailApp.getMessageById(messageId);
    if (!message) {
      return [buildErrorCard('Could not access the email message.')];
    }

    // Run all analysis layers (respecting feature toggles)
    var findings = [];

    // Layer 1-3: Authentication + Sender + Content analysis (toggles checked inside)
    findings = findings.concat(analyzeEmail(message));

    // Layer 4: Attachment sandbox analysis
    if (isFeatureEnabled('attachments')) {
      findings = findings.concat(analyzeAttachments(message));
    }

    // Layer 5: VirusTotal enrichment (if API key configured)
    if (isFeatureEnabled('enrichment')) {
      findings = findings.concat(analyzeEnrichment(message));
    }

    // Layer 6: Blacklist / Whitelist check
    findings = findings.concat(checkBlacklist(message));

    // Layer 6b: Adaptive scoring from history
    if (isFeatureEnabled('adaptive')) {
      findings = findings.concat(getAdaptiveFindings(message));
    }

    // Calculate score and verdict
    var scoreResult = calculateScore(findings);

    // Save scan to history
    saveScanHistory(message, scoreResult);

    // Build and return the UI card
    var card = buildScoreCard(message, scoreResult);
    return [card];

  } catch (error) {
    console.error('Error in onGmailMessageOpen: ' + error.toString());
    return [buildErrorCard('Analysis failed: ' + error.message)];
  }
}

/**
 * Homepage trigger: fires when the add-on icon is clicked without an email open.
 * @param {Object} e - Event object
 * @return {CardService.Card[]}
 */
function onHomepage(e) {
  return [buildHomepageCard()];
}
