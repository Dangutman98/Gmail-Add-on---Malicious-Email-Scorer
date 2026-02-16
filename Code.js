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

    // Step 1-2: Run analysis layers and collect findings
    var findings = [];

    // Layer 1 & 2: Authentication + Sender analysis
    var emailFindings = analyzeEmail(message);
    findings = findings.concat(emailFindings);

    // Layer 4: Attachment sandbox analysis
    var attachmentFindings = analyzeAttachments(message);
    findings = findings.concat(attachmentFindings);

    // (Future layers will be added here in later sprints)
    // Layer 5: VirusTotal enrichment — Baby 5
    // Layer 6: Blacklist + History — Baby 6

    // Step 3: Calculate score and verdict
    var scoreResult = calculateScore(findings);

    // Step 4: Build and return the UI card
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
