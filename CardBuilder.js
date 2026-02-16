/**
 * CardBuilder.js — UI card construction
 * Builds all CardService cards for the Gmail sidebar.
 */

/**
 * Builds the main score card with verdict, bar, narrative, and findings breakdown.
 * @param {GmailMessage} message - The email message
 * @param {Object} scoreResult - Result from calculateScore()
 * @return {CardService.Card}
 */
function buildScoreCard(message, scoreResult) {
  var card = CardService.newCardBuilder();

  // Header
  card.setHeader(
    CardService.newCardHeader()
      .setTitle('Malicious Email Scorer')
      .setSubtitle(scoreResult.verdictIcon + ' ' + scoreResult.verdict)
  );

  // --- Score Section ---
  var scoreSection = CardService.newCardSection();

  // Score display
  scoreSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Risk Score')
      .setText('<b>' + scoreResult.score + ' / 100</b>')
      .setBottomLabel(buildScoreBar(scoreResult.score))
  );

  // Verdict
  scoreSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Verdict')
      .setText('<font color="' + scoreResult.color + '"><b>' + scoreResult.verdictIcon + ' ' + scoreResult.verdict + '</b></font>')
  );

  // Signals count
  var findingsCount = scoreResult.findings.length;
  scoreSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Signals')
      .setText(findingsCount + ' signal' + (findingsCount !== 1 ? 's' : '') + ' detected')
  );

  card.addSection(scoreSection);

  // --- Threat Narrative Section ---
  var narrativeSection = CardService.newCardSection()
    .setHeader('Threat Narrative');

  narrativeSection.addWidget(
    CardService.newTextParagraph()
      .setText(scoreResult.summary)
  );

  card.addSection(narrativeSection);

  // --- Findings Breakdown Section ---
  if (findingsCount > 0) {
    var findingsSection = CardService.newCardSection()
      .setHeader('Signal Details');

    var grouped = groupFindingsByCategory(scoreResult.findings);
    var categoryLabels = {
      'authentication': '🔐 Authentication',
      'sender': '👤 Sender',
      'content': '📝 Content',
      'attachment': '📎 Attachments',
      'enrichment': '🌐 Enrichment',
      'blacklist': '🚫 Blacklist'
    };

    var categoryOrder = ['authentication', 'sender', 'content', 'attachment', 'enrichment', 'blacklist'];

    for (var c = 0; c < categoryOrder.length; c++) {
      var cat = categoryOrder[c];
      if (grouped[cat]) {
        var status = getCategoryStatus(grouped[cat]);
        var statusColor = status === 'FAIL' ? '#F44336' : (status === 'WARNING' ? '#FF9800' : '#4CAF50');
        var label = (categoryLabels[cat] || cat) + '  —  ' + status;

        findingsSection.addWidget(
          CardService.newDecoratedText()
            .setText('<font color="' + statusColor + '"><b>' + label + '</b></font>')
        );

        for (var f = 0; f < grouped[cat].length; f++) {
          var finding = grouped[cat][f];
          findingsSection.addWidget(
            CardService.newDecoratedText()
              .setText(finding.signal)
              .setBottomLabel(finding.detail)
              .setWrapText(true)
          );
        }
      }
    }

    card.addSection(findingsSection);
  }

  // --- Email Info Section ---
  var infoSection = CardService.newCardSection()
    .setHeader('Email Info');

  infoSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Subject')
      .setText(message.getSubject() || '(no subject)')
      .setWrapText(true)
  );

  infoSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('From')
      .setText(message.getFrom() || '(unknown)')
      .setWrapText(true)
  );

  infoSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Date')
      .setText(message.getDate().toLocaleString())
  );

  card.addSection(infoSection);

  // --- Quick Actions Section ---
  var quickSection = CardService.newCardSection().setHeader('Quick Actions');

  var senderEmail = extractEmail(message.getFrom() || '');
  var senderDomain = extractDomain(message.getFrom() || '');

  // Blacklist sender button
  var blEmailAction = CardService.newAction()
    .setFunctionName('onBlacklistEmail')
    .setParameters({ email: senderEmail });

  quickSection.addWidget(
    CardService.newTextButton()
      .setText('🚫 Blacklist Sender')
      .setOnClickAction(blEmailAction)
  );

  // Blacklist domain button
  var blDomainAction = CardService.newAction()
    .setFunctionName('onBlacklistDomain')
    .setParameters({ domain: senderDomain });

  quickSection.addWidget(
    CardService.newTextButton()
      .setText('🚫 Blacklist Domain')
      .setOnClickAction(blDomainAction)
  );

  // Mark as trusted button
  var trustAction = CardService.newAction()
    .setFunctionName('onWhitelistEmail')
    .setParameters({ email: senderEmail });

  quickSection.addWidget(
    CardService.newTextButton()
      .setText('✅ Mark as Trusted')
      .setOnClickAction(trustAction)
  );

  card.addSection(quickSection);

  // --- Navigation Section ---
  var navSection = CardService.newCardSection();

  // VT status indicator
  var vtKey = getVTApiKey();
  navSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('VirusTotal')
      .setText(vtKey ? '✅ Active — enrichment enabled' : '⚠️ No API key — local analysis only')
  );

  // Navigation buttons row
  navSection.addWidget(
    CardService.newTextButton()
      .setText('📋 Blacklist & Whitelist')
      .setOnClickAction(CardService.newAction().setFunctionName('onOpenBlacklist'))
  );

  navSection.addWidget(
    CardService.newTextButton()
      .setText('📊 History')
      .setOnClickAction(CardService.newAction().setFunctionName('onOpenHistory'))
  );

  navSection.addWidget(
    CardService.newTextButton()
      .setText('⚙️ Settings')
      .setOnClickAction(CardService.newAction().setFunctionName('onOpenSettings'))
  );

  card.addSection(navSection);

  return card.build();
}

/**
 * Builds the homepage card shown when the add-on is opened without an email.
 * @return {CardService.Card}
 */
function buildHomepageCard() {
  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle('Malicious Email Scorer')
        .setSubtitle('Email security analysis tool')
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText('Open an email to analyze its maliciousness score.\n\nThis tool checks:')
        )
        .addWidget(
          CardService.newTextParagraph()
            .setText(
              '🔐 <b>Authentication</b> — SPF, DKIM, DMARC\n' +
              '👤 <b>Sender</b> — Reply-To, spoofing, impersonation\n' +
              '📝 <b>Content</b> — Phishing patterns, suspicious URLs\n' +
              '📎 <b>Attachments</b> — Dangerous files, malware indicators\n' +
              '🌐 <b>Enrichment</b> — VirusTotal reputation data\n' +
              '🚫 <b>Blacklist</b> — Your personal block list'
            )
        )
    );

  return card.build();
}

/**
 * Builds an error card when something goes wrong.
 * @param {string} errorMessage - The error description
 * @return {CardService.Card}
 */
function buildErrorCard(errorMessage) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle('Malicious Email Scorer')
        .setSubtitle('Error')
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText('⚠️ ' + errorMessage)
        )
    )
    .build();
}
