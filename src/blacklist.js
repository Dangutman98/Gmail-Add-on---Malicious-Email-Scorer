/**
 * Blacklist.js — User-managed blacklist
 * Allows users to blacklist/whitelist email addresses and domains.
 * Stored in PropertiesService.getUserProperties().
 *
 * Storage keys:
 *   'blacklist_emails'  → JSON array of email addresses
 *   'blacklist_domains' → JSON array of domains
 *   'whitelist_emails'  → JSON array of trusted email addresses
 *   'whitelist_domains' → JSON array of trusted domains
 */

// ============================================================
// BLACKLIST CHECK (called during analysis pipeline)
// ============================================================

/**
 * Checks if the sender is on the user's blacklist or whitelist.
 * @param {GmailMessage} message - The Gmail message
 * @return {Object[]} Array of findings
 */
function checkBlacklist(message) {
  var findings = [];
  var from = message.getFrom() || '';
  var email = extractEmail(from).toLowerCase();
  var domain = extractDomain(from).toLowerCase();

  var blacklistedEmails = getBlacklistEmails();
  var blacklistedDomains = getBlacklistDomains();
  var whitelistedEmails = getWhitelistEmails();
  var whitelistedDomains = getWhitelistDomains();

  // Check whitelist first (reduces false positives)
  if (whitelistedEmails.indexOf(email) > -1) {
    findings.push(createFinding(
      'blacklist',
      'Trusted sender',
      'Sender "' + email + '" is on your trusted (whitelist) list.',
      -10,
      'info'
    ));
    return findings;
  }

  if (whitelistedDomains.indexOf(domain) > -1) {
    findings.push(createFinding(
      'blacklist',
      'Trusted domain',
      'Domain "' + domain + '" is on your trusted (whitelist) list.',
      -5,
      'info'
    ));
    return findings;
  }

  // Check blacklist
  if (blacklistedEmails.indexOf(email) > -1) {
    findings.push(createFinding(
      'blacklist',
      'Blacklisted sender',
      'Sender "' + email + '" is on your personal blacklist. You previously marked this sender as malicious.',
      30,
      'critical'
    ));
  }

  if (blacklistedDomains.indexOf(domain) > -1) {
    findings.push(createFinding(
      'blacklist',
      'Blacklisted domain',
      'Domain "' + domain + '" is on your personal blacklist. All emails from this domain are flagged.',
      25,
      'high'
    ));
  }

  return findings;
}

// ============================================================
// CRUD OPERATIONS
// ============================================================

/**
 * Adds an email to the blacklist. Called from UI action.
 * @param {Object} e - Action event with parameter 'email'
 * @return {CardService.ActionResponse}
 */
function onBlacklistEmail(e) {
  var email = (e.parameters.email || '').toLowerCase().trim();
  if (!email) return buildNotification('No email provided.');

  var list = getBlacklistEmails();
  if (list.indexOf(email) === -1) {
    list.push(email);
    saveBlacklistEmails(list);
    logAction('blacklist_add', 'email', email);
    return buildNotification('Added "' + email + '" to blacklist.');
  }
  return buildNotification('"' + email + '" is already blacklisted.');
}

/**
 * Adds a domain to the blacklist. Called from UI action.
 * @param {Object} e - Action event with parameter 'domain'
 * @return {CardService.ActionResponse}
 */
function onBlacklistDomain(e) {
  var domain = (e.parameters.domain || '').toLowerCase().trim();
  if (!domain) return buildNotification('No domain provided.');

  var list = getBlacklistDomains();
  if (list.indexOf(domain) === -1) {
    list.push(domain);
    saveBlacklistDomains(list);
    logAction('blacklist_add', 'domain', domain);
    return buildNotification('Added "' + domain + '" to blacklist.');
  }
  return buildNotification('"' + domain + '" is already blacklisted.');
}

/**
 * Adds an email to the whitelist (trusted). Called from UI action.
 * @param {Object} e - Action event with parameter 'email'
 * @return {CardService.ActionResponse}
 */
function onWhitelistEmail(e) {
  var email = (e.parameters.email || '').toLowerCase().trim();
  if (!email) return buildNotification('No email provided.');

  // Remove from blacklist if present
  removeFromList('blacklist_emails', email);

  var list = getWhitelistEmails();
  if (list.indexOf(email) === -1) {
    list.push(email);
    saveWhitelistEmails(list);
    logAction('whitelist_add', 'email', email);
    return buildNotification('Added "' + email + '" to trusted list.');
  }
  return buildNotification('"' + email + '" is already trusted.');
}

/**
 * Removes an entry from the blacklist. Called from UI action.
 * @param {Object} e - Action event with parameters 'key' and 'value'
 * @return {CardService.ActionResponse}
 */
function onRemoveBlacklistEntry(e) {
  var key = e.parameters.key;
  var value = e.parameters.value;
  removeFromList(key, value);
  logAction('blacklist_remove', key, value);

  // Rebuild and push updated blacklist card
  var card = buildBlacklistCard();
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('Removed "' + value + '".'))
    .setNavigation(CardService.newNavigation().updateCard(card))
    .build();
}

/**
 * Removes an entry from the whitelist. Called from UI action.
 * @param {Object} e - Action event with parameters 'key' and 'value'
 * @return {CardService.ActionResponse}
 */
function onRemoveWhitelistEntry(e) {
  var key = e.parameters.key;
  var value = e.parameters.value;
  removeFromList(key, value);
  logAction('whitelist_remove', key, value);

  var card = buildBlacklistCard();
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('Removed "' + value + '".'))
    .setNavigation(CardService.newNavigation().updateCard(card))
    .build();
}

// ============================================================
// BLACKLIST CARD UI
// ============================================================

/**
 * Builds the blacklist management card.
 * Shows current blacklisted/whitelisted items with remove buttons.
 * @return {CardService.Card}
 */
function buildBlacklistCard() {
  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle('Blacklist & Whitelist')
        .setSubtitle('Manage trusted and blocked senders')
    );

  // --- Blacklisted Emails ---
  var blEmails = getBlacklistEmails();
  var blSection = CardService.newCardSection().setHeader('🚫 Blacklisted Emails (' + blEmails.length + ')');

  if (blEmails.length === 0) {
    blSection.addWidget(CardService.newTextParagraph().setText('No blacklisted emails.'));
  } else {
    for (var i = 0; i < blEmails.length; i++) {
      var removeAction = CardService.newAction()
        .setFunctionName('onRemoveBlacklistEntry')
        .setParameters({ key: 'blacklist_emails', value: blEmails[i] });

      blSection.addWidget(
        CardService.newDecoratedText()
          .setText(blEmails[i])
          .setButton(
            CardService.newTextButton()
              .setText('✕')
              .setOnClickAction(removeAction)
          )
      );
    }
  }
  card.addSection(blSection);

  // --- Blacklisted Domains ---
  var blDomains = getBlacklistDomains();
  var blDomSection = CardService.newCardSection().setHeader('🚫 Blacklisted Domains (' + blDomains.length + ')');

  if (blDomains.length === 0) {
    blDomSection.addWidget(CardService.newTextParagraph().setText('No blacklisted domains.'));
  } else {
    for (var j = 0; j < blDomains.length; j++) {
      var removeDomAction = CardService.newAction()
        .setFunctionName('onRemoveBlacklistEntry')
        .setParameters({ key: 'blacklist_domains', value: blDomains[j] });

      blDomSection.addWidget(
        CardService.newDecoratedText()
          .setText(blDomains[j])
          .setButton(
            CardService.newTextButton()
              .setText('✕')
              .setOnClickAction(removeDomAction)
          )
      );
    }
  }
  card.addSection(blDomSection);

  // --- Whitelisted (Trusted) ---
  var wlEmails = getWhitelistEmails();
  var wlDomains = getWhitelistDomains();
  var wlSection = CardService.newCardSection().setHeader('✅ Trusted Senders (' + (wlEmails.length + wlDomains.length) + ')');

  if (wlEmails.length === 0 && wlDomains.length === 0) {
    wlSection.addWidget(CardService.newTextParagraph().setText('No trusted senders.'));
  }

  for (var k = 0; k < wlEmails.length; k++) {
    var removeWlAction = CardService.newAction()
      .setFunctionName('onRemoveWhitelistEntry')
      .setParameters({ key: 'whitelist_emails', value: wlEmails[k] });

    wlSection.addWidget(
      CardService.newDecoratedText()
        .setText(wlEmails[k])
        .setBottomLabel('email')
        .setButton(
          CardService.newTextButton()
            .setText('✕')
            .setOnClickAction(removeWlAction)
        )
    );
  }

  for (var m = 0; m < wlDomains.length; m++) {
    var removeWlDomAction = CardService.newAction()
      .setFunctionName('onRemoveWhitelistEntry')
      .setParameters({ key: 'whitelist_domains', value: wlDomains[m] });

    wlSection.addWidget(
      CardService.newDecoratedText()
        .setText(wlDomains[m])
        .setBottomLabel('domain')
        .setButton(
          CardService.newTextButton()
            .setText('✕')
            .setOnClickAction(removeWlDomAction)
        )
    );
  }

  card.addSection(wlSection);

  // --- Back button ---
  var navSection = CardService.newCardSection();
  navSection.addWidget(
    CardService.newTextButton()
      .setText('← Back')
      .setOnClickAction(CardService.newAction().setFunctionName('onBackToHome'))
  );
  card.addSection(navSection);

  return card.build();
}

/**
 * Opens the blacklist management card. Called from score card button.
 * @return {CardService.ActionResponse}
 */
function onOpenBlacklist() {
  var card = buildBlacklistCard();
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card))
    .build();
}

// ============================================================
// STORAGE HELPERS
// ============================================================

function getBlacklistEmails() { return getJsonList('blacklist_emails'); }
function getBlacklistDomains() { return getJsonList('blacklist_domains'); }
function getWhitelistEmails() { return getJsonList('whitelist_emails'); }
function getWhitelistDomains() { return getJsonList('whitelist_domains'); }

function saveBlacklistEmails(list) { saveJsonList('blacklist_emails', list); }
function saveBlacklistDomains(list) { saveJsonList('blacklist_domains', list); }
function saveWhitelistEmails(list) { saveJsonList('whitelist_emails', list); }
function saveWhitelistDomains(list) { saveJsonList('whitelist_domains', list); }

function getJsonList(key) {
  try {
    var val = PropertiesService.getUserProperties().getProperty(key);
    return val ? JSON.parse(val) : [];
  } catch (e) { return []; }
}

function saveJsonList(key, list) {
  PropertiesService.getUserProperties().setProperty(key, JSON.stringify(list));
}

function removeFromList(key, value) {
  var list = getJsonList(key);
  var idx = list.indexOf(value);
  if (idx > -1) {
    list.splice(idx, 1);
    saveJsonList(key, list);
  }
}

/**
 * Builds a simple notification response.
 * @param {string} text - Notification message
 * @return {CardService.ActionResponse}
 */
function buildNotification(text) {
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(text))
    .build();
}
