/**
 * Settings.js — User configuration management
 * Handles API key storage and settings card.
 */

/**
 * Builds the Settings card for API key and configuration.
 * @return {CardService.Card}
 */
function buildSettingsCard() {
  var card = CardService.newCardBuilder();

  card.setHeader(
    CardService.newCardHeader()
      .setTitle('Settings')
      .setSubtitle('Configure your email scanner')
  );

  // --- VirusTotal API Key Section ---
  var vtSection = CardService.newCardSection()
    .setHeader('VirusTotal API Key');

  var currentKey = getVTApiKey();
  var keyDisplay = currentKey ? ('••••••••' + currentKey.slice(-4)) : 'Not configured';

  vtSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Current Status')
      .setText(currentKey ? '✅ Key configured (' + keyDisplay + ')' : '⚠️ No API key set')
  );

  vtSection.addWidget(
    CardService.newTextInput()
      .setFieldName('vt_api_key_input')
      .setTitle('Enter VirusTotal API Key')
      .setHint('Get free key at virustotal.com')
  );

  var saveAction = CardService.newAction()
    .setFunctionName('onSaveVTApiKey');

  vtSection.addWidget(
    CardService.newTextButton()
      .setText('Save API Key')
      .setOnClickAction(saveAction)
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
  );

  if (currentKey) {
    var clearAction = CardService.newAction()
      .setFunctionName('onClearVTApiKey');

    vtSection.addWidget(
      CardService.newTextButton()
        .setText('Remove API Key')
        .setOnClickAction(clearAction)
    );
  }

  card.addSection(vtSection);

  // --- Info Section ---
  var infoSection = CardService.newCardSection()
    .setHeader('About VirusTotal');

  infoSection.addWidget(
    CardService.newTextParagraph()
      .setText(
        'VirusTotal checks URLs, domains, and file hashes against 70+ security engines.\n\n' +
        '<b>Free tier:</b> 4 requests/min, 500/day\n' +
        '<b>What we send:</b> Only URLs, domains, and file hashes — never email content\n\n' +
        'Without an API key, the scanner still works using local analysis (authentication, content, attachments).'
      )
  );

  infoSection.addWidget(
    CardService.newTextButton()
      .setText('Get Free API Key')
      .setOpenLink(
        CardService.newOpenLink()
          .setUrl('https://www.virustotal.com/gui/join-us')
      )
  );

  card.addSection(infoSection);

  // --- Back Button ---
  var backSection = CardService.newCardSection();
  var backAction = CardService.newAction()
    .setFunctionName('onBackToHome');

  backSection.addWidget(
    CardService.newTextButton()
      .setText('◄ Back')
      .setOnClickAction(backAction)
  );

  card.addSection(backSection);

  return card.build();
}

/**
 * Callback: saves the VirusTotal API key.
 * @param {Object} e - Event with form inputs
 * @return {CardService.ActionResponse}
 */
function onSaveVTApiKey(e) {
  var key = e.formInput.vt_api_key_input;
  if (key && key.trim().length > 0) {
    PropertiesService.getUserProperties().setProperty('vt_api_key', key.trim());
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('✅ API key saved!'))
      .setNavigation(CardService.newNavigation().updateCard(buildSettingsCard()))
      .build();
  }
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('⚠️ Please enter a valid API key'))
    .build();
}

/**
 * Callback: removes the VirusTotal API key.
 * @return {CardService.ActionResponse}
 */
function onClearVTApiKey() {
  PropertiesService.getUserProperties().deleteProperty('vt_api_key');
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('API key removed'))
    .setNavigation(CardService.newNavigation().updateCard(buildSettingsCard()))
    .build();
}

/**
 * Callback: navigate back to homepage.
 * @return {CardService.ActionResponse}
 */
function onBackToHome() {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().popCard())
    .build();
}

/**
 * Callback: navigate to Settings card.
 * @return {CardService.ActionResponse}
 */
function onOpenSettings() {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(buildSettingsCard()))
    .build();
}
