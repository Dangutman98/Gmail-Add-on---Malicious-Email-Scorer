/**
 * Settings.js — User configuration and management console
 * Handles API key, sensitivity level, feature toggles, and data management.
 *
 * Storage keys:
 *   'vt_api_key'        → VirusTotal API key string
 *   'sensitivity_level'  → 'low', 'medium', or 'high' (default: medium)
 *   'feature_toggles'    → JSON object of feature on/off flags
 */

// Default feature toggles
var DEFAULT_TOGGLES = {
  authentication: true,
  sender: true,
  content: true,
  attachments: true,
  enrichment: true,
  translation: true,
  adaptive: true
};

/**
 * Builds the Settings card — full management console.
 * @return {CardService.Card}
 */
function buildSettingsCard() {
  var card = CardService.newCardBuilder();

  card.setHeader(
    CardService.newCardHeader()
      .setTitle('Settings & Console')
      .setSubtitle('Configure your email scanner')
  );

  // --- Current Status Summary (always fresh) ---
  var statusSection = CardService.newCardSection().setHeader('Current Status');
  var vtKey = getVTApiKey();
  var toggles = getFeatureToggles();
  var level = getSensitivityLevel();

  var enabledCount = 0;
  var allKeys = Object.keys(DEFAULT_TOGGLES);
  for (var s = 0; s < allKeys.length; s++) {
    if (toggles[allKeys[s]]) enabledCount++;
  }

  statusSection.addWidget(
    CardService.newTextParagraph()
      .setText(
        'Sensitivity: <b>' + level.charAt(0).toUpperCase() + level.slice(1) + '</b>\n' +
        'Features: <b>' + enabledCount + '/' + allKeys.length + '</b> enabled\n' +
        'VirusTotal: ' + (vtKey ? (toggles.enrichment ? '<b>Active</b>' : '<b>Key set, disabled</b>') : '<b>Not configured</b>') + '\n' +
        'Translation: ' + (toggles.translation ? '<b>ON</b>' : '<b>OFF</b>')
      )
  );
  card.addSection(statusSection);

  // --- Sensitivity Level Section ---
  var sensSection = CardService.newCardSection()
    .setHeader('Sensitivity Level');

  var currentLevel = getSensitivityLevel();

  sensSection.addWidget(
    CardService.newTextParagraph()
      .setText(
        '<b>Low:</b> Only flag high-confidence threats\n' +
        '<b>Medium:</b> Balanced detection (recommended)\n' +
        '<b>High:</b> Flag everything suspicious'
      )
  );

  sensSection.addWidget(
    CardService.newSelectionInput()
      .setType(CardService.SelectionInputType.RADIO_BUTTON)
      .setFieldName('sensitivity_level')
      .addItem('Low — fewer alerts', 'low', currentLevel === 'low')
      .addItem('Medium — balanced (default)', 'medium', currentLevel === 'medium')
      .addItem('High — maximum detection', 'high', currentLevel === 'high')
  );

  sensSection.addWidget(
    CardService.newTextButton()
      .setText('Save Sensitivity')
      .setOnClickAction(CardService.newAction().setFunctionName('onSaveSensitivity'))
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
  );

  card.addSection(sensSection);

  // --- Feature Toggles Section ---
  var toggleSection = CardService.newCardSection()
    .setHeader('Feature Toggles (auto-saved)');

  var toggles = getFeatureToggles();

  var toggleItems = [
    { key: 'authentication', label: '🔐 Authentication (SPF/DKIM/DMARC)' },
    { key: 'sender', label: '👤 Sender analysis' },
    { key: 'content', label: '📝 Content analysis' },
    { key: 'attachments', label: '📎 Attachment sandbox' },
    { key: 'enrichment', label: '🌐 VirusTotal enrichment' },
    { key: 'translation', label: '🌍 Multi-language translation' },
    { key: 'adaptive', label: '📊 Adaptive scoring (history)' }
  ];

  for (var t = 0; t < toggleItems.length; t++) {
    var item = toggleItems[t];
    var switchAction = CardService.newAction()
      .setFunctionName('onToggleFeature')
      .setParameters({ feature: item.key });

    toggleSection.addWidget(
      CardService.newDecoratedText()
        .setText(item.label)
        .setSwitchControl(
          CardService.newSwitch()
            .setFieldName('toggle_' + item.key)
            .setValue('on')
            .setSelected(toggles[item.key])
            .setOnChangeAction(switchAction)
        )
    );
  }

  card.addSection(toggleSection);

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

  vtSection.addWidget(
    CardService.newTextButton()
      .setText('Save API Key')
      .setOnClickAction(CardService.newAction().setFunctionName('onSaveVTApiKey'))
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
  );

  if (currentKey) {
    vtSection.addWidget(
      CardService.newTextButton()
        .setText('Remove API Key')
        .setOnClickAction(CardService.newAction().setFunctionName('onClearVTApiKey'))
    );
  }

  vtSection.addWidget(
    CardService.newTextButton()
      .setText('Get Free API Key')
      .setOpenLink(
        CardService.newOpenLink()
          .setUrl('https://www.virustotal.com/gui/join-us')
      )
  );

  card.addSection(vtSection);

  // --- Data Management Section ---
  var dataSection = CardService.newCardSection()
    .setHeader('Data Management');

  var scanCount = getScanHistory().length;
  var actionCount = getActionHistory().length;
  var blCount = getBlacklistEmails().length + getBlacklistDomains().length;
  var wlCount = getWhitelistEmails().length + getWhitelistDomains().length;

  dataSection.addWidget(
    CardService.newTextParagraph()
      .setText(
        'Scan history: <b>' + scanCount + '</b> entries\n' +
        'Action history: <b>' + actionCount + '</b> entries\n' +
        'Blacklisted: <b>' + blCount + '</b> | Trusted: <b>' + wlCount + '</b>'
      )
  );

  dataSection.addWidget(
    CardService.newTextButton()
      .setText('🗑️ Clear All History')
      .setOnClickAction(CardService.newAction().setFunctionName('onClearAllData'))
  );

  dataSection.addWidget(
    CardService.newTextButton()
      .setText('🔄 Reset All Settings')
      .setOnClickAction(CardService.newAction().setFunctionName('onResetSettings'))
  );

  card.addSection(dataSection);

  // --- Back Button ---
  var backSection = CardService.newCardSection();
  backSection.addWidget(
    CardService.newTextButton()
      .setText('← Back')
      .setOnClickAction(CardService.newAction().setFunctionName('onBackToHome'))
  );
  card.addSection(backSection);

  return card.build();
}

// ============================================================
// CALLBACKS — API Key
// ============================================================

function onSaveVTApiKey(e) {
  var key = e.formInput.vt_api_key_input;
  if (key && key.trim().length > 0) {
    PropertiesService.getUserProperties().setProperty('vt_api_key', key.trim());
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('API key saved!'))
      .setNavigation(CardService.newNavigation().updateCard(buildSettingsCard()))
      .build();
  }
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('Please enter a valid API key'))
    .build();
}

function onClearVTApiKey() {
  PropertiesService.getUserProperties().deleteProperty('vt_api_key');
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('API key removed'))
    .setNavigation(CardService.newNavigation().updateCard(buildSettingsCard()))
    .build();
}

// ============================================================
// CALLBACKS — Sensitivity & Toggles
// ============================================================

function onSaveSensitivity(e) {
  var level = e.formInput.sensitivity_level;
  if (level) {
    // If array (radio buttons), take first value
    if (Array.isArray(level)) level = level[0];
    PropertiesService.getUserProperties().setProperty('sensitivity_level', level);
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Sensitivity set to: ' + level))
      .build();
  }
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('Please select a level'))
    .build();
}

function onToggleFeature(e) {
  var feature = e.parameters.feature;
  var fieldName = 'toggle_' + feature;

  // Read actual switch state from form inputs
  var formInputs = e.formInputs || {};
  var isOn = formInputs[fieldName] ? true : false;

  var toggles = getFeatureToggles();
  toggles[feature] = isOn;

  PropertiesService.getUserProperties().setProperty('feature_toggles', JSON.stringify(toggles));

  var label = feature.charAt(0).toUpperCase() + feature.slice(1);
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(label + ': ' + (isOn ? 'ON' : 'OFF')))
    .setNavigation(CardService.newNavigation().updateCard(buildSettingsCard()))
    .build();
}

// ============================================================
// CALLBACKS — Data Management
// ============================================================

function onClearAllData() {
  var props = PropertiesService.getUserProperties();
  props.deleteProperty('scan_history');
  props.deleteProperty('action_history');
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('History cleared'))
    .setNavigation(CardService.newNavigation().updateCard(buildSettingsCard()))
    .build();
}

function onResetSettings() {
  var props = PropertiesService.getUserProperties();
  props.deleteProperty('sensitivity_level');
  props.deleteProperty('feature_toggles');
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('Settings reset to defaults'))
    .setNavigation(CardService.newNavigation().updateCard(buildSettingsCard()))
    .build();
}

// ============================================================
// CALLBACKS — Navigation
// ============================================================

function onBackToHome() {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().popCard())
    .build();
}

function onOpenSettings() {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(buildSettingsCard()))
    .build();
}

// ============================================================
// GETTERS — Settings
// ============================================================

/**
 * Gets the current sensitivity level.
 * @return {string} 'low', 'medium', or 'high'
 */
function getSensitivityLevel() {
  try {
    return PropertiesService.getUserProperties().getProperty('sensitivity_level') || 'medium';
  } catch (e) { return 'medium'; }
}

/**
 * Gets the sensitivity multiplier for scoring.
 * Low = 0.6, Medium = 1.0, High = 1.4
 * @return {number}
 */
function getSensitivityMultiplier() {
  var level = getSensitivityLevel();
  if (level === 'low') return 0.6;
  if (level === 'high') return 1.4;
  return 1.0;
}

/**
 * Gets feature toggles. Returns defaults if not set.
 * @return {Object} Map of feature name → boolean
 */
function getFeatureToggles() {
  try {
    var val = PropertiesService.getUserProperties().getProperty('feature_toggles');
    if (val) {
      var parsed = JSON.parse(val);
      // Merge with defaults in case new features were added
      var result = {};
      var keys = Object.keys(DEFAULT_TOGGLES);
      for (var i = 0; i < keys.length; i++) {
        result[keys[i]] = parsed.hasOwnProperty(keys[i]) ? parsed[keys[i]] : DEFAULT_TOGGLES[keys[i]];
      }
      return result;
    }
  } catch (e) {}
  return JSON.parse(JSON.stringify(DEFAULT_TOGGLES));
}

/**
 * Checks if a specific feature is enabled.
 * @param {string} featureName
 * @return {boolean}
 */
function isFeatureEnabled(featureName) {
  var toggles = getFeatureToggles();
  return toggles.hasOwnProperty(featureName) ? toggles[featureName] : true;
}
