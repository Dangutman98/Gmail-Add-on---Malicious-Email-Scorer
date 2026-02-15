/**
 * Sprint 1 — Minimal Gmail Add-on
 * Shows the email subject in the sidebar when a message is opened.
 */

/**
 * Contextual trigger: fires when the user opens an email.
 * @param {Object} e - Gmail event object
 * @return {CardService.Card[]}
 */
function onGmailMessageOpen(e) {
  var messageId = e.gmail.messageId;
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

  var message = GmailApp.getMessageById(messageId);
  var subject = message.getSubject();
  var from = message.getFrom();

  console.log("Email subject: " + subject);
  console.log("From: " + from);

  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Malicious Email Scorer")
        .setImageUrl("https://www.gstatic.com/images/icons/material/system/1x/security_white_48dp.png")
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("Subject")
            .setText(subject || "(no subject)")
        )
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("From")
            .setText(from || "(unknown)")
        )
    )
    .build();

  return [card];
}

/**
 * Homepage trigger: fires when the add-on icon is clicked.
 * @param {Object} e - event object
 * @return {CardService.Card[]}
 */
function onHomepage(e) {
  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Malicious Email Scorer")
        .setSubtitle("Open an email to scan it")
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText("Select an email to analyze its maliciousness score.")
        )
    )
    .build();

  return [card];
}
