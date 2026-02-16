/**
 * Analyzer.js — Layers 1-3: Authentication, Sender, and Content analysis
 * Parses email headers, sender patterns, body content, and URLs.
 */

/**
 * Runs all authentication, sender, and content checks on the email.
 * @param {GmailMessage} message - The Gmail message object
 * @return {Object[]} Array of Finding objects
 */
function analyzeEmail(message) {
  var findings = [];
  var rawContent = message.getRawContent();
  var headers = extractHeaders(rawContent);

  // --- Layer 1: Authentication ---
  findings = findings.concat(analyzeAuthentication(headers));

  // --- Layer 2: Sender ---
  findings = findings.concat(analyzeSender(message, headers));

  // --- Layer 3: Content ---
  findings = findings.concat(analyzeContent(message));

  return findings;
}

/**
 * Extracts header block from raw email content.
 * Headers end at the first blank line.
 * @param {string} rawContent - Full raw email
 * @return {string} The header block
 */
function extractHeaders(rawContent) {
  var headerEnd = rawContent.indexOf('\r\n\r\n');
  if (headerEnd === -1) {
    headerEnd = rawContent.indexOf('\n\n');
  }
  return headerEnd > 0 ? rawContent.substring(0, headerEnd) : rawContent.substring(0, 5000);
}

// ============================================================
// LAYER 1: Authentication (SPF / DKIM / DMARC)
// ============================================================

/**
 * Parses Authentication-Results and Received-SPF headers.
 * @param {string} headers - Raw header block
 * @return {Object[]} Array of findings
 */
function analyzeAuthentication(headers) {
  var findings = [];

  var spfResult = parseSPF(headers);
  var dkimResult = parseDKIM(headers);
  var dmarcResult = parseDMARC(headers);

  // SPF check
  if (spfResult === 'fail' || spfResult === 'softfail') {
    findings.push(createFinding(
      'authentication',
      'SPF ' + spfResult,
      'SPF authentication failed — the sending server is not authorized to send on behalf of this domain.',
      25,
      'high'
    ));
  } else if (spfResult === 'none' || spfResult === 'neutral') {
    findings.push(createFinding(
      'authentication',
      'SPF ' + spfResult,
      'No SPF record found or neutral result — the domain does not declare which servers can send for it.',
      5,
      'low'
    ));
  }

  // DKIM check
  if (dkimResult === 'fail') {
    findings.push(createFinding(
      'authentication',
      'DKIM fail',
      'DKIM signature verification failed — the email may have been tampered with in transit.',
      20,
      'high'
    ));
  } else if (dkimResult === 'none') {
    findings.push(createFinding(
      'authentication',
      'DKIM none',
      'No DKIM signature found — the sender did not cryptographically sign this email.',
      5,
      'low'
    ));
  }

  // DMARC check
  if (dmarcResult === 'fail') {
    findings.push(createFinding(
      'authentication',
      'DMARC fail',
      'DMARC policy check failed — SPF/DKIM do not align with the sender domain. This is a strong spoofing indicator.',
      15,
      'high'
    ));
  } else if (dmarcResult === 'none') {
    findings.push(createFinding(
      'authentication',
      'DMARC none',
      'No DMARC policy published for the sender domain.',
      3,
      'low'
    ));
  }

  return findings;
}

/**
 * Parses SPF result from headers.
 * Checks Received-SPF header and Authentication-Results.
 * @param {string} headers - Raw header block
 * @return {string} "pass", "fail", "softfail", "neutral", "none", or "unknown"
 */
function parseSPF(headers) {
  // Check Received-SPF header first (most explicit)
  var spfHeader = headers.match(/Received-SPF:\s*(pass|fail|softfail|neutral|none)/i);
  if (spfHeader) return spfHeader[1].toLowerCase();

  // Fallback: check Authentication-Results for spf=
  var authResults = headers.match(/Authentication-Results:[\s\S]*?(?=\r?\n\S)/gi);
  if (authResults) {
    for (var i = 0; i < authResults.length; i++) {
      var spfMatch = authResults[i].match(/spf=(pass|fail|softfail|neutral|none)/i);
      if (spfMatch) return spfMatch[1].toLowerCase();
    }
  }

  return 'unknown';
}

/**
 * Parses DKIM result from Authentication-Results header.
 * @param {string} headers - Raw header block
 * @return {string} "pass", "fail", "none", or "unknown"
 */
function parseDKIM(headers) {
  var authResults = headers.match(/Authentication-Results:[\s\S]*?(?=\r?\n\S)/gi);
  if (authResults) {
    for (var i = 0; i < authResults.length; i++) {
      var dkimMatch = authResults[i].match(/dkim=(pass|fail|none)/i);
      if (dkimMatch) return dkimMatch[1].toLowerCase();
    }
  }
  return 'unknown';
}

/**
 * Parses DMARC result from Authentication-Results header.
 * @param {string} headers - Raw header block
 * @return {string} "pass", "fail", "none", or "unknown"
 */
function parseDMARC(headers) {
  var authResults = headers.match(/Authentication-Results:[\s\S]*?(?=\r?\n\S)/gi);
  if (authResults) {
    for (var i = 0; i < authResults.length; i++) {
      var dmarcMatch = authResults[i].match(/dmarc=(pass|fail|none)/i);
      if (dmarcMatch) return dmarcMatch[1].toLowerCase();
    }
  }
  return 'unknown';
}

// ============================================================
// LAYER 2: Sender Analysis
// ============================================================

/**
 * Analyzes sender for suspicious patterns.
 * @param {GmailMessage} message - Gmail message object
 * @param {string} headers - Raw header block
 * @return {Object[]} Array of findings
 */
function analyzeSender(message, headers) {
  var findings = [];
  var from = message.getFrom();
  var fromDomain = extractDomain(from);

  // Check Reply-To mismatch
  var replyTo = message.getReplyTo();
  if (replyTo) {
    var replyToDomain = extractDomain(replyTo);
    if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
      findings.push(createFinding(
        'sender',
        'Reply-To mismatch',
        'From domain (' + fromDomain + ') differs from Reply-To domain (' + replyToDomain + '). This is a common phishing technique.',
        15,
        'high'
      ));
    }
  }

  // Check free email provider sending "business" emails
  var freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'mail.com', 'protonmail.com', 'yandex.com'];
  if (freeProviders.indexOf(fromDomain) > -1) {
    var displayName = from.replace(/<[^>]+>/, '').trim().toLowerCase();
    var businessKeywords = ['bank', 'support', 'security', 'admin', 'service', 'billing', 'paypal', 'amazon', 'microsoft', 'apple', 'account'];
    for (var i = 0; i < businessKeywords.length; i++) {
      if (displayName.indexOf(businessKeywords[i]) > -1) {
        findings.push(createFinding(
          'sender',
          'Free email impersonation',
          'Display name contains "' + businessKeywords[i] + '" but sent from free provider (' + fromDomain + '). Legitimate businesses use their own domain.',
          5,
          'medium'
        ));
        break;
      }
    }
  }

  // Check display name spoofing (name contains an email-like string that doesn't match actual sender)
  var nameMatch = from.match(/^"?([^"<]+)"?\s*</);
  if (nameMatch) {
    var displayName = nameMatch[1].trim();
    var fakeEmailInName = displayName.match(/[\w.-]+@[\w.-]+\.\w+/);
    if (fakeEmailInName) {
      var actualEmail = extractEmail(from);
      if (fakeEmailInName[0].toLowerCase() !== actualEmail) {
        findings.push(createFinding(
          'sender',
          'Display name spoofing',
          'Display name contains "' + fakeEmailInName[0] + '" but actual sender is "' + actualEmail + '".',
          10,
          'high'
        ));
      }
    }
  }

  return findings;
}

// ============================================================
// LAYER 3: Content Analysis
// ============================================================

/**
 * Analyzes email body content for phishing signals.
 * @param {GmailMessage} message - Gmail message object
 * @return {Object[]} Array of findings
 */
function analyzeContent(message) {
  var findings = [];
  var subject = (message.getSubject() || '').toLowerCase();
  var plainBody = (message.getPlainBody() || '').toLowerCase();
  var htmlBody = message.getBody() || '';
  var textToScan = subject + ' ' + plainBody;

  // --- Urgency keywords ---
  findings = findings.concat(checkUrgencyKeywords(textToScan));

  // --- Phishing patterns ---
  findings = findings.concat(checkPhishingPatterns(textToScan));

  // --- Sensitive data requests ---
  findings = findings.concat(checkSensitiveDataRequests(textToScan));

  // --- Suspicious URLs ---
  findings = findings.concat(checkSuspiciousURLs(htmlBody, plainBody));

  return findings;
}

/**
 * Checks for urgency and pressure language.
 * @param {string} text - Combined subject + body text (lowercase)
 * @return {Object[]} Array of findings
 */
function checkUrgencyKeywords(text) {
  var findings = [];

  var urgencyPatterns = [
    { regex: /\b(act now|act immediately|immediate action|action required|urgent action)\b/, label: 'Urgent action demand' },
    { regex: /\b(account.{0,15}(suspended|disabled|locked|compromised|restricted|terminated|closed))\b/, label: 'Account threat' },
    { regex: /\b(within \d+ hours?|within 24 hours?|expires? (today|soon|immediately))\b/, label: 'Time pressure' },
    { regex: /\b(final warning|last chance|last notice|final notice)\b/, label: 'Final warning language' },
    { regex: /\b(failure to (comply|respond|verify|confirm)|if you do not)\b/, label: 'Threat of consequences' },
    { regex: /\b(unauthorized (access|activity|transaction|login))\b/, label: 'Unauthorized activity claim' }
  ];

  var matchedLabels = [];
  for (var i = 0; i < urgencyPatterns.length; i++) {
    if (urgencyPatterns[i].regex.test(text)) {
      matchedLabels.push(urgencyPatterns[i].label);
    }
  }

  if (matchedLabels.length > 0) {
    findings.push(createFinding(
      'content',
      'Urgency language (' + matchedLabels.length + ')',
      'Detected pressure tactics: ' + matchedLabels.join(', ') + '. Phishing emails often create false urgency to bypass critical thinking.',
      Math.min(10 + (matchedLabels.length - 1) * 5, 25),
      matchedLabels.length >= 3 ? 'high' : 'medium'
    ));
  }

  return findings;
}

/**
 * Checks for credential harvesting and phishing language.
 * @param {string} text - Combined subject + body text (lowercase)
 * @return {Object[]} Array of findings
 */
function checkPhishingPatterns(text) {
  var findings = [];

  var phishingPatterns = [
    { regex: /\b(verify your (account|identity|email|information|details))\b/, label: 'Verify identity request' },
    { regex: /\b(confirm your (account|identity|password|payment|details))\b/, label: 'Confirm credentials request' },
    { regex: /\b(update your (payment|billing|account|information|details))\b/, label: 'Update info request' },
    { regex: /\b(click (here|below|the link|this link) to (verify|confirm|secure|restore|unlock))\b/, label: 'Click-to-verify lure' },
    { regex: /\b(log\s?in to (verify|confirm|secure|restore|review))\b/, label: 'Login lure' },
    { regex: /\b(won a|winner|congratulations|you('ve| have) been selected|claim your (prize|reward))\b/, label: 'Prize/reward bait' },
    { regex: /\b(dear (customer|user|valued|sir|madam|member|client))\b/, label: 'Generic greeting' }
  ];

  var matchedLabels = [];
  for (var i = 0; i < phishingPatterns.length; i++) {
    if (phishingPatterns[i].regex.test(text)) {
      matchedLabels.push(phishingPatterns[i].label);
    }
  }

  if (matchedLabels.length > 0) {
    findings.push(createFinding(
      'content',
      'Phishing patterns (' + matchedLabels.length + ')',
      'Detected phishing indicators: ' + matchedLabels.join(', ') + '. These patterns are commonly used to steal credentials.',
      Math.min(15 + (matchedLabels.length - 1) * 5, 30),
      matchedLabels.length >= 2 ? 'high' : 'medium'
    ));
  }

  return findings;
}

/**
 * Checks for requests for sensitive personal data.
 * @param {string} text - Combined subject + body text (lowercase)
 * @return {Object[]} Array of findings
 */
function checkSensitiveDataRequests(text) {
  var findings = [];

  var sensitivePatterns = [
    { regex: /\b(social security|ssn|tax.?id)\b/, label: 'SSN/Tax ID' },
    { regex: /\b(credit card|debit card|card number|cvv|expir(y|ation) date)\b/, label: 'Credit card details' },
    { regex: /\b(bank account|routing number|swift|iban)\b/, label: 'Bank account info' },
    { regex: /\b(send (me |us )?(your )?password|enter (your )?password|provide (your )?password)\b/, label: 'Password request' },
    { regex: /\b(one.?time.?(password|code|pin)|otp|verification code|mfa code|2fa code)\b/, label: 'MFA/OTP code' }
  ];

  var matchedLabels = [];
  for (var i = 0; i < sensitivePatterns.length; i++) {
    if (sensitivePatterns[i].regex.test(text)) {
      matchedLabels.push(sensitivePatterns[i].label);
    }
  }

  if (matchedLabels.length > 0) {
    findings.push(createFinding(
      'content',
      'Sensitive data request',
      'Email asks for: ' + matchedLabels.join(', ') + '. Legitimate services never ask for sensitive data via email.',
      15,
      'high'
    ));
  }

  return findings;
}

/**
 * Checks for suspicious URLs in the email.
 * @param {string} htmlBody - HTML body of the email
 * @param {string} plainBody - Plain text body (lowercase)
 * @return {Object[]} Array of findings
 */
function checkSuspiciousURLs(htmlBody, plainBody) {
  var findings = [];

  // Extract URLs from HTML href attributes
  var hrefRegex = /<a[^>]+href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  var match;
  var suspiciousURLCount = 0;
  var ipURLCount = 0;
  var shortenedURLCount = 0;
  var mismatchDetails = [];

  while ((match = hrefRegex.exec(htmlBody)) !== null) {
    var href = match[1].trim();
    var displayText = match[2].replace(/<[^>]*>/g, '').trim();

    // Skip mailto, tel, and # links
    if (/^(mailto:|tel:|#|javascript:)/i.test(href)) continue;

    // Check for href/display text mismatch (display shows a domain but href goes elsewhere)
    var displayDomain = extractDomainFromURL(displayText);
    var hrefDomain = extractDomainFromURL(href);
    if (displayDomain && hrefDomain && displayDomain !== hrefDomain) {
      suspiciousURLCount++;
      if (mismatchDetails.length < 3) {
        mismatchDetails.push('"' + displayDomain + '" → ' + hrefDomain);
      }
    }

    // Check for IP-based URLs
    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(href)) {
      ipURLCount++;
    }

    // Check for URL shorteners
    var shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rb.gy', 'shorturl.at'];
    for (var s = 0; s < shorteners.length; s++) {
      if (href.toLowerCase().indexOf(shorteners[s]) > -1) {
        shortenedURLCount++;
        break;
      }
    }
  }

  // Report href mismatches
  if (suspiciousURLCount > 0) {
    findings.push(createFinding(
      'content',
      'URL mismatch (' + suspiciousURLCount + ')',
      'Found ' + suspiciousURLCount + ' link(s) where display text doesn\'t match destination: ' + mismatchDetails.join('; ') + '. This is a common phishing technique.',
      Math.min(suspiciousURLCount * 10, 25),
      'high'
    ));
  }

  // Report IP-based URLs
  if (ipURLCount > 0) {
    findings.push(createFinding(
      'content',
      'IP-based URL (' + ipURLCount + ')',
      'Found ' + ipURLCount + ' link(s) pointing to raw IP addresses instead of domains. Legitimate sites use domain names.',
      Math.min(ipURLCount * 10, 20),
      'high'
    ));
  }

  // Report shortened URLs
  if (shortenedURLCount > 0) {
    findings.push(createFinding(
      'content',
      'Shortened URL (' + shortenedURLCount + ')',
      'Found ' + shortenedURLCount + ' shortened link(s) that hide the real destination. These can mask malicious sites.',
      Math.min(shortenedURLCount * 5, 15),
      'medium'
    ));
  }

  return findings;
}

/**
 * Extracts domain from a URL string or text that looks like a domain/URL.
 * @param {string} text - URL or text
 * @return {string} Domain or empty string
 */
function extractDomainFromURL(text) {
  if (!text) return '';
  var urlMatch = text.match(/https?:\/\/([^\/\s:?#]+)/i);
  if (urlMatch) return urlMatch[1].toLowerCase().replace(/^www\./, '');
  var domainMatch = text.match(/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i);
  if (domainMatch) return text.toLowerCase().replace(/^www\./, '');
  return '';
}
