/**
 * Enrichment.js — Layer 5: External API Enrichment (VirusTotal)
 * Queries VirusTotal for domain reputation, URL scanning, and file hash lookups.
 * Only sends URLs, domains, and hashes — never email content or file bytes.
 */

var VT_API_BASE = 'https://www.virustotal.com/api/v3';

/**
 * Runs all enrichment checks on the email.
 * Gracefully skips if no API key is configured.
 * @param {GmailMessage} message - The Gmail message object
 * @return {Object[]} Array of Finding objects
 */
function analyzeEnrichment(message) {
  var apiKey = getVTApiKey();
  if (!apiKey) {
    return [];
  }

  var findings = [];

  // Check sender domain reputation
  var fromDomain = extractDomain(message.getFrom());
  if (fromDomain) {
    findings = findings.concat(checkDomainReputation(fromDomain, apiKey));
  }

  // Check URLs found in email body
  var urls = extractURLsFromBody(message.getBody());
  for (var i = 0; i < Math.min(urls.length, 3); i++) {
    findings = findings.concat(checkURLReputation(urls[i], apiKey));
  }

  // Check attachment hashes
  var attachments = message.getAttachments();
  if (attachments) {
    for (var j = 0; j < Math.min(attachments.length, 2); j++) {
      try {
        var bytes = attachments[j].getBytes();
        var hash = computeSHA256(bytes);
        if (hash) {
          findings = findings.concat(checkFileHashReputation(hash, attachments[j].getName(), apiKey));
        }
      } catch (e) {
        console.error('Error hashing attachment for VT: ' + e.toString());
      }
    }
  }

  return findings;
}

// ============================================================
// VirusTotal API Lookups
// ============================================================

/**
 * Checks domain reputation via VirusTotal.
 * @param {string} domain - Domain to check
 * @param {string} apiKey - VT API key
 * @return {Object[]} Findings
 */
function checkDomainReputation(domain, apiKey) {
  try {
    var response = UrlFetchApp.fetch(VT_API_BASE + '/domains/' + domain, {
      method: 'get',
      headers: { 'x-apikey': apiKey },
      muteHttpExceptions: true
    });

    if (response.getResponseCode() !== 200) return [];

    var json = JSON.parse(response.getContentText());
    var stats = json.data.attributes.last_analysis_stats;

    if (stats.malicious > 0) {
      return [createFinding(
        'enrichment',
        'Malicious domain',
        'Sender domain "' + domain + '" flagged by ' + stats.malicious + ' security engine(s) on VirusTotal. ' +
        (stats.suspicious > 0 ? stats.suspicious + ' additional engine(s) marked it as suspicious. ' : '') +
        'Report: https://www.virustotal.com/gui/domain/' + domain,
        Math.min(25 + stats.malicious * 2, 35),
        stats.malicious >= 3 ? 'critical' : 'high'
      )];
    }

    if (stats.suspicious > 0) {
      return [createFinding(
        'enrichment',
        'Suspicious domain',
        'Sender domain "' + domain + '" marked suspicious by ' + stats.suspicious + ' engine(s) on VirusTotal. Report: https://www.virustotal.com/gui/domain/' + domain,
        10,
        'medium'
      )];
    }
  } catch (e) {
    console.error('VT domain check error: ' + e.toString());
  }
  return [];
}

/**
 * Checks URL reputation via VirusTotal.
 * Uses URL identifier (base64 of URL without padding).
 * @param {string} url - URL to check
 * @param {string} apiKey - VT API key
 * @return {Object[]} Findings
 */
function checkURLReputation(url, apiKey) {
  try {
    // VT URL lookup uses base64url-encoded URL (no padding)
    var urlId = Utilities.base64Encode(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    var response = UrlFetchApp.fetch(VT_API_BASE + '/urls/' + urlId, {
      method: 'get',
      headers: { 'x-apikey': apiKey },
      muteHttpExceptions: true
    });

    if (response.getResponseCode() !== 200) return [];

    var json = JSON.parse(response.getContentText());
    var stats = json.data.attributes.last_analysis_stats;

    if (stats.malicious > 0) {
      var displayUrl = url.length > 60 ? url.substring(0, 57) + '...' : url;
      return [createFinding(
        'enrichment',
        'Malicious URL',
        'URL "' + displayUrl + '" flagged by ' + stats.malicious + ' security engine(s) on VirusTotal.',
        Math.min(30 + stats.malicious * 2, 40),
        stats.malicious >= 3 ? 'critical' : 'high'
      )];
    }

    if (stats.suspicious > 0) {
      var displayUrl = url.length > 60 ? url.substring(0, 57) + '...' : url;
      return [createFinding(
        'enrichment',
        'Suspicious URL',
        'URL "' + displayUrl + '" marked suspicious by ' + stats.suspicious + ' engine(s) on VirusTotal.',
        10,
        'medium'
      )];
    }
  } catch (e) {
    console.error('VT URL check error: ' + e.toString());
  }
  return [];
}

/**
 * Checks file hash reputation via VirusTotal.
 * Only sends the SHA256 hash, never the actual file.
 * @param {string} hash - SHA256 hash
 * @param {string} fileName - Original filename for reporting
 * @param {string} apiKey - VT API key
 * @return {Object[]} Findings
 */
function checkFileHashReputation(hash, fileName, apiKey) {
  try {
    var response = UrlFetchApp.fetch(VT_API_BASE + '/files/' + hash, {
      method: 'get',
      headers: { 'x-apikey': apiKey },
      muteHttpExceptions: true
    });

    // 404 = file not in VT database (not seen before)
    if (response.getResponseCode() === 404) return [];
    if (response.getResponseCode() !== 200) return [];

    var json = JSON.parse(response.getContentText());
    var stats = json.data.attributes.last_analysis_stats;

    if (stats.malicious > 0) {
      return [createFinding(
        'enrichment',
        'Known malware file',
        'Attachment "' + fileName + '" (SHA256: ' + hash.substring(0, 16) + '...) flagged as malware by ' + stats.malicious + ' engine(s) on VirusTotal. Report: https://www.virustotal.com/gui/file/' + hash,
        35,
        'critical'
      )];
    }

    if (stats.suspicious > 0) {
      return [createFinding(
        'enrichment',
        'Suspicious file',
        'Attachment "' + fileName + '" marked suspicious by ' + stats.suspicious + ' engine(s) on VirusTotal.',
        15,
        'high'
      )];
    }
  } catch (e) {
    console.error('VT file hash check error: ' + e.toString());
  }
  return [];
}

// ============================================================
// Helpers
// ============================================================

/**
 * Extracts URLs from HTML email body.
 * @param {string} htmlBody - HTML content
 * @return {string[]} Array of URLs
 */
function extractURLsFromBody(htmlBody) {
  if (!htmlBody) return [];

  var urls = [];
  var seen = {};
  var regex = /href\s*=\s*["'](https?:\/\/[^"']+)["']/gi;
  var match;

  while ((match = regex.exec(htmlBody)) !== null) {
    var url = match[1];
    // Skip Google internal URLs and common safe domains
    if (/\.(google\.com|googleapis\.com|gstatic\.com|gmail\.com)$/i.test(extractDomainFromURL(url))) continue;

    if (!seen[url]) {
      seen[url] = true;
      urls.push(url);
    }
  }

  return urls;
}

/**
 * Gets the VirusTotal API key from user settings.
 * @return {string|null} API key or null if not configured
 */
function getVTApiKey() {
  try {
    return PropertiesService.getUserProperties().getProperty('vt_api_key');
  } catch (e) {
    return null;
  }
}
