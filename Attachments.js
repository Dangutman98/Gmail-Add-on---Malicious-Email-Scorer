/**
 * Attachments.js — Layer 4: Attachment Sandbox Analysis
 * Downloads attachments into Apps Script memory for safe static analysis.
 * No files are executed or saved — all inspection runs server-side in Google's V8 sandbox.
 */

/**
 * Analyzes all attachments on the email.
 * @param {GmailMessage} message - The Gmail message object
 * @return {Object[]} Array of Finding objects
 */
function analyzeAttachments(message) {
  var attachments = message.getAttachments();
  if (!attachments || attachments.length === 0) {
    return [];
  }

  var findings = [];

  for (var i = 0; i < attachments.length; i++) {
    var attachment = attachments[i];
    var fileName = attachment.getName() || 'unknown';
    var fileSize = attachment.getSize();
    var contentType = attachment.getContentType() || '';

    // --- Stage A: Metadata checks (no download needed) ---
    findings = findings.concat(checkDangerousExtension(fileName));
    findings = findings.concat(checkDoubleExtension(fileName));
    findings = findings.concat(checkMacroEnabled(fileName));
    findings = findings.concat(checkArchiveFile(fileName));
    findings = findings.concat(checkUnusualSize(fileName, fileSize));

    // --- Stage B: Content inspection (downloads bytes into sandbox) ---
    try {
      var bytes = attachment.getBytes();
      findings = findings.concat(checkMagicBytes(fileName, bytes));
      findings = findings.concat(checkSuspiciousStrings(fileName, bytes));
      findings = findings.concat(checkMacroMarkers(fileName, bytes, contentType));
      findings = findings.concat(checkEncryptedArchive(fileName, bytes));

      // Compute SHA256 hash (will be used for VT lookup in Baby 5)
      var hash = computeSHA256(bytes);
      if (hash) {
        // SHA256 hash available for VT lookup
      }
    } catch (e) {
      console.error('Error analyzing attachment bytes for "' + fileName + '": ' + e.toString());
    }
  }

  return findings;
}

// ============================================================
// STAGE A: Metadata Checks
// ============================================================

/**
 * Checks for dangerous executable file extensions.
 * @param {string} fileName - Attachment filename
 * @return {Object[]} Findings
 */
function checkDangerousExtension(fileName) {
  var dangerous = ['.exe', '.bat', '.cmd', '.scr', '.ps1', '.vbs', '.vbe',
                   '.js', '.jse', '.wsf', '.wsh', '.msi', '.hta', '.cpl',
                   '.com', '.pif', '.reg', '.dll'];

  var ext = getFileExtension(fileName);
  for (var i = 0; i < dangerous.length; i++) {
    if (ext === dangerous[i]) {
      return [createFinding(
        'attachment',
        'Dangerous file type',
        'Attachment "' + fileName + '" is an executable file type (' + ext + '). These files can run malicious code on your computer.',
        30,
        'critical'
      )];
    }
  }
  return [];
}

/**
 * Checks for double extensions (e.g., invoice.pdf.exe).
 * @param {string} fileName - Attachment filename
 * @return {Object[]} Findings
 */
function checkDoubleExtension(fileName) {
  var parts = fileName.split('.');
  if (parts.length >= 3) {
    var lastExt = '.' + parts[parts.length - 1].toLowerCase();
    var secondExt = '.' + parts[parts.length - 2].toLowerCase();
    var execExts = ['.exe', '.bat', '.cmd', '.scr', '.ps1', '.vbs', '.js', '.hta', '.msi', '.com'];
    var docExts = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.jpg', '.png'];

    if (execExts.indexOf(lastExt) > -1 && docExts.indexOf(secondExt) > -1) {
      return [createFinding(
        'attachment',
        'Double extension trick',
        'Attachment "' + fileName + '" uses a double extension (' + secondExt + lastExt + '). This disguises an executable as a document — a classic malware delivery technique.',
        25,
        'critical'
      )];
    }
  }
  return [];
}

/**
 * Checks for macro-enabled Office documents.
 * @param {string} fileName - Attachment filename
 * @return {Object[]} Findings
 */
function checkMacroEnabled(fileName) {
  var macroExts = ['.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm', '.xlam'];
  var ext = getFileExtension(fileName);

  for (var i = 0; i < macroExts.length; i++) {
    if (ext === macroExts[i]) {
      return [createFinding(
        'attachment',
        'Macro-enabled document',
        'Attachment "' + fileName + '" is a macro-enabled Office document (' + ext + '). Macros can execute malicious code when the file is opened.',
        20,
        'high'
      )];
    }
  }
  return [];
}

/**
 * Checks for archive/compressed files.
 * @param {string} fileName - Attachment filename
 * @return {Object[]} Findings
 */
function checkArchiveFile(fileName) {
  var archiveExts = ['.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz', '.tgz', '.cab', '.iso'];
  var ext = getFileExtension(fileName);

  for (var i = 0; i < archiveExts.length; i++) {
    if (ext === archiveExts[i]) {
      return [createFinding(
        'attachment',
        'Archive file',
        'Attachment "' + fileName + '" is a compressed archive (' + ext + '). Archives can hide malicious files inside and may bypass scanning.',
        10,
        'medium'
      )];
    }
  }
  return [];
}

/**
 * Checks for unusually large or small files.
 * @param {string} fileName - Attachment filename
 * @param {number} fileSize - Size in bytes
 * @return {Object[]} Findings
 */
function checkUnusualSize(fileName, fileSize) {
  if (fileSize > 25 * 1024 * 1024) {
    return [createFinding(
      'attachment',
      'Very large file',
      'Attachment "' + fileName + '" is ' + Math.round(fileSize / 1024 / 1024) + 'MB. Unusually large attachments may contain hidden payloads.',
      5,
      'low'
    )];
  }
  if (fileSize < 100 && fileSize > 0) {
    return [createFinding(
      'attachment',
      'Suspiciously small file',
      'Attachment "' + fileName + '" is only ' + fileSize + ' bytes. Tiny files may be shortcut files or stubs that download malware.',
      5,
      'low'
    )];
  }
  return [];
}

// ============================================================
// STAGE B: Content Inspection (Sandbox)
// ============================================================

/**
 * Known file signatures (magic bytes) mapped to file types.
 */
var MAGIC_BYTES = {
  'exe': { bytes: [0x4D, 0x5A], name: 'Windows Executable (MZ)' },
  'pdf': { bytes: [0x25, 0x50, 0x44, 0x46], name: 'PDF Document' },
  'zip': { bytes: [0x50, 0x4B, 0x03, 0x04], name: 'ZIP Archive' },
  'rar': { bytes: [0x52, 0x61, 0x72, 0x21], name: 'RAR Archive' },
  'png': { bytes: [0x89, 0x50, 0x4E, 0x47], name: 'PNG Image' },
  'jpg': { bytes: [0xFF, 0xD8, 0xFF], name: 'JPEG Image' },
  'gif': { bytes: [0x47, 0x49, 0x46], name: 'GIF Image' },
  'docx': { bytes: [0x50, 0x4B, 0x03, 0x04], name: 'Office Document (ZIP-based)' },
  '7z': { bytes: [0x37, 0x7A, 0xBC, 0xAF], name: '7-Zip Archive' },
  'elf': { bytes: [0x7F, 0x45, 0x4C, 0x46], name: 'Linux Executable (ELF)' }
};

/**
 * Validates that file magic bytes match the claimed extension.
 * Detects file type spoofing (e.g., .pdf that is actually .exe).
 * @param {string} fileName - Attachment filename
 * @param {number[]} bytes - File bytes
 * @return {Object[]} Findings
 */
function checkMagicBytes(fileName, bytes) {
  if (!bytes || bytes.length < 4) return [];

  var ext = getFileExtension(fileName);

  // Check if the file starts with MZ (executable) but claims to be something else
  if (bytes[0] === 0x4D && bytes[1] === 0x5A) {
    var nonExeExts = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                      '.txt', '.jpg', '.png', '.gif', '.csv', '.html'];
    if (nonExeExts.indexOf(ext) > -1) {
      return [createFinding(
        'attachment',
        'File type spoofing',
        'Attachment "' + fileName + '" claims to be ' + ext + ' but has executable (MZ) file signature. This file is disguised — it is actually a Windows executable.',
        30,
        'critical'
      )];
    }
  }

  // Check if claimed PDF doesn't have PDF magic bytes
  if (ext === '.pdf' && !(bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46)) {
    return [createFinding(
      'attachment',
      'PDF signature mismatch',
      'Attachment "' + fileName + '" has .pdf extension but does not start with PDF file signature (%PDF). The file type may be falsified.',
      15,
      'high'
    )];
  }

  return [];
}

/**
 * Scans file content for suspicious strings.
 * Looks for PowerShell commands, base64 payloads, suspicious URLs, etc.
 * @param {string} fileName - Attachment filename
 * @param {number[]} bytes - File bytes
 * @return {Object[]} Findings
 */
function checkSuspiciousStrings(fileName, bytes) {
  if (!bytes || bytes.length === 0) return [];

  // Convert first 50KB to string for scanning (avoid huge files)
  var scanLength = Math.min(bytes.length, 50000);
  var content = '';
  for (var i = 0; i < scanLength; i++) {
    var charCode = bytes[i];
    if (charCode >= 32 && charCode <= 126) {
      content += String.fromCharCode(charCode);
    } else {
      content += ' ';
    }
  }

  var suspiciousPatterns = [];

  // PowerShell commands
  if (/powershell|invoke-expression|invoke-webrequest|downloadstring|iex\s*\(/i.test(content)) {
    suspiciousPatterns.push('PowerShell commands');
  }

  // cmd/batch commands
  if (/cmd\.exe|command\.com|wscript|cscript/i.test(content)) {
    suspiciousPatterns.push('Command shell references');
  }

  // Large base64 blobs (>100 chars of continuous base64)
  if (/[A-Za-z0-9+\/]{100,}={0,2}/.test(content)) {
    suspiciousPatterns.push('Base64-encoded payload');
  }

  // Registry manipulation
  if (/HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|reg\s+add/i.test(content)) {
    suspiciousPatterns.push('Registry manipulation');
  }

  // Network download commands
  if (/wget|curl\s|certutil.*urlcache|bitsadmin/i.test(content)) {
    suspiciousPatterns.push('Network download commands');
  }

  if (suspiciousPatterns.length > 0) {
    return [createFinding(
      'attachment',
      'Suspicious content in file',
      'Attachment "' + fileName + '" contains: ' + suspiciousPatterns.join(', ') + '. These patterns are commonly found in malware and exploit scripts.',
      15,
      'high'
    )];
  }

  return [];
}

/**
 * Checks for embedded macro markers in Office documents.
 * Looks for vbaProject.bin and other macro indicators.
 * @param {string} fileName - Attachment filename
 * @param {number[]} bytes - File bytes
 * @param {string} contentType - MIME type
 * @return {Object[]} Findings
 */
function checkMacroMarkers(fileName, bytes, contentType) {
  if (!bytes || bytes.length === 0) return [];

  var ext = getFileExtension(fileName);
  var officeExts = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.docm', '.xlsm', '.pptm'];
  var isOffice = officeExts.indexOf(ext) > -1 ||
                 contentType.indexOf('officedocument') > -1 ||
                 contentType.indexOf('msword') > -1 ||
                 contentType.indexOf('ms-excel') > -1;

  if (!isOffice) return [];

  // Convert to string to search for macro markers
  var scanLength = Math.min(bytes.length, 100000);
  var content = '';
  for (var i = 0; i < scanLength; i++) {
    var c = bytes[i];
    if (c >= 32 && c <= 126) content += String.fromCharCode(c);
    else content += ' ';
  }

  var macroIndicators = [];

  if (content.indexOf('vbaProject.bin') > -1 || content.indexOf('VBA') > -1) {
    macroIndicators.push('VBA project detected');
  }
  if (/Auto_?Open|AutoExec|Document_?Open|Workbook_?Open/i.test(content)) {
    macroIndicators.push('Auto-execute macro');
  }
  if (/Shell|CreateObject|WScript/i.test(content)) {
    macroIndicators.push('Shell execution in macro');
  }

  if (macroIndicators.length > 0) {
    return [createFinding(
      'attachment',
      'Embedded macros detected',
      'Attachment "' + fileName + '": ' + macroIndicators.join(', ') + '. Macros with auto-execute and shell access are a top malware delivery method.',
      20,
      'high'
    )];
  }

  return [];
}

/**
 * Checks if a ZIP file is password-protected (encrypted).
 * @param {string} fileName - Attachment filename
 * @param {number[]} bytes - File bytes
 * @return {Object[]} Findings
 */
function checkEncryptedArchive(fileName, bytes) {
  if (!bytes || bytes.length < 10) return [];

  var ext = getFileExtension(fileName);
  if (ext !== '.zip') return [];

  // ZIP local file header: bytes 6-7 are general purpose bit flag
  // Bit 0 set = encrypted
  if (bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04) {
    var flags = bytes[6] | (bytes[7] << 8);
    if (flags & 0x01) {
      return [createFinding(
        'attachment',
        'Password-protected archive',
        'Attachment "' + fileName + '" is an encrypted ZIP file. Password-protected archives are a common malware delivery trick — they prevent security scanners from inspecting the contents.',
        15,
        'high'
      )];
    }
  }

  return [];
}

// ============================================================
// Helpers
// ============================================================

/**
 * Gets the lowercase file extension from a filename.
 * @param {string} fileName
 * @return {string} Extension with dot, e.g., ".pdf"
 */
function getFileExtension(fileName) {
  if (!fileName) return '';
  var lastDot = fileName.lastIndexOf('.');
  if (lastDot === -1) return '';
  return fileName.substring(lastDot).toLowerCase();
}

/**
 * Computes SHA256 hash of file bytes.
 * @param {number[]} bytes - File bytes
 * @return {string} Hex-encoded SHA256 hash, or empty string on error
 */
function computeSHA256(bytes) {
  try {
    var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
    var hash = '';
    for (var i = 0; i < digest.length; i++) {
      var b = (digest[i] + 256) % 256;
      hash += ('0' + b.toString(16)).slice(-2);
    }
    return hash;
  } catch (e) {
    console.error('SHA256 error: ' + e.toString());
    return '';
  }
}
