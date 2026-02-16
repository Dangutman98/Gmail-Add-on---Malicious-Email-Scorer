# Project State — Last Updated: Feb 16, 2026

## What This Is
Gmail Add-on for Upwind bootcamp home task. Analyzes emails for maliciousness
and produces a score with explainable verdict.

## Interview Context
- **Company:** Upwind (cloud security, eBPF-based runtime threat detection)
- **Interviewer:** Cloud monitoring engineer
- **Assignment PDF:** Bootcamp home task - Gmail Add-on Malicious Email Scorer
- **Repository:** https://github.com/Dangutman98/Gmail-Add-on---Malicious-Email-Scorer.git
- **Design philosophy:** Mirrors Upwind's approach — multi-layer detection, baselines, threat narratives, explainability

## Current Sprint Status

### COMPLETED
- **Baby 1:** Minimal add-on showing subject + sender in sidebar ✅
- **Baby 2:** Authentication parsing (SPF/DKIM/DMARC) + Scoring engine + Verdict card ✅
- **Baby 3:** Content analysis (urgency keywords, phishing patterns, sensitive data requests, suspicious URLs) ✅
- **Baby 4:** Attachment sandbox (extensions, double ext, magic bytes, SHA256, macro scan, suspicious strings, encrypted ZIP) ✅
- **Baby 5:** VirusTotal enrichment + Settings + Multi-language + Clean confirmations ✅
  - VirusTotal API: domain, URL, file hash lookups
  - Settings card: API key save/remove/status
  - Clean domain confirmation: shows "Domain is clean" when VT finds no threats
  - Scoring: info severity handled, narrative says "VT scan came back clean" for safe results
  - Multi-language support: auto-translates non-English emails (Hebrew, Arabic, Russian, etc.) to English before content analysis using LanguageApp.translate()

### REMAINING
- **Baby 6:** User blacklist CRUD + Scan/action history + Adaptive scoring
- **Baby 7:** Management console polish + README + Demo prep

## Files in the Project

| File | Purpose | Status |
|------|---------|--------|
| `appsscript.json` | Gmail Add-on manifest (6 OAuth scopes, triggers) | Done |
| `Code.js` | Entry points, orchestration pipeline (layers 1-5 wired) | Done |
| `Analyzer.js` | Layers 1-3: auth, sender, content + multi-language translation | Done |
| `Attachments.js` | Layer 4: attachment sandbox (Stage A metadata + Stage B content) | Done |
| `Enrichment.js` | Layer 5: VirusTotal API (domain, URL, file hash) + clean confirmations | Done |
| `Settings.js` | Settings card: VT API key save/remove, navigation callbacks | Done |
| `Scoring.js` | Weighted scoring engine + threat narrative + info severity support | Done |
| `CardBuilder.js` | Score card, findings display, VT status, settings button, homepage, error card | Done |
| `Utils.js` | Helpers: createFinding, extractDomain, getVerdict, getScoreColor, score bar | Done |
| `ARCHITECTURE.md` | Full architecture doc with layers, scoring, sprint plan | Done |
| `PROJECT_STATE.md` | This file — current state for context recovery | Done |
| `.clasp.json` | clasp CLI config (user needs to add their scriptId) | Template |
| `README.md` | Basic setup instructions | Needs expansion in Baby 7 |
| `Blacklist.js` | NOT YET CREATED — Baby 6 | Pending |
| `History.js` | NOT YET CREATED — Baby 6 | Pending |

## OAuth Scopes in appsscript.json
1. `gmail.addons.execute` — add-on execution
2. `gmail.addons.current.message.metadata` — email metadata
3. `gmail.addons.current.message.readonly` — email body/attachments
4. `gmail.readonly` — raw email headers (getRawContent)
5. `script.external_request` — VirusTotal API calls (UrlFetchApp) + LanguageApp translation
6. `script.storage` — PropertiesService for settings/blacklist/history

## Deployment
- Project is deployed as a **test deployment** in Google Apps Script
- User copies files manually into the Apps Script editor (not using clasp)
- After changes: update .gs files in editor → save → refresh Gmail
- New scopes require re-authorization: go to myaccount.google.com/permissions → remove app → reinstall test deployment
- VirusTotal API key: Settings card → paste key → Save. Free tier: 4 req/min, 500/day

## Key Technical Patterns

### Analysis Pipeline (Code.js)
```
onGmailMessageOpen(e)
  → analyzeEmail(message)        // Analyzer.js: layers 1-3 (auth, sender, content + translation)
  → analyzeAttachments(message)  // Attachments.js: layer 4
  → analyzeEnrichment(message)   // Enrichment.js: layer 5 (skips if no VT key)
  → calculateScore(findings)     // Scoring.js: weighted aggregation
  → buildScoreCard(message, scoreResult) // CardBuilder.js: UI
```

### Finding Object Format
```javascript
{ category, signal, detail, score, severity }
```
Categories: authentication, sender, content, attachment, enrichment, blacklist
Severities: info, low, medium, high, critical

### Category Weights (Scoring.js)
- authentication: 1.0, sender: 1.0, content: 0.7, attachment: 1.0, enrichment: 0.9, blacklist: 1.0

### VirusTotal Integration (Enrichment.js)
- API key stored in: `PropertiesService.getUserProperties().getProperty('vt_api_key')`
- Domain: `GET /api/v3/domains/{domain}` → clean/suspicious/malicious finding
- URL: `GET /api/v3/urls/{base64url_no_padding}` → suspicious/malicious finding
- File hash: `GET /api/v3/files/{sha256}` → suspicious/malicious finding
- All use `x-apikey` header, `muteHttpExceptions: true`
- Clean domains return an info-severity "Domain is clean" finding
- Graceful skip if no key configured

### Multi-Language Support (Analyzer.js)
- `translateIfNeeded(text)` detects non-Latin chars (Hebrew, Arabic, Cyrillic, CJK, Korean)
- Uses `LanguageApp.translate(sample, '', 'en')` — auto-detects source language
- Translates first 3000 chars, then runs all English pattern checks on translated text
- Falls back to original text if translation fails

### Settings Card Navigation (Settings.js)
- `onOpenSettings()` → pushCard(buildSettingsCard())
- `onSaveVTApiKey(e)` → saves to UserProperties
- `onClearVTApiKey()` → deletes from UserProperties
- `onBackToHome()` → popCard()

### Attachment Sandbox (Attachments.js)
- Stage A (metadata): dangerous extensions, double ext, macro-enabled, archive, size
- Stage B (content): magic bytes validation, suspicious strings, macro markers, encrypted ZIP
- `computeSHA256(bytes)` — used for VT file hash lookup

### Scoring Details (Scoring.js)
- `getCategoryStatus()` returns PASS for info-only findings (green in UI)
- Threat narrative distinguishes "VT scan came back clean" vs "flagged"
- Score capped at 0-100, findings with score 0 don't affect total

## Reference Code Found During Research
- VirusTotal API pattern from "Himaya" project (UrlFetchApp.fetch with x-apikey header)
- kosborn/Gmail-Phish-Addon — getRawContent(), getHeader() patterns
- dennisavk/Email-Security-Analyzer — phishing score + VT integration reference
- googleworkspace/gmail-add-on-codelab — CardService navigation patterns

## Next Step
Start Baby 6: Create `Blacklist.js` (add/remove emails/domains, check against blacklist)
and `History.js` (scan history + action log + adaptive scoring). Wire into Code.js pipeline.
Add Blacklist card and History card to CardBuilder.js with navigation buttons on score card.
