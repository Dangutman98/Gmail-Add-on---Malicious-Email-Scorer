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
- **Sprint 1:** Minimal add-on showing subject + sender in sidebar ✅
- **Sprint 2:** Authentication parsing (SPF/DKIM/DMARC) + Scoring engine + Verdict card ✅
- **Sprint 3:** Content analysis (urgency keywords, phishing patterns, sensitive data requests, suspicious URLs) ✅
- **Sprint 4:** Attachment sandbox (extensions, double ext, magic bytes, SHA256, macro scan, suspicious strings, encrypted ZIP) ✅
- **Sprint 5:** VirusTotal enrichment + Settings + Multi-language + Clean confirmations ✅
  - VirusTotal API: domain, URL, file hash lookups
  - Settings card: API key save/remove/status
  - Clean domain confirmation: shows "Domain is clean" when VT finds no threats
  - Multi-language: auto-translates non-English emails via LanguageApp.translate()
- **Sprint 6:** Blacklist + Whitelist + History + Adaptive scoring ✅
  - Blacklist CRUD: add/remove emails and domains with ✕ remove buttons
  - Whitelist (trusted): reduces score by -10 for trusted emails, -5 for trusted domains
  - Scan history: saves last 50 scans with score, verdict, sender info
  - Action history: logs all blacklist/whitelist actions (last 100)
  - Adaptive scoring: repeat offender domains (+5 per past flag), first-time sender info, known safe domain baseline
  - History card: recent scans, recent actions, statistics (total, avg score, safe vs risky)
  - Score card: quick action buttons (Blacklist Sender, Blacklist Domain, Mark as Trusted)
  - Navigation: Blacklist & Whitelist, History, Settings buttons

- **Sprint 7:** Management console + README + Polish ✅
  - Settings card → full management console: sensitivity levels (Low/Med/High), 7 feature toggles
  - Sensitivity multiplier: Low 0.6x, Medium 1.0x, High 1.4x applied to scoring
  - Feature toggles: authentication, sender, content, attachments, enrichment, translation, adaptive
  - Data management: clear history, reset settings buttons
  - Homepage: scan stats, quick navigation, status indicators
  - Comprehensive README with architecture diagram, setup, scoring, design philosophy

### ALL SPRINTS COMPLETE

## Files in the Project

| File | Purpose | Status |
|------|---------|--------|
| `appsscript.json` | Gmail Add-on manifest (6 OAuth scopes, triggers) | Done |
| `Code.js` | Entry points, orchestration pipeline (layers 1-6 wired + history save) | Done |
| `Analyzer.js` | Layers 1-3: auth, sender, content + multi-language translation | Done |
| `Attachments.js` | Layer 4: attachment sandbox (Stage A metadata + Stage B content) | Done |
| `Enrichment.js` | Layer 5: VirusTotal API (domain, URL, file hash) + clean confirmations | Done |
| `Blacklist.js` | Layer 6: blacklist/whitelist CRUD + check + management card | Done |
| `History.js` | Layer 6b: scan history + action log + adaptive scoring + history card | Done |
| `Settings.js` | Settings card: VT API key save/remove, navigation callbacks | Done |
| `Scoring.js` | Weighted scoring engine + threat narrative + adaptive narrative | Done |
| `CardBuilder.js` | Score card, quick actions, navigation, findings, homepage, error card | Done |
| `Utils.js` | Helpers: createFinding, extractDomain, getVerdict, getScoreColor, score bar | Done |
| `ARCHITECTURE.md` | Full architecture doc with layers, scoring, sprint plan | Done |
| `PROJECT_STATE.md` | This file — current state for context recovery | Done |
| `.clasp.json` | clasp CLI config (user needs to add their scriptId) | Template |
| `README.md` | Basic setup instructions | Needs expansion in Sprint 7 |

## OAuth Scopes in appsscript.json
1. `gmail.addons.execute` — add-on execution
2. `gmail.addons.current.message.metadata` — email metadata
3. `gmail.addons.current.message.readonly` — email body/attachments
4. `gmail.readonly` — raw email headers (getRawContent)
5. `script.external_request` — VirusTotal API calls + LanguageApp translation
6. `script.storage` — PropertiesService for settings/blacklist/whitelist/history

## Deployment
- Project is deployed as a **test deployment** in Google Apps Script
- User copies files manually into the Apps Script editor (not using clasp)
- After changes: update .gs files in editor → save → refresh Gmail
- New scopes require re-authorization: myaccount.google.com/permissions → remove app → reinstall
- VirusTotal API key: Settings card → paste key → Save. Free tier: 4 req/min, 500/day

## Key Technical Patterns

### Analysis Pipeline (Code.js)
```
onGmailMessageOpen(e)
  → analyzeEmail(message)        // Analyzer.js: layers 1-3 (auth, sender, content + translation)
  → analyzeAttachments(message)  // Attachments.js: layer 4
  → analyzeEnrichment(message)   // Enrichment.js: layer 5 (skips if no VT key)
  → checkBlacklist(message)      // Blacklist.js: layer 6 (blacklist/whitelist check)
  → getAdaptiveFindings(message) // History.js: layer 6b (repeat offender, first-time sender)
  → calculateScore(findings)     // Scoring.js: weighted aggregation
  → saveScanHistory(message, scoreResult) // History.js: persist scan
  → buildScoreCard(message, scoreResult)  // CardBuilder.js: UI
```

### Finding Object Format
```javascript
{ category, signal, detail, score, severity }
```
Categories: authentication, sender, content, attachment, enrichment, blacklist
Severities: info, low, medium, high, critical

### Category Weights (Scoring.js)
- authentication: 1.0, sender: 1.0, content: 0.7, attachment: 1.0, enrichment: 0.9, blacklist: 1.0

### Storage Keys (PropertiesService.getUserProperties)
- `vt_api_key` — VirusTotal API key string
- `blacklist_emails` — JSON array of blacklisted emails
- `blacklist_domains` — JSON array of blacklisted domains
- `whitelist_emails` — JSON array of trusted emails
- `whitelist_domains` — JSON array of trusted domains
- `scan_history` — JSON array of scan entries (max 50)
- `action_history` — JSON array of action entries (max 100)

### Score Card UI Sections
1. Score display (score bar, verdict, signals count)
2. Threat Narrative
3. Signal Details (grouped by category with PASS/WARNING/FAIL status)
4. Email Info (subject, from, date)
5. Quick Actions (Blacklist Sender, Blacklist Domain, Mark as Trusted)
6. Navigation (VT status, Blacklist & Whitelist, History, Settings)

### Navigation Cards
- `onOpenBlacklist()` → Blacklist & Whitelist management card
- `onOpenHistory()` → Scan history + actions + statistics card
- `onOpenSettings()` → VT API key management card
- `onBackToHome()` → pop card (go back)

## Next Step
Sprint 7: Management console polish + README + Demo prep
- Management console: sensitivity levels, feature toggles
- Clean README: architecture, APIs, features, limitations, setup instructions
- Code cleanup, error handling, edge cases
- Demo preparation with test emails
- Interview-ready deliverable
