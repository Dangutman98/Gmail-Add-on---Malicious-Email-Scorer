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

### REMAINING
- **Baby 4:** Attachment sandbox (extensions, magic bytes, SHA256 hash, macro scan)
- **Baby 5:** VirusTotal enrichment (URL, domain, file hash lookups) + Settings card for API key
- **Baby 6:** User blacklist CRUD + Scan/action history + Adaptive scoring
- **Baby 7:** Management console + README + Polish + Demo prep

## Files in the Project

| File | Purpose | Status |
|------|---------|--------|
| `appsscript.json` | Gmail Add-on manifest, scopes, triggers | Done |
| `Code.js` | Entry points, orchestration pipeline | Done |
| `Analyzer.js` | Layers 1-3: auth (SPF/DKIM/DMARC), sender, content analysis | Done |
| `Scoring.js` | Weighted scoring engine + threat narrative builder | Done |
| `CardBuilder.js` | Score card, findings display, homepage, error card | Done |
| `Utils.js` | Helpers: createFinding, extractDomain, getVerdict, score bar | Done |
| `ARCHITECTURE.md` | Full architecture doc with layers, scoring, sprint plan | Done |
| `PROJECT_STATE.md` | This file — current state for context recovery | Done |
| `.clasp.json` | clasp CLI config (user needs to add their scriptId) | Template |
| `README.md` | Basic setup instructions | Needs expansion in Baby 7 |
| `Attachments.js` | NOT YET CREATED — Baby 4 | Pending |
| `Enrichment.js` | NOT YET CREATED — Baby 5 | Pending |
| `Blacklist.js` | NOT YET CREATED — Baby 6 | Pending |
| `History.js` | NOT YET CREATED — Baby 6 | Pending |
| `Settings.js` | NOT YET CREATED — Baby 5/7 | Pending |

## Deployment
- Project is deployed as a **test deployment** in Google Apps Script
- User copies files manually into the Apps Script editor (not using clasp)
- After changes: update .gs files in editor → save → refresh Gmail
- New scopes require re-authorization (Advanced → Go to unsafe → Allow)

## Key Technical Patterns
- `message.getRawContent()` — gets full raw email with headers
- `extractHeaders()` — splits header block at first blank line
- Regex parsing of `Authentication-Results` and `Received-SPF` headers
- `message.getPlainBody()` / `message.getBody()` — for content analysis
- `createFinding(category, signal, detail, score, severity)` — standard finding format
- `calculateScore(findings)` — weighted aggregation with category weights
- `buildScoreCard(message, scoreResult)` — CardService UI builder
- Content weight is 0.7 (not 1.0) to reduce false positives

## Reference Code Found During Research
- VirusTotal API pattern from "Himaya" project (UrlFetchApp.fetch with x-apikey header)
- kosborn/Gmail-Phish-Addon — getRawContent(), getHeader() patterns
- dennisavk/Email-Security-Analyzer — phishing score + VT integration reference
- googleworkspace/gmail-add-on-codelab — CardService navigation patterns

## Next Step
Start Baby 4: Create `Attachments.js` with metadata checks (dangerous extensions,
double extensions, size) and content inspection (magic bytes, SHA256, macro detection).
Wire it into `Code.js` pipeline.
