# Malicious Email Scorer — Architecture

## Objective

A Gmail Add-on that analyzes an opened email and produces a maliciousness score
with a clear, explainable verdict — inspired by Upwind's runtime-powered threat
detection philosophy: multi-layer signals, baseline-driven adaptation, and
correlated threat narratives rather than isolated alerts.

---

## Design Philosophy

```
Traditional email security:  "Is this on a blacklist?"          → Yes/No
Our approach:                "What story do the signals tell?"  → Correlated verdict

Inspired by Upwind's Threat Stories:
  Multiple signals from different layers are correlated into
  a unified narrative that explains WHY an email is suspicious,
  not just WHETHER it is.
```

**Core principles:**
1. **Multi-layer detection** — authentication, content, attachments, reputation, user knowledge
2. **Explainability** — every score comes with a story: which signals fired and why
3. **Adaptive baselines** — history of scans and user actions improves future decisions
4. **Graceful degradation** — works without external APIs; richer with them

---

## Assignment Capability Coverage

| # | Assignment Capability                     | Where it lives                          | Sprint |
|---|-------------------------------------------|-----------------------------------------|--------|
| 1 | Email Content and Metadata Analysis       | `Analyzer.js`                           | 2, 3   |
| 2 | Risk Scoring and Verdict                  | `Scoring.js`                            | 2      |
| 3 | Explainability                            | `CardBuilder.js` (Threat Story card)    | 2, 3   |
| 4 | Attachment Analysis                       | `Attachments.js` (sandbox)              | 4      |
| 5 | Dynamic Enrichment via External APIs      | `Enrichment.js` (VirusTotal)            | 5      |
| 6 | User-Managed Blacklist                    | `Blacklist.js`                          | 6      |
| 7 | History of Actions                        | `History.js` (adaptive scoring)         | 6      |
| 8 | Management Console for User Configuration | `Settings.js`                           | 5, 7   |

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Gmail (User opens email)                     │
└──────────────────────────┬──────────────────────────────────────┘
                           │ contextual trigger
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Code.js  (Orchestrator)                         │
│                                                                  │
│  1. Receive event + access token                                 │
│  2. Extract email data (headers, body, attachments, metadata)    │
│  3. Run detection layers:                                        │
│     ┌──────────────────────────────────────────────────────┐     │
│     │  Layer 1: Authentication  (SPF / DKIM / DMARC)       │     │
│     │  Layer 2: Sender Analysis (reply-to, domain, free)   │     │
│     │  Layer 3: Content Analysis (keywords, URLs, patterns)│     │
│     │  Layer 4: Attachment Sandbox (types, bytes, hashes)   │     │
│     │  Layer 5: Reputation (VirusTotal API)                │     │
│     │  Layer 6: User Knowledge (blacklist, history)         │     │
│     └──────────────────────────────────────────────────────┘     │
│  4. Feed all findings into Scoring Engine                        │
│  5. Apply history-based adaptive adjustment                      │
│  6. Generate verdict + threat narrative                           │
│  7. Save to history                                              │
│  8. Build UI card → return to Gmail sidebar                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Detection Layers — Detail

### Layer 1: Authentication (SPF / DKIM / DMARC)

**Why it matters:** These protocols prove the sender's identity. Failures are the
highest-confidence signal that an email is spoofed. Major providers (Google, Yahoo,
Microsoft) now require all three as of 2025.

| Check              | How                                           | Score     |
|--------------------|-----------------------------------------------|-----------|
| SPF validation     | Parse `Received-SPF` header for pass/fail     | Fail: +25 |
| DKIM validation    | Parse `Authentication-Results` for dkim=       | Fail: +20 |
| DMARC validation   | Parse `Authentication-Results` for dmarc=      | Fail: +15 |

**Implementation:** Read raw email headers via `GmailApp`, regex-parse the
`Authentication-Results` and `Received-SPF` header values.

---

### Layer 2: Sender Analysis

**Why it matters:** Even if authentication passes, the sender can still be suspicious.
Lookalike domains (`paypa1.com`), display-name spoofing, and reply-to mismatches
are classic social engineering tricks.

| Check                  | How                                                    | Score     |
|------------------------|--------------------------------------------------------|-----------|
| Reply-To mismatch      | Compare From domain vs Reply-To domain                 | +15       |
| Display name spoofing  | Name says "PayPal" but address is `xyz@random.com`     | +10       |
| Free email for business| Sender claims to be a company but uses @gmail/@yahoo   | +5        |
| Lookalike domain       | Levenshtein distance check against known brand domains | +10       |

---

### Layer 3: Content Analysis

**Why it matters:** The body and links reveal the attacker's intent — urgency language
to bypass critical thinking, deceptive URLs to steal credentials, requests for
sensitive data.

| Check                   | How                                                       | Score     |
|-------------------------|-----------------------------------------------------------|-----------|
| Urgency keywords        | Regex for "act now", "suspended", "immediately", etc.     | +10       |
| Phishing patterns       | "verify your account", "confirm your identity"            | +15       |
| Suspicious URLs         | Href mismatch (display vs actual), IP-based URLs          | +10 each  |
| Shortened URLs          | Detect bit.ly, tinyurl, t.co, etc.                        | +5 each   |
| Sensitive data requests | Asks for password, SSN, credit card, MFA code             | +15       |
| Obfuscation             | Zero-width characters, excessive HTML, hidden text        | +10       |

---

### Layer 4: Attachment Sandbox

**Why it matters:** 87% of malicious binary files in emails are actual malware
(Barracuda 2025 report). Attachments are the highest-risk vector.

**How it works:** Attachments are downloaded into Apps Script's server-side memory
for safe static analysis. No files are executed — all inspection is in Google's
isolated V8 sandbox.

**Stage A — Metadata (no download needed):**

| Check                 | How                                              | Score  |
|-----------------------|--------------------------------------------------|--------|
| Dangerous extensions  | `.exe .bat .scr .ps1 .vbs .cmd .js .wsf .hta`   | +30    |
| Macro-enabled docs    | `.docm .xlsm .pptm`                              | +20    |
| Double extensions     | `invoice.pdf.exe`                                 | +25    |
| Archive files         | `.zip .rar .7z .tar.gz`                           | +10    |
| Unusual size          | >25MB or <1KB                                     | +5     |

**Stage B — Content inspection (downloads bytes into sandbox):**

| Check                 | How                                                    | Score  |
|-----------------------|--------------------------------------------------------|--------|
| Magic bytes mismatch  | First bytes don't match extension (PDF header ≠ MZ)    | +30    |
| SHA256 → VirusTotal   | Hash lookup against 70+ antivirus engines              | +35    |
| Macro markers         | Scan for `vbaProject.bin` in Office XML structure      | +20    |
| Suspicious strings    | PowerShell commands, base64 blobs, malicious TLD URLs  | +15    |
| Encrypted archive     | Password-protected ZIP (common malware delivery trick) | +15    |

---

### Layer 5: Reputation Enrichment (VirusTotal)

**Why it matters:** Taps into collective intelligence from 70+ security engines.
Catches known threats that local analysis alone might miss.

| Lookup type      | How                                               | Score     |
|------------------|---------------------------------------------------|-----------|
| URL reputation   | Submit extracted URLs to VT `/urls` endpoint      | Malicious: +30 |
| Domain reputation| Submit sender domain to VT `/domains` endpoint    | Malicious: +25 |
| File hash lookup | Submit SHA256 to VT `/files` endpoint (hash only) | Flagged: +35   |

**Privacy:** Only URLs, domains, and hashes are sent. Never email content or file bytes.
**Graceful degradation:** If no API key configured, this layer is skipped entirely.

---

### Layer 6: User Knowledge (Blacklist + History)

**Why it matters:** The user knows their own threat landscape. A sender they
blacklisted should always score high. A sender they marked safe should get relief.
This mirrors Upwind's baseline concept — learn what's "normal" for this user.

| Check                           | How                                     | Score    |
|---------------------------------|-----------------------------------------|----------|
| Sender on blacklist             | Check email/domain against user's list  | +40      |
| Sender previously HIGH/CRITICAL | Look up scan history for this sender    | +10      |
| Sender marked safe by user      | Look up action history                  | -10      |
| Domain repeat offender          | 3+ high-risk scans from same domain     | +5       |

---

## Scoring Engine

### Aggregation

```
findings[] ← collect from all 6 layers

for each finding:
  weightedScore = finding.score × categoryWeight

finalScore = min(100, max(0, Σ weightedScores + historyAdjustment))
```

### Category Weights

| Category                | Weight | Rationale                                 |
|-------------------------|--------|-------------------------------------------|
| Authentication          | 1.0    | Highest confidence — binary pass/fail     |
| Sender Analysis         | 1.0    | Direct trust signal                       |
| Content Analysis        | 0.7    | Heuristic — prone to false positives      |
| Attachment Sandbox      | 1.0    | High confidence when triggered            |
| Reputation (VirusTotal) | 0.9    | Depends on API availability               |
| Blacklist               | 1.0    | Explicit user intent                      |
| History Adjustment      | ±flat  | Adaptive modifier, not weighted           |

### Verdict Tiers

| Score   | Verdict     | Color  | Meaning                                   |
|---------|-------------|--------|-------------------------------------------|
| 0 – 15  | SAFE        | Green  | No suspicious signals detected             |
| 16 – 40 | LOW RISK    | Yellow | Minor signals, likely benign               |
| 41 – 65 | MEDIUM RISK | Orange | Multiple signals, review recommended       |
| 66 – 85 | HIGH RISK   | Red    | Strong malicious indicators                |
| 86 – 100| CRITICAL    | Dark Red| Very high confidence of malicious intent  |

---

## Threat Narrative (Explainability)

Instead of just showing "Score: 82", we tell a story:

```
┌─────────────────────────────────────────────┐
│  THREAT NARRATIVE                           │
│                                             │
│  "This email failed email authentication    │
│   (SPF and DKIM both failed), the reply-to  │
│   address goes to a different domain than    │
│   the sender, and the body contains 2       │
│   URLs that VirusTotal flagged as           │
│   malicious. This sender was also flagged   │
│   in a previous scan 3 days ago."           │
│                                             │
│  Signals:                                   │
│  ● Authentication: SPF fail, DKIM fail      │
│  ● Sender: Reply-To mismatch               │
│  ● Content: 2 suspicious URLs              │
│  ● Enrichment: 2 URLs flagged by VT        │
│  ● History: Previously scored HIGH RISK     │
└─────────────────────────────────────────────┘
```

Each finding is tagged with:
- **category** (authentication, sender, content, attachment, enrichment, blacklist)
- **severity** (low, medium, high, critical)
- **detail** (human-readable explanation)
- **score** (points contributed)

---

## Storage (PropertiesService)

All data stored per-user via `PropertiesService.getUserProperties()`.
No external database needed.

| Key                  | Type       | Purpose                              |
|----------------------|------------|--------------------------------------|
| `blacklist_emails`   | JSON Array | Blacklisted email addresses          |
| `blacklist_domains`  | JSON Array | Blacklisted domains                  |
| `whitelist_emails`   | JSON Array | Trusted email addresses              |
| `whitelist_domains`  | JSON Array | Trusted domains                      |
| `scan_history`       | JSON Array | Last 50 scan results (FIFO)          |
| `action_history`     | JSON Array | Last 100 user actions (FIFO)         |
| `sensitivity_level`  | String     | 'low', 'medium', or 'high'           |
| `feature_toggles`    | JSON Object| 7 feature on/off flags               |
| `vt_api_key`         | String     | VirusTotal API key                   |

---

## File Structure

```
GmailAddOn/
├── appsscript.json      # Gmail Add-on manifest
├── Code.js              # Entry points + orchestration
├── Analyzer.js          # Layers 1-3: auth, sender, content analysis
├── Attachments.js       # Layer 4: attachment sandbox
├── Enrichment.js        # Layer 5: VirusTotal API
├── Blacklist.js         # Layer 6a: user blacklist CRUD
├── History.js           # Layer 6b: scan/action history + adaptive scoring
├── Scoring.js           # Scoring engine + verdict logic
├── CardBuilder.js       # All UI cards (score, findings, blacklist, history, settings)
├── Settings.js          # User configuration management
├── Utils.js             # Shared helpers (URL extraction, domain parsing, etc.)
├── .clasp.json          # clasp CLI config
├── ARCHITECTURE.md      # This file
└── README.md            # Setup, features, limitations
```

---

## External APIs

| API        | Purpose                            | Free Tier            | Required |
|------------|------------------------------------|----------------------|----------|
| VirusTotal | URL, domain, file hash reputation  | 4 req/min, 500/day   | Optional |

---

## Security Considerations

1. **Minimal scopes** — only `readonly` access to the current message
2. **No email body sent externally** — only URLs, domains, and file hashes go to VT
3. **Attachment sandbox** — bytes loaded into Apps Script memory only, never saved/forwarded
4. **API keys encrypted** — stored in UserProperties (encrypted at rest by Google)
5. **Server-side only** — all analysis in Google's isolated V8 runtime
6. **Hash-only file lookup** — file bytes never leave the sandbox

---

## Design Decisions & Trade-offs

| Decision                          | Rationale                                                    |
|-----------------------------------|--------------------------------------------------------------|
| No backend server                 | Apps Script handles everything — simpler deploy, zero infra  |
| PropertiesService for storage     | Per-user, encrypted, no DB setup. ~9KB limit is sufficient   |
| VirusTotal only                   | Best free tier, covers URLs + domains + file hashes          |
| Static attachment analysis only   | No dynamic execution — trade-off: can't detect zero-days     |
| Hash lookup, not file upload      | Faster, privacy-preserving, within free tier limits          |
| Content weight 0.7 (not 1.0)     | Keywords are heuristic — reduces false positives on marketing emails |
| History-based adaptive scoring    | Mirrors Upwind's baseline concept — tool gets smarter        |
| Score cap at 100                  | Intuitive, prevents inflation when many signals fire         |

---

## Sprint Plan

### Baby 1: Proof of Life ✅ DONE
- Gmail Add-on shows email subject + sender in sidebar
- Deployed and working in Gmail

### Baby 2: Authentication + Scoring + Verdict ✅ DONE
- SPF/DKIM/DMARC parsing from raw email headers
- Weighted scoring engine with category weights
- Score card with color-coded verdict, score bar, threat narrative
- Tested: Google emails correctly score 0 (SAFE)

### Baby 3: Content + Sender Analysis ✅ DONE
- Urgency keywords (6 patterns), phishing patterns (7 patterns), sensitive data requests (5 patterns)
- URL analysis: href mismatch, IP-based URLs, shortened URL detection
- Sender: reply-to mismatch, display name spoofing, free email impersonation
- Tested: phishing test email scored 49% MEDIUM RISK with 4 signals

### Baby 4: Attachment Sandbox ✅ DONE
- Stage A metadata: dangerous extensions, double extensions, macro-enabled, archive, unusual size
- Stage B content: magic bytes validation, suspicious strings scan, macro markers, encrypted ZIP detection
- SHA256 hash computation (ready for VT lookup)
- Tested: ZIP file correctly flagged as archive (+10 pts)

### Baby 5: VirusTotal Enrichment + Settings ✅ DONE
- Domain reputation: GET /api/v3/domains/{domain}
- URL reputation: GET /api/v3/urls/{base64url}
- File hash lookup: GET /api/v3/files/{sha256}
- Settings card: save/remove API key, status indicator, link to get free key
- Graceful skip when no API key configured
- Settings button on score card with VT status

### Baby 6: Blacklist + History + Adaptive Scoring ✅ DONE
- Blacklist CRUD: add/remove emails and domains with ✕ remove buttons
- Whitelist (trusted): reduces score for known-safe senders
- Scan history: saves last 50 scans, viewable in History card with statistics
- Action history: logs last 100 user actions (blacklist/whitelist changes)
- Adaptive scoring: repeat offender domains boosted, first-time sender alerts, safe domain baselines
- Quick action buttons on score card: Blacklist Sender, Blacklist Domain, Mark as Trusted
- Navigation buttons: Blacklist & Whitelist, History, Settings

### Baby 7: Management Console + README + Polish ✅ DONE
- Management console in Settings: sensitivity levels (Low/Medium/High), feature toggles (7 toggleable layers)
- Sensitivity multiplier applied to scoring (0.6x / 1.0x / 1.4x)
- Feature toggles: disable/enable authentication, sender, content, attachments, enrichment, translation, adaptive
- Data management: clear history, reset settings
- Polished homepage: scan statistics, quick navigation, status indicators
- Comprehensive README: architecture diagram, setup guide, scoring details, design philosophy
- Multi-language support: auto-translation of non-English emails via LanguageApp
