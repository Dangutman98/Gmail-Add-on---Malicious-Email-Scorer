# Malicious Email Scorer — Gmail Add-on

A Gmail Add-on that analyzes emails for malicious intent using **6 detection layers**, producing an explainable risk score with a clear verdict. Built as a bootcamp home assignment for **Upwind Security**.

## Features

### 6 Detection Layers

| Layer | What it does |
|-------|-------------|
| **Authentication** | Parses SPF, DKIM, DMARC from raw email headers |
| **Sender Analysis** | Detects Reply-To mismatch, display name spoofing, free email impersonation |
| **Content Analysis** | Urgency keywords, phishing patterns, sensitive data requests, suspicious URLs. Auto-translates non-English emails (Hebrew, Arabic, Russian, etc.) |
| **Attachment Sandbox** | In-memory static analysis — dangerous extensions, magic bytes validation, SHA256 hash, macro detection, suspicious strings, encrypted ZIP |
| **VirusTotal Enrichment** | Domain, URL, and file hash reputation lookups via VT API |
| **Blacklist + Adaptive** | User-managed blacklist/whitelist, repeat offender detection, first-time sender alerts |

### Explainable Verdicts
Every score comes with a **Threat Narrative** — a human-readable explanation of why the email received its score, inspired by Upwind's "Threat Stories" approach.

### Management Console
- **Sensitivity levels:** Low / Medium / High — adjusts scoring strictness
- **Feature toggles:** Enable/disable individual detection layers
- **VirusTotal API key management**
- **Data management:** Clear history, reset settings

### Additional Capabilities
- **Multi-language support** — auto-detects and translates non-English emails before analysis
- **Scan history** with statistics (avg score, safe vs risky breakdown)
- **Action history** tracking all user decisions
- **Adaptive scoring** — learns from your scan history (repeat offenders, trusted baselines)

## Architecture

```
Gmail Email Opened
       │
       ▼
┌──────────────────┐
│   Code.js        │  ← Orchestrator
│   (Pipeline)     │
└──────┬───────────┘
       │
       ├──► Analyzer.js      → Layers 1-3: Auth + Sender + Content (+ translation)
       ├──► Attachments.js   → Layer 4: Attachment sandbox
       ├──► Enrichment.js    → Layer 5: VirusTotal API
       ├──► Blacklist.js     → Layer 6: Blacklist/whitelist check
       ├──► History.js       → Layer 6b: Adaptive scoring
       │
       ▼
┌──────────────────┐
│   Scoring.js     │  ← Weighted aggregation + sensitivity multiplier
│   (Score Engine)  │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  CardBuilder.js  │  ← Score card, findings, narrative, actions
│  (UI Builder)    │
└──────────────────┘
```

## File Structure

| File | Lines | Purpose |
|------|-------|---------|
| `Code.js` | ~65 | Entry points, pipeline orchestration |
| `Analyzer.js` | ~524 | Auth (SPF/DKIM/DMARC), sender, content analysis, translation |
| `Attachments.js` | ~425 | Attachment sandbox (metadata + content inspection) |
| `Enrichment.js` | ~253 | VirusTotal API integration |
| `Blacklist.js` | ~360 | Blacklist/whitelist CRUD + check + management card |
| `History.js` | ~384 | Scan/action history + adaptive scoring + history card |
| `Settings.js` | ~250 | Management console: sensitivity, toggles, API key, data |
| `Scoring.js` | ~170 | Weighted scoring engine + threat narrative builder |
| `CardBuilder.js` | ~280 | All UI cards (score, homepage, error) |
| `Utils.js` | ~100 | Shared utilities |
| `appsscript.json` | ~33 | Gmail Add-on manifest |

## Setup — Run It Yourself

**Prerequisites:** A Google account with Gmail, and a modern browser.

---

### Step 1: Get the Code

Clone or download this repo to your computer:

```bash
git clone https://github.com/Dangutman98/Gmail-Add-on---Malicious-Email-Scorer.git
cd Gmail-Add-on---Malicious-Email-Scorer
```

Or download the ZIP from GitHub and extract it.

---

### Step 2: Create the Apps Script Project

1. Open [script.google.com](https://script.google.com) in your browser and sign in.
2. Click **+ New project**.
3. Rename the project to **Malicious Email Scorer** (click "Untitled project" at the top).

---

### Step 3: Add All Script Files

In the Apps Script editor, **delete** the default `Code.gs` content (or leave one file and rename). Create these files and paste the contents from your local repo:

| Create in Apps Script | Copy content from |
|-----------------------|-------------------|
| `Code.gs` | `Code.js` |
| `Analyzer.gs` | `Analyzer.js` |
| `Attachments.gs` | `Attachments.js` |
| `Enrichment.gs` | `Enrichment.js` |
| `Blacklist.gs` | `Blacklist.js` |
| `History.gs` | `History.js` |
| `Settings.gs` | `Settings.js` |
| `Scoring.gs` | `Scoring.js` |
| `CardBuilder.gs` | `CardBuilder.js` |
| `Utils.gs` | `Utils.js` |

To create a new file: click the **+** next to Files, choose **Script**, name it (e.g. `Analyzer`), then paste the content. Save each file (Ctrl+S).

---

### Step 4: Update the Manifest

1. Click the **gear icon** (Project Settings) in the left sidebar.
2. Check **Show "appsscript.json" manifest file in editor**.
3. Click the **Editor** icon to go back.
4. Open `appsscript.json` in the file list.
5. Replace its entire content with the content of `appsscript.json` from this repo.
6. Save (Ctrl+S).

---

### Step 5: Deploy and Install

1. Click **Deploy** → **Test deployments**.
2. Click **Install**.
3. Choose your Google account and click **Allow**.
4. If you see "This app isn't verified": click **Advanced** → **Go to Malicious Email Scorer (unsafe)** → **Allow**.
5. Click **Done**.

---

### Step 6: Use the Add-on in Gmail

1. Open [Gmail](https://mail.google.com) in a new tab.
2. Open any email (click on it).
3. In the right sidebar, click the **puzzle piece** icon (Extensions).
4. Find **Malicious Email Scorer** and click it.
5. The add-on opens and analyzes the email. You should see the risk score, verdict, and signal details.

---

### Step 7 (Optional): Add VirusTotal API Key

For domain/URL/file reputation lookups:

1. Sign up at [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us).
2. After login, click your profile icon → **API key** → copy.
3. In the add-on sidebar, click **Settings**.
4. Paste the key and click **Save API Key**.
5. Free tier: 4 requests/min, 500/day. Without a key, the add-on still works (local analysis only).

---

### Troubleshooting

| Problem | Solution |
|---------|----------|
| Add-on doesn't appear in Gmail | Refresh Gmail, or open the puzzle piece → Malicious Email Scorer. |
| "Permission denied" or UrlFetchApp error | Go to [myaccount.google.com/permissions](https://myaccount.google.com/permissions) → Remove "Malicious Email Scorer" → In Apps Script: Deploy → Test deployments → Install again. |
| Changes not showing | After editing .gs files, save and refresh Gmail. |

## OAuth Scopes

| Scope | Purpose |
|-------|---------|
| `gmail.addons.execute` | Run the add-on |
| `gmail.addons.current.message.metadata` | Read email metadata |
| `gmail.addons.current.message.readonly` | Read email body and attachments |
| `gmail.readonly` | Access raw headers (getRawContent) |
| `script.external_request` | VirusTotal API + translation |
| `script.storage` | User settings, blacklist, history |

## Scoring

- **0–15:** ✅ SAFE (green)
- **16–40:** ⚠️ LOW RISK (yellow-green)
- **41–65:** 🔶 MEDIUM RISK (orange)
- **66–85:** 🔴 HIGH RISK (red)
- **86–100:** 🚨 CRITICAL (dark red)

Category weights: Authentication 1.0, Sender 1.0, Content 0.7, Attachment 1.0, Enrichment 0.9, Blacklist 1.0

Sensitivity multiplier: Low 0.6x, Medium 1.0x, High 1.4x

## Design Philosophy

Inspired by **Upwind Security's** approach to cloud threat detection:

- **Multi-layer detection** — like Upwind's eBPF sensor layers, each layer adds a different perspective
- **Behavioral baselines** — adaptive scoring learns from scan history, similar to Upwind's runtime baselines
- **Threat narratives** — explainable verdicts that tell a story, mirroring Upwind's correlated threat stories
- **Zero trust by default** — every email is analyzed; trust is earned through history
- **Graceful degradation** — works without VirusTotal, works without history, always provides value

## Limitations

- Gmail Add-on sandbox has no persistent server — all analysis runs client-side in Apps Script
- Attachment analysis is static only (no dynamic/behavioral execution)
- VirusTotal free tier has rate limits
- PropertiesService storage has a 500KB quota per user
- Translation depends on Google Translate availability

## Tech Stack

- Google Apps Script (V8 runtime)
- Gmail Add-on framework (CardService)
- VirusTotal API v3
- Google LanguageApp (translation)
- PropertiesService (user data persistence)
