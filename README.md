# Malicious Email Scorer

> A Gmail Add-on that analyzes emails in real time for phishing, spoofing, and malware — producing an explainable risk score with a clear verdict.

## What It Does

When you open an email in Gmail, the add-on runs **6 detection layers** against it and shows a risk score (0–100) with a human-readable explanation of exactly which signals fired and why.

**Example verdicts:**
- `✅ SAFE (4/100)` — Clean domain, no suspicious patterns.
- `🔶 MEDIUM RISK (49/100)` — Urgency language detected, Reply-To mismatch.
- `🔴 HIGH RISK (78/100)` — SPF failed, malicious URL flagged by VirusTotal, attachment with macro.

## Features

### Detection Layers

| # | Layer | What it checks |
|---|-------|---------------|
| 1 | **Authentication** | SPF, DKIM, DMARC — parsed from raw email headers |
| 2 | **Sender Analysis** | Reply-To mismatch, display name spoofing, free email impersonation |
| 3 | **Content Analysis** | Urgency keywords, phishing patterns, sensitive data requests, suspicious URLs. Auto-translates non-English emails (Hebrew, Arabic, Russian, etc.) |
| 4 | **Attachment Sandbox** | In-memory static analysis — dangerous extensions, magic bytes validation, SHA256 hash, macro detection, suspicious strings, encrypted ZIP |
| 5 | **VirusTotal Enrichment** | Domain, URL, and file hash reputation lookups via VT API v3 |
| 6 | **Blacklist + Adaptive** | User-managed blacklist/whitelist, repeat offender detection, first-time sender alerts, history-based scoring |

### Explainability

Every score comes with a **Threat Narrative** — a correlated story explaining which signals fired and why, instead of just a number.

### Management Console

- **Sensitivity levels** — Low (0.6x) / Medium (1.0x) / High (1.4x)
- **Feature toggles** — Enable/disable each detection layer individually
- **Scan history** — View past scans with statistics
- **VirusTotal API key** — Enter, update, or remove
- **Data management** — Clear history, reset all settings

## Architecture

```
Gmail — user opens an email
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│  code.js — Orchestrator                                   │
│                                                           │
│  ┌─────────────┐  ┌───────────────┐  ┌────────────────┐ │
│  │ analyzer.js  │  │ attachments.js│  │ enrichment.js  │ │
│  │ Layers 1-3   │  │ Layer 4       │  │ Layer 5 (VT)   │ │
│  └──────┬───────┘  └──────┬────────┘  └──────┬─────────┘ │
│         │                 │                   │           │
│  ┌──────┴─────┐    ┌──────┴──────┐    ┌──────┴────────┐ │
│  │blacklist.js│    │ history.js  │    │ settings.js   │ │
│  │ Layer 6    │    │ Layer 6b    │    │ Config/toggles│ │
│  └────────────┘    └─────────────┘    └───────────────┘ │
│                                                           │
│         All findings → scoring.js → cardbuilder.js        │
└──────────────────────────────────────────────────────────┘
```

## Project Structure

```
├── README.md               # This file
├── ARCHITECTURE.md          # Detailed design document
├── appsscript.json          # Gmail Add-on manifest (triggers + OAuth scopes)
├── .clasp.json              # clasp CLI config (optional)
├── .gitignore
└── src/
    ├── code.js              # Entry points + pipeline orchestration
    ├── analyzer.js           # Authentication, sender, content analysis + translation
    ├── attachments.js        # Attachment sandbox (metadata + byte-level inspection)
    ├── enrichment.js         # VirusTotal API (domain, URL, file hash lookups)
    ├── blacklist.js          # Blacklist/whitelist CRUD + management card
    ├── history.js            # Scan/action history + adaptive scoring + stats card
    ├── settings.js           # Management console (sensitivity, toggles, API key)
    ├── scoring.js            # Weighted scoring engine + threat narrative
    ├── cardbuilder.js        # All Gmail sidebar UI cards
    └── utils.js              # Shared helpers (domain extraction, finding format, etc.)
```

## Installation

### Prerequisites

- A Google account with Gmail
- A modern web browser

### Step 1 — Get the code

```bash
git clone https://github.com/Dangutman98/Gmail-Add-on---Malicious-Email-Scorer.git
cd Gmail-Add-on---Malicious-Email-Scorer
```

Or download the ZIP from GitHub and extract it.

### Step 2 — Create an Apps Script project

1. Go to [script.google.com](https://script.google.com) and sign in.
2. Click **+ New project**.
3. Rename it to **Malicious Email Scorer** (click "Untitled project" at the top).

### Step 3 — Add the source files

In the Apps Script editor, create one `.gs` file for each `.js` file in `src/` and paste the contents:

| Create in Apps Script | Copy content from |
|-----------------------|-------------------|
| `Code.gs` | `src/code.js` |
| `Analyzer.gs` | `src/analyzer.js` |
| `Attachments.gs` | `src/attachments.js` |
| `Enrichment.gs` | `src/enrichment.js` |
| `Blacklist.gs` | `src/blacklist.js` |
| `History.gs` | `src/history.js` |
| `Settings.gs` | `src/settings.js` |
| `Scoring.gs` | `src/scoring.js` |
| `CardBuilder.gs` | `src/cardbuilder.js` |
| `Utils.gs` | `src/utils.js` |

To create a file: click **+** next to "Files" → **Script** → name it → paste content → **Ctrl+S**.

### Step 4 — Set up the manifest

1. In the left sidebar, click the **gear** icon (Project Settings).
2. Toggle ON **Show "appsscript.json" manifest file in editor**.
3. Go back to **Editor**, open `appsscript.json`.
4. Replace its entire content with the `appsscript.json` from this repo.
5. Save (**Ctrl+S**).

### Step 5 — Deploy

1. Click **Deploy** → **Test deployments** → **Install**.
2. Click **Authorize access** → select your Google account.
3. If you see "This app isn't verified": click **Advanced** → **Go to Malicious Email Scorer (unsafe)** → **Allow**.
4. Click **Done**.

### Step 6 — Open in Gmail

1. Go to [Gmail](https://mail.google.com).
2. Open any email.
3. In the right sidebar, click the **puzzle piece** icon (Extensions).
4. Click **Malicious Email Scorer** — the analysis runs and the score card appears.

## Configuration

### VirusTotal API Key (optional)

Adds domain, URL, and file hash reputation lookups from 70+ security engines.

1. Create a free account at [virustotal.com](https://www.virustotal.com/gui/join-us).
2. Go to your profile → **API key** → copy.
3. In the add-on, click **Settings** → paste key → **Save API Key**.

Free tier: 4 requests/min, 500/day. Without a key, everything still works — just local analysis.

### Sensitivity Levels

| Level | Multiplier | Effect |
|-------|-----------|--------|
| Low | 0.6x | Only flag high-confidence threats |
| Medium | 1.0x | Balanced detection (default) |
| High | 1.4x | Flag everything suspicious |

### Feature Toggles

Each detection layer can be enabled/disabled independently via **Settings & Console**.

## Scoring

| Score | Verdict | Color |
|-------|---------|-------|
| 0–15 | SAFE | Green |
| 16–40 | LOW RISK | Yellow-green |
| 41–65 | MEDIUM RISK | Orange |
| 66–85 | HIGH RISK | Red |
| 86–100 | CRITICAL | Dark red |

**Category weights:** Authentication 1.0 · Sender 1.0 · Content 0.7 · Attachment 1.0 · Enrichment 0.9 · Blacklist 1.0

## OAuth Scopes

| Scope | Why |
|-------|-----|
| `gmail.addons.execute` | Run the add-on |
| `gmail.addons.current.message.metadata` | Read email metadata |
| `gmail.addons.current.message.readonly` | Read email body and attachments |
| `gmail.readonly` | Access raw headers for authentication parsing |
| `script.external_request` | VirusTotal API calls + Google Translate |
| `script.storage` | Persist user settings, blacklist, and history |

## Tech Stack

- **Runtime:** Google Apps Script (V8)
- **UI:** Gmail Add-on CardService
- **Threat intelligence:** VirusTotal API v3
- **Translation:** Google LanguageApp
- **Storage:** PropertiesService (per-user, encrypted at rest)

## Limitations

- Runs entirely in Google's Apps Script sandbox — no backend server
- Attachment analysis is static only (no dynamic execution / behavioral analysis)
- VirusTotal free tier has rate limits (4 req/min)
- PropertiesService storage quota is ~500KB per user
- Translation quality depends on Google Translate

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Add-on not visible in Gmail | Refresh Gmail. Click the puzzle piece icon in the sidebar. |
| "Permission denied" or UrlFetchApp error | Go to [myaccount.google.com/permissions](https://myaccount.google.com/permissions) → remove "Malicious Email Scorer" → reinstall via Deploy → Test deployments. |
| Score doesn't change after toggling features | Make sure you saved the toggle in Settings, then re-open the email. |
| Changes to code not showing | Save all `.gs` files in the editor, then refresh Gmail. |
