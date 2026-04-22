# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**Spam Shield** is a Manifest V3 Chrome extension (works on Chrome, Edge, and Brave) that detects spam, phishing, and scam emails. It operates in two modes:

- **Auto mode**: when the active tab is a supported webmail client (Gmail, Outlook, Yahoo Mail, Proton Mail), it injects `content.js` to extract the open email's sender/subject/body/headers via DOM scraping, auto-populates the header fields panel, and shows a preview with an "Evaluate Email" button.
- **Manual mode**: on any other page, the popup shows a paste form where the user enters email content and optional header fields directly.

Both modes feed into the same analysis pipeline and render results in the shared results panel.

## Loading the extension for development

There is no build step — the extension runs directly from source files.

1. Open `chrome://extensions` in Chrome (or `brave://extensions` in Brave)
2. Enable **Developer mode**
3. Click **Load unpacked** and select the `spam-shield-extension/` directory
4. Click the extension icon in the toolbar to open `popup.html`

After editing any file, click the reload icon on the extension card and re-open the popup.

## Architecture

### Files

| File | Role |
|------|------|
| `manifest.json` | MV3 manifest — permissions (`activeTab`, `storage`, `scripting`), host permissions for all four webmail clients, content script injection, service worker declaration |
| `background.js` | Minimal service worker; responds to `{ action: 'ping' }` to confirm the extension is alive |
| `content.js` | Injected into supported webmail pages at `document_idle`; one DOM scraper per client (`extractGmail`, `extractOutlook`, `extractYahooMail`, `extractProtonMail`); responds to `{ action: 'extractEmail' }` messages |
| `popup.js` | All UI logic, analysis engine, AI API calls, and results rendering |
| `popup.html` | Two views: `#mainView` (email mode + manual mode + results panel) and `#settingsView` (API key / provider config) |
| `popup.css` | All styles |
| `icons/` | `icon16.png`, `icon48.png`, `icon128.png` — generate via `generate-icons.js` (Node) or `generate_icons.html` (browser canvas) |

### Analysis pipeline (`popup.js`)

`runAnalysis(senderVal, subjectVal, bodyVal, headerData, triggerBtn, originalBtnHTML)` is the single entry point for both modes. It:

1. Loads `apiKey`, `orKey`, `orModel`, `aiProvider` from `chrome.storage.local`
2. Determines provider order based on which keys are present and the saved preference:
   - Both keys → preferred provider first, other as fallback
   - One key → use it directly
   - No keys → skip to heuristic
3. Iterates provider order, calling `analyzeWithClaude()` or `analyzeWithOpenRouter()`; catches errors and falls through to the next
4. Falls back to `analyzeEmail()` (local heuristic) if all AI calls fail
5. Calls `analyzeHeaders(headerData)` and blends `addedSpamScore` (up to +30) into the content score
6. Re-derives verdict from the blended score
7. Calls `renderResults({ score, verdict, findings, authResult })`

**Heuristic engine** (`analyzeEmail`): three-tier rule set in `SPAM_RULES` (`critical` / `high` / `medium`) with weighted scoring (15 / 8 / 3 per tier). Structural checks (ALL-CAPS ratio, exclamation count, suspicious/shortened URLs, sender domain spoofing against known brands) add additional score. Score ≤25 → safe, ≤55 → suspicious, >55 → spam. Each finding includes an `extractSnippet()` result — ±60 chars of context around the match, split into `{ before, matched, after }` for highlighted rendering.

**Claude path** (`analyzeWithClaude`): POSTs to `https://api.anthropic.com/v1/messages` with model `claude-haiku-4-5-20251001`. Requires the `anthropic-dangerous-direct-browser-access: true` header for direct browser calls. Parses response from `data.content[0].text`.

**OpenRouter path** (`analyzeWithOpenRouter`): POSTs to `https://openrouter.ai/api/v1/chat/completions` (OpenAI-compatible). Model is user-configurable (7 options). Parses response from `data.choices[0].message.content`. Both AI paths use a `regex(/\{[\s\S]*\}/)` JSON extraction in case the model wraps JSON in prose.

**Header analysis** (`analyzeHeaders`): six checks against `{ from, replyTo, mailedBy, signedBy, security, date }`:

| Check | Weight |
|-------|--------|
| Mailed-by ↔ From domain alignment | 35 |
| DKIM Signed-by ↔ From domain alignment | 30 |
| No DKIM signature | 15 |
| Reply-To domain mismatch | 20 |
| No TLS encryption | 10 |
| Display name brand spoofing | 25 |
| Date forged into future | 15 |

MAX_DEMERITS = 135. `probability = 100 − (demerits / 135 × 100)`. `addedSpamScore = demerits / 135 × 30` (capped at 30 so headers can't override a clearly clean body).

### Content script data (`content.js`)

`extractGmail()` returns the full set:

```js
{ body, subject, sender, from, mailedBy, signedBy, security, date }
```

`extractOutlook()`, `extractYahooMail()`, `extractProtonMail()` return the base set only:

```js
{ body, subject, sender }
```

Gmail header selectors (`.aZo`, `.aZp`, `.g3`, `.gK`, etc.) are best-effort — absence is treated as empty string, not an error. The default result object initialises all eight keys to `''` so callers never see `undefined`.

### Settings / storage

All values stored in `chrome.storage.local` (device-local, not synced across profiles):

| Key | Type | Description |
|-----|------|-------------|
| `apiKey` | string | Anthropic API key (`sk-ant-…`) |
| `orKey` | string | OpenRouter API key (`sk-or-…`) |
| `orModel` | string | OpenRouter model slug (e.g. `anthropic/claude-haiku-4-5`) |
| `aiProvider` | `'anthropic'` \| `'openrouter'` | Preferred provider when both keys are set |

### Message passing

| Direction | Message | Response |
|-----------|---------|----------|
| `popup.js` → `content.js` | `{ action: 'extractEmail' }` | `{ body, subject, sender, from, mailedBy, signedBy, security, date }` |
| `popup.js` → `background.js` | `{ action: 'ping' }` | `{ status: 'ok' }` |

### PII masking (`maskPII`)

`maskPII(text)` is called in `runAnalysis()` on `subjectVal` and `bodyVal` **before** either value is passed to any external AI provider. The heuristic engine runs on-device and receives the original unmasked text.

`senderVal` and `headerData` are intentionally **not** masked — they contain technical spam signals (domain names, DKIM selectors, TLS flags) that must remain intact for accurate detection.

Patterns masked and their replacement tokens:

| Pattern | Token |
|---------|-------|
| Email addresses | `[EMAIL REDACTED]` |
| Phone numbers (formatted US/international) | `[PHONE REDACTED]` |
| SSN — `XXX-XX-XXXX` form only | `[SSN REDACTED]` |
| Payment card — 4×4, Amex 4-6-5, 16-digit run | `[CARD REDACTED]` |
| IPv4 addresses | `[IP REDACTED]` |
| Physical street addresses (number + street type) | `[ADDRESS REDACTED]` |
| Date of birth (labelled: "dob:", "born on:") | `[DOB REDACTED]` |
| Bank routing number (labelled) | `[ROUTING REDACTED]` |
| Bank account number (labelled) | `[ACCOUNT REDACTED]` |
| Passport number (labelled) | `[PASSPORT REDACTED]` |
| Driver's licence number (labelled) | `[DL REDACTED]` |
| National / health insurance ID (labelled) | `[ID REDACTED]` |

Unlabelled structured IDs (Medicare numbers, national IDs) are only matched when prefixed by a keyword (e.g. "Medicare ID:") to avoid false positives. Names are not masked — reliable name detection requires NLP that is out of scope for a client-side regex pass.

## Key constraints

- **No build tooling** — plain ES5-compatible JS; no bundler, no npm, no TypeScript.
- JSON from AI responses must be extracted with `/\{[\s\S]*\}/` because models sometimes add prose around JSON.
- `apexDomain()` extracts only the last two domain labels for alignment checks, so `mail.paypal.com` correctly aligns with `paypal.com`.
- DOM selectors in `content.js` target live webmail UIs that restructure without notice — expect to update them periodically.
- `addedSpamScore` is capped at 30 so header signals supplement but don't dominate content analysis.
- OpenRouter's API is OpenAI-compatible; do not use Anthropic response parsing (`content[0].text`) for it.

## Version history

| Version | Changes |
|---------|---------|
| 1.0.0 | Initial release — heuristic engine, Gmail/Outlook/Yahoo/Proton auto-extract, Anthropic Claude support |
| 1.1.0 | Email header analysis — Mailed-by, DKIM, Reply-To, TLS, brand spoof, date validity; Sender Authenticity panel in results |
| 1.2.0 | OpenRouter support — dual-provider settings UI, provider preference + fallback chain, 7 model options |
