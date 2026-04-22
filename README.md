# Spam Shield — Email Checker

A Manifest V3 browser extension for Chrome, Edge, and Brave that detects spam, phishing, and scam emails. Works directly inside Gmail, Outlook, Yahoo Mail, and Proton Mail — or paste any email content manually.

---

## Features

- **Auto-reads open emails** from Gmail, Outlook, Yahoo Mail, and Proton Mail — no copy-pasting required
- **Header authenticity analysis** — checks Mailed-by, DKIM Signed-by, Reply-To, TLS encryption, display-name brand spoofing, and email date validity to produce a Sender Authenticity probability score
- **Highlighted findings** — flags suspicious phrases with exact quotes and surrounding context
- **AI-powered analysis** via Anthropic Claude or OpenRouter (optional) — falls back to the built-in heuristic engine if no key is configured
- **Dual-provider support** — add one or both API keys; set a preferred provider with automatic fallback
- **Manual mode** — works on any page; paste the sender, subject, body, and header fields yourself
- **No data collection** — all analysis happens locally or via your own API key; nothing is sent to third-party servers except the AI provider you configure

---

## Installation

There is no published store listing. Load the extension directly from source:

1. Download or clone this repository
2. Open `chrome://extensions` (Chrome / Brave) or `edge://extensions` (Edge)
3. Enable **Developer mode** (toggle in the top-right)
4. Click **Load unpacked** and select the `spam-shield-extension/` folder
5. The Spam Shield icon appears in your toolbar — pin it for easy access

---

## Usage

### On a supported email page (Gmail, Outlook, Yahoo Mail, Proton Mail)

1. Open an email in your browser
2. Click the Spam Shield extension icon
3. The extension reads the email automatically and shows a preview
4. Click **Evaluate Email**
5. Results appear below — verdict, risk score, Sender Authenticity panel, and flagged sections

### On any other page (manual mode)

1. Click the Spam Shield extension icon
2. Paste the sender address, subject line, and email body
3. Optionally expand **Email Headers** and fill in header fields for a more thorough check
4. Click **Analyze Email**

### Reading results

| Verdict | Score | Meaning |
|---------|-------|---------|
| **SAFE** | 0 – 25 | No significant spam signals detected |
| **SUSPICIOUS** | 26 – 55 | Some indicators present — review carefully |
| **SPAM** | 56 – 100 | Strong spam / phishing / scam signals |

The **Sender Authenticity** panel shows domain-alignment checks for each header field with pass / fail / warn / skip indicators and a probability percentage.

Flagged sections list the specific phrases or patterns that triggered the score, with coloured highlights showing exactly where in the email they appear.

---

## AI Enhancement (optional)

Without an API key the extension uses its built-in heuristic rule engine — no setup required.

Adding an API key enables AI-powered analysis for more nuanced, context-aware verdicts.

### Anthropic

1. Get an API key at [console.anthropic.com](https://console.anthropic.com)
2. Keys start with `sk-ant-`
3. Uses **Claude Haiku** — fast and inexpensive

### OpenRouter

1. Get an API key at [openrouter.ai](https://openrouter.ai)
2. Keys start with `sk-or-`
3. Choose from 7 available models in the settings:

| Model | Characteristics |
|-------|----------------|
| Claude Haiku 4.5 | Fast, cheap |
| Claude Sonnet 4.5 | Balanced |
| GPT-4o Mini | Fast, cheap |
| GPT-4o | Powerful |
| Gemini Flash 1.5 | Fast |
| Gemini Pro 1.5 | Balanced |
| Llama 3.3 70B | Open source |

### Adding keys

1. Click the ⚙ settings icon in the extension header
2. Enter your Anthropic key, your OpenRouter key, or both
3. If both are set, choose your preferred provider — the other is used as fallback
4. Click **Save Settings**

The active provider is shown in a green bar at the top of the settings page.

---

## Supported email clients

| Client | Auto-extract | Header fields auto-filled |
|--------|-------------|--------------------------|
| Gmail | Yes | From, Mailed-by, Signed-by, Security, Date |
| Outlook (live / office / office365) | Yes | Sender only |
| Yahoo Mail | Yes | Sender only |
| Proton Mail | Yes | Sender only |

Header fields not extracted automatically can be filled in manually by expanding the **Email Headers** panel before clicking Evaluate.

---

## Privacy & data protection

### What leaves your device

When an AI provider key is configured, the email's **sender address**, **masked subject**, and **masked body** are sent to your chosen provider (Anthropic or OpenRouter) over HTTPS. No data is ever sent to any other server.

When no key is configured, analysis runs entirely on-device using the built-in heuristic engine — nothing leaves your browser.

### PII masking before AI calls

Before the subject line or email body is sent to an AI provider, the extension automatically redacts recognised personal and sensitive data:

| What gets masked | Replaced with |
|-----------------|---------------|
| Email addresses | `[EMAIL REDACTED]` |
| Phone numbers | `[PHONE REDACTED]` |
| Social Security Numbers (XXX-XX-XXXX) | `[SSN REDACTED]` |
| Payment card numbers | `[CARD REDACTED]` |
| IP addresses | `[IP REDACTED]` |
| Physical street addresses | `[ADDRESS REDACTED]` |
| Date of birth (when labelled) | `[DOB REDACTED]` |
| Bank routing / account numbers (when labelled) | `[ROUTING REDACTED]` / `[ACCOUNT REDACTED]` |
| Passport numbers (when labelled) | `[PASSPORT REDACTED]` |
| Driver's licence numbers (when labelled) | `[DL REDACTED]` |
| National / health insurance IDs (when labelled) | `[ID REDACTED]` |

The sender address and email header fields (Mailed-by, DKIM, TLS etc.) are **not** masked — they are technical spam signals that must remain intact for accurate detection.

The built-in heuristic engine processes the original unmasked text on-device; no masking is needed because no data leaves the browser.

### Other privacy points

- No analytics, telemetry, or remote logging of any kind
- API keys are stored in `chrome.storage.local` — device-local, not synced across browser profiles
- The extension only activates on the four supported webmail domains and any page you manually open the popup on

---

## File structure

```
spam-shield-extension/
├── manifest.json          # Extension manifest (MV3)
├── background.js          # Service worker (keep-alive ping)
├── content.js             # DOM scrapers for each webmail client
├── popup.html             # Extension popup UI
├── popup.js               # UI logic, analysis engine, AI API calls
├── popup.css              # All styles
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   ├── icon128.png
│   ├── generate-icons.js       # Node.js icon generator (zero deps)
│   └── generate_icons.html     # Browser canvas icon generator
├── CLAUDE.md              # Developer guidance for Claude Code
└── README.md              # This file
```

---

## Development

No build step — edit source files and reload the extension.

After any change:

1. Go to `chrome://extensions`
2. Click the reload icon on the Spam Shield card
3. Re-open the popup

See `CLAUDE.md` for architecture details, analysis pipeline internals, and key constraints.

---

## Version history

| Version | What changed |
|---------|-------------|
| 1.2.0 | OpenRouter support — dual-provider settings, provider preference + fallback, 7 model choices |
| 1.1.0 | Email header analysis — Sender Authenticity panel with Mailed-by, DKIM, Reply-To, TLS, brand spoof, date checks |
| 1.0.0 | Initial release — heuristic engine, Gmail/Outlook/Yahoo/Proton auto-extract, Anthropic Claude support |
