'use strict';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Search `text` for `pattern`. If found, return the matched string plus
 * up to `ctx` characters of surrounding context, split into three parts
 * so the UI can highlight just the matched portion.
 */
function extractSnippet(text, pattern, ctx = 60) {
  // Clone pattern without flags that might cause lastIndex issues
  const re = new RegExp(pattern.source, 'i');
  const m = re.exec(text);
  if (!m) return null;

  const matchStart = m.index;
  const matchEnd   = m.index + m[0].length;
  const start      = Math.max(0, matchStart - ctx);
  const end        = Math.min(text.length, matchEnd + ctx);

  // Collapse whitespace/newlines in context fragments
  const clean = s => s.replace(/\s+/g, ' ');

  return {
    before:  (start > 0 ? '…' : '') + clean(text.slice(start, matchStart)),
    matched: clean(m[0]),
    after:   clean(text.slice(matchEnd, end)) + (end < text.length ? '…' : '')
  };
}

// ─── Spam Detection Engine ────────────────────────────────────────────────────

const SPAM_RULES = {
  critical: [
    { pattern: /you('ve| have) won\b/i,                                     label: 'Claims you won a prize',                    severity: 'high' },
    { pattern: /congratulations.*you.*won/i,                                 label: 'Suspicious congratulations message',         severity: 'high' },
    { pattern: /\$\d[\d,]+\s*(million|billion|thousand)/i,                  label: 'Unrealistic money amount',                  severity: 'high' },
    { pattern: /nigerian\s+prince/i,                                         label: 'Classic Nigerian prince scam',               severity: 'high' },
    { pattern: /inheritance\s+(fund|transfer|claim)/i,                       label: 'Inheritance scam pattern',                  severity: 'high' },
    { pattern: /transfer.*funds.*account/i,                                  label: 'Suspicious fund transfer request',           severity: 'high' },
    { pattern: /your\s+account\s+(has been\s+)?(suspended|disabled|locked|compromised)/i, label: 'Account suspension threat',  severity: 'high' },
    { pattern: /verify\s+your\s+(account|identity|information)\s+(immediately|now|urgently)/i, label: 'Urgent verification demand', severity: 'high' },
    { pattern: /confirm\s+your\s+(password|credentials|banking|payment)/i,  label: 'Credential harvesting attempt',             severity: 'high' },
    { pattern: /claim\s+(your\s+)?(prize|reward|gift|winnings)/i,           label: 'Prize claim prompt',                        severity: 'high' },
    { pattern: /lottery\s+(winner|won|winning)/i,                            label: 'Lottery scam pattern',                      severity: 'high' },
    { pattern: /wire\s+(transfer|money)\s+to/i,                              label: 'Wire transfer request',                     severity: 'high' },
    { pattern: /send\s+(money|cash|bitcoin|crypto|gift\s+card)/i,           label: 'Suspicious payment request',                severity: 'high' },
    { pattern: /gift\s+card\s+(code|number|pin)/i,                          label: 'Gift card scam pattern',                    severity: 'high' },
    { pattern: /bitcoin\s+(wallet|address|payment)/i,                        label: 'Cryptocurrency payment request',            severity: 'high' },
    { pattern: /IRS\s+(notice|warning|penalty|refund)/i,                     label: 'IRS impersonation attempt',                 severity: 'high' },
    { pattern: /social\s+security\s+(number|card|suspended)/i,               label: 'SSN / identity scam',                       severity: 'high' },
  ],
  high: [
    { pattern: /act\s+now\b/i,                                               label: 'Urgency tactic: "Act now"',                 severity: 'medium' },
    { pattern: /limited\s+time\s+offer/i,                                    label: 'Artificial urgency: limited time offer',    severity: 'medium' },
    { pattern: /expires?\s+in\s+\d+\s+hours?/i,                             label: 'Countdown pressure tactic',                 severity: 'medium' },
    { pattern: /respond\s+(immediately|urgently|asap|right\s+away)/i,       label: 'Urgency pressure tactic',                   severity: 'medium' },
    { pattern: /make\s+money\s+(fast|quickly|online|from\s+home)/i,         label: 'Get-rich-quick scheme',                     severity: 'medium' },
    { pattern: /earn\s+\$[\d,]+\s+(per day|a day|daily|per week|weekly)/i, label: 'Unrealistic earnings claim',                severity: 'medium' },
    { pattern: /work\s+from\s+home.*earn/i,                                  label: 'Work-from-home money scheme',               severity: 'medium' },
    { pattern: /100%\s+(free|guaranteed|risk.?free)/i,                       label: 'Unrealistic guarantee',                     severity: 'medium' },
    { pattern: /no\s+credit\s+card\s+required/i,                             label: 'No-cost hook',                              severity: 'medium' },
    { pattern: /click\s+here\s+(to|now)\s+(verify|confirm|update|claim)/i, label: 'Suspicious click prompt',                   severity: 'medium' },
    { pattern: /your\s+password\s+(has\s+)?(expired|will\s+expire)/i,      label: 'Password expiry phishing',                  severity: 'medium' },
    { pattern: /unusual\s+(sign.?in|activity|login)\s+(detected|attempt)/i,label: 'Fake security alert',                       severity: 'medium' },
    { pattern: /we\s+(detected|noticed)\s+suspicious\s+activity/i,          label: 'Fake suspicious activity alert',            severity: 'medium' },
    { pattern: /update\s+your\s+(payment|billing|credit\s+card)\s+info/i,  label: 'Fake payment update request',               severity: 'medium' },
    { pattern: /your\s+(package|shipment|parcel)\s+(is\s+)?(held|pending|awaiting\s+payment)/i, label: 'Fake delivery scam', severity: 'medium' },
  ],
  medium: [
    { pattern: /dear\s+(friend|member|customer|valued\s+customer|beneficiary)/i, label: 'Generic impersonal greeting',          severity: 'low' },
    { pattern: /to\s+whom\s+it\s+may\s+concern/i,                           label: 'Generic impersonal salutation',             severity: 'low' },
    { pattern: /special\s+(promotion|offer|deal|discount)/i,                 label: 'Promotional language',                     severity: 'low' },
    { pattern: /free\s+(gift|offer|trial|download|access)/i,                label: '"Free" hook',                              severity: 'low' },
    { pattern: /buy\s+now|order\s+now|shop\s+now/i,                         label: 'Hard sales pressure',                      severity: 'low' },
    { pattern: /unsubscribe\b/i,                                             label: 'Unsubscribe link present',                 severity: 'low' },
    { pattern: /opt\s+out\b/i,                                               label: 'Opt-out link present',                     severity: 'low' },
    { pattern: /confidential(ity)?\s+(notice|disclaimer)/i,                  label: 'Suspicious confidentiality notice',        severity: 'low' },
    { pattern: /kindly\s+(send|provide|transfer|assist)/i,                   label: 'Suspicious "kindly" phrasing',             severity: 'low' },
    { pattern: /\bspam\b.*\b(not|free)\b/i,                                 label: 'Self-certifying "not spam" claim',         severity: 'low' },
  ]
};

const WEIGHTS = { critical: 15, high: 8, medium: 3 };

/**
 * Core analysis. Returns { score, verdict, findings[] }
 * Each finding: { label, severity, source, snippet: {before, matched, after} | null }
 */
function analyzeEmail(senderVal, subjectVal, bodyVal) {
  const findings = [];
  let score = 0;

  // Named sections — we search each separately so we can label where the match was found
  const sections = [
    { name: 'Sender',  text: senderVal  || '' },
    { name: 'Subject', text: subjectVal || '' },
    { name: 'Body',    text: bodyVal    || '' },
  ];

  // ── Pattern rules ────────────────────────────────────────────────────────────
  for (const [category, rules] of Object.entries(SPAM_RULES)) {
    for (const rule of rules) {
      let snippet = null;
      let matchedSection = null;

      for (const sec of sections) {
        if (!sec.text) continue;
        const s = extractSnippet(sec.text, rule.pattern);
        if (s) { snippet = s; matchedSection = sec.name; break; }
      }

      if (snippet) {
        score += WEIGHTS[category];
        findings.push({ label: rule.label, severity: rule.severity, source: matchedSection, snippet });
      }
    }
  }

  // ── Structural checks ────────────────────────────────────────────────────────

  // ALL-CAPS subject
  if (subjectVal) {
    const capsRatio = (subjectVal.match(/[A-Z]/g) || []).length / subjectVal.length;
    if (capsRatio > 0.6 && subjectVal.length > 5) {
      score += 8;
      findings.push({ label: 'Subject line is mostly UPPERCASE', severity: 'medium', source: 'Subject',
        snippet: { before: '', matched: subjectVal, after: '' } });
    }
    const excl = (subjectVal.match(/!/g) || []).length;
    if (excl >= 2) {
      score += 5;
      findings.push({ label: `Subject line has ${excl} exclamation marks`, severity: 'medium', source: 'Subject',
        snippet: { before: '', matched: subjectVal, after: '' } });
    }
  }

  // Excessive caps in body
  if (bodyVal) {
    const words = bodyVal.split(/\s+/).filter(w => w.length > 3);
    if (words.length > 0) {
      const capsWords = words.filter(w => w === w.toUpperCase() && /[A-Z]/.test(w));
      if (capsWords.length / words.length > 0.25) {
        score += 6;
        const sample = capsWords.slice(0, 4).join(' ');
        findings.push({ label: 'Excessive uppercase text in body', severity: 'medium', source: 'Body',
          snippet: { before: 'e.g. ', matched: sample, after: capsWords.length > 4 ? ' …' : '' } });
      }
    }

    // Excessive exclamation marks
    const bodyExcl = (bodyVal.match(/!/g) || []).length;
    if (bodyExcl > 4) {
      score += 4;
      findings.push({ label: `${bodyExcl} exclamation marks in body`, severity: 'low', source: 'Body', snippet: null });
    }

    // Suspicious / shortened URLs
    const urls = bodyVal.match(/https?:\/\/[^\s<>"]+/g) || [];
    const badUrls = urls.filter(u =>
      /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(u) ||
      /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|rb\.gy|cutt\.ly/i.test(u) ||
      /[a-z0-9]{25,}\.(com|net|org|xyz|top|click|live|online)/i.test(u)
    );
    if (badUrls.length > 0) {
      score += 12;
      findings.push({ label: `${badUrls.length} suspicious URL(s) — IP-based or shortened`, severity: 'high',
        source: 'Body', snippet: { before: '', matched: badUrls[0], after: badUrls.length > 1 ? ` (+${badUrls.length - 1} more)` : '' } });
    }

    // Very short body with urgent subject
    if (bodyVal.trim().length < 50 && subjectVal && /urgent|immediately|verify|confirm/i.test(subjectVal)) {
      score += 5;
      findings.push({ label: 'Tiny body + urgent subject — common phishing pattern', severity: 'medium', source: 'Subject',
        snippet: { before: '', matched: subjectVal, after: '' } });
    }
  }

  // Sender domain spoofing checks
  if (senderVal) {
    const sl = senderVal.toLowerCase();
    const knownBrands = {
      paypal: 'paypal.com', amazon: 'amazon.com', apple: 'apple.com',
      google: 'google.com', microsoft: 'microsoft.com', netflix: 'netflix.com',
      fedex: 'fedex.com', ups: 'ups.com', dhl: 'dhl.com'
    };
    for (const [brand, domain] of Object.entries(knownBrands)) {
      if (sl.includes(brand) && !sl.includes(domain)) {
        score += 15;
        findings.push({ label: `"${brand}" in sender name but domain doesn't match — likely spoofed`,
          severity: 'high', source: 'Sender', snippet: { before: '', matched: senderVal, after: '' } });
        break;
      }
    }

    // Authority claim from free email
    const fullText = [senderVal, subjectVal, bodyVal].join(' ');
    if (/@(gmail|yahoo|hotmail|outlook|aol)\.com/i.test(sl) &&
        /irs|bank|paypal|amazon|microsoft|government|official/i.test(fullText)) {
      score += 10;
      findings.push({ label: 'Authority entity sending from a free email address',
        severity: 'high', source: 'Sender', snippet: { before: '', matched: senderVal, after: '' } });
    }
  }

  score = Math.min(100, score);

  let verdict;
  if      (score <= 25) verdict = 'safe';
  else if (score <= 55) verdict = 'suspicious';
  else                  verdict = 'spam';

  if (findings.length === 0) {
    findings.push({ label: 'No spam indicators detected — email looks clean', severity: 'clean', source: null, snippet: null });
  }

  return { score, verdict, findings };
}

// ─── Claude AI Analysis ───────────────────────────────────────────────────────

async function analyzeWithClaude(apiKey, senderVal, subjectVal, bodyVal) {
  const prompt = `You are a spam detection expert. Analyze the following email and respond ONLY with a JSON object.

Sender: ${senderVal || '(not provided)'}
Subject: ${subjectVal || '(not provided)'}
Body:
${bodyVal || '(not provided)'}

JSON format:
{
  "verdict": "spam" | "suspicious" | "safe",
  "score": <0-100>,
  "findings": [
    {
      "label": "<specific reason>",
      "severity": "high" | "medium" | "low" | "clean",
      "source": "Sender" | "Subject" | "Body" | null,
      "quote": "<exact short phrase from the email that is suspicious, or null>"
    }
  ]
}`;

  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true'
    },
    body: JSON.stringify({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 768,
      messages: [{ role: 'user', content: prompt }]
    })
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `API error ${res.status}`);
  }

  const data = await res.json();
  const text = data.content[0].text.trim();
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error('Invalid response from Claude');

  const parsed = JSON.parse(jsonMatch[0]);

  // Normalise Claude findings to match our snippet format
  parsed.findings = (parsed.findings || []).map(f => ({
    label:    f.label,
    severity: f.severity,
    source:   f.source || null,
    snippet:  f.quote ? { before: '', matched: f.quote, after: '' } : null
  }));

  return parsed;
}

// ─── UI helpers ───────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);

function setLoadingBtn(btn, loading, originalHTML) {
  if (loading) {
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner"></div> Analyzing…';
  } else {
    btn.disabled = false;
    btn.innerHTML = originalHTML;
  }
}

// ─── Render Results ───────────────────────────────────────────────────────────

function renderResults({ score, verdict, findings }) {
  const verdictBadge  = $('verdictBadge');
  const verdictIcon   = $('verdictIcon');
  const verdictLabel  = $('verdictLabel');
  const scoreValue    = $('scoreValue');
  const scoreBarFill  = $('scoreBarFill');
  const findingsEl    = $('findings');
  const findingsHdr   = $('findingsHeader');

  const config = {
    safe:       { icon: '✓', label: 'SAFE',       cls: 'safe' },
    suspicious: { icon: '⚠',  label: 'SUSPICIOUS', cls: 'suspicious' },
    spam:       { icon: '✕', label: 'SPAM',        cls: 'spam' }
  };
  const c = config[verdict] || config.safe;

  verdictBadge.className  = `verdict-badge ${c.cls}`;
  verdictIcon.textContent  = c.icon;
  verdictLabel.textContent = c.label;
  scoreValue.textContent   = score;

  setTimeout(() => { scoreBarFill.style.width = `${score}%`; }, 50);

  // Show "Flagged sections" header only when there are real findings
  const hasRealFindings = findings.some(f => f.severity !== 'clean');
  findingsHdr.style.display = hasRealFindings ? 'flex' : 'none';

  // Render findings
  findingsEl.innerHTML = '';
  const severityIcons = { high: '🔴', medium: '🟡', low: '🔵', clean: '✅' };

  for (const f of findings) {
    const itemClass = f.severity === 'clean' ? 'low' : f.severity;
    const div = document.createElement('div');
    div.className = `finding-item ${itemClass}`;

    // Header row: icon + label + source badge
    const sourceBadge = f.source
      ? `<span class="finding-source">${escapeHtml(f.source)}</span>`
      : '';

    let snippetHtml = '';
    if (f.snippet) {
      const b = escapeHtml(f.snippet.before);
      const m = escapeHtml(f.snippet.matched);
      const a = escapeHtml(f.snippet.after);
      snippetHtml = `
        <div class="match-quote">
          <span class="match-ctx">${b}</span><span class="match-highlight">${m}</span><span class="match-ctx">${a}</span>
        </div>`;
    }

    div.innerHTML = `
      <div class="finding-header">
        <span class="finding-icon">${severityIcons[f.severity] || '•'}</span>
        <span class="finding-text">${escapeHtml(f.label)}</span>
        ${sourceBadge}
      </div>
      ${snippetHtml}`;

    findingsEl.appendChild(div);
  }

  $('results').style.display = 'block';
  $('results').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ─── Core analysis runner (shared by both modes) ──────────────────────────────

async function runAnalysis(senderVal, subjectVal, bodyVal, triggerBtn, originalBtnHTML) {
  setLoadingBtn(triggerBtn, true);
  $('results').style.display = 'none';

  try {
    const stored = await new Promise(res => chrome.storage.local.get(['apiKey'], res));
    const key    = stored.apiKey;

    let result;
    if (key && key.startsWith('sk-ant-')) {
      try {
        result = await analyzeWithClaude(key, senderVal, subjectVal, bodyVal);
      } catch (e) {
        console.warn('Claude API error, falling back:', e.message);
        result = analyzeEmail(senderVal, subjectVal, bodyVal);
        result.findings.unshift({
          label: `AI unavailable: ${e.message} — showing heuristic results`,
          severity: 'low', source: null, snippet: null
        });
      }
    } else {
      result = analyzeEmail(senderVal, subjectVal, bodyVal);
    }

    renderResults(result);
  } catch (e) {
    console.error(e);
    alert('Analysis failed: ' + e.message);
  } finally {
    setLoadingBtn(triggerBtn, false, originalBtnHTML);
  }
}

// ─── Email Mode ───────────────────────────────────────────────────────────────

// Stored extracted email data for evaluate button
let extractedEmail = { sender: '', subject: '', body: '' };

function showEmailMode() {
  $('emailModePanel').style.display  = 'block';
  $('manualModePanel').style.display = 'none';
}

function showManualMode() {
  $('emailModePanel').style.display  = 'none';
  $('manualModePanel').style.display = 'block';
}

function setEmailStatus(state, text) {
  const bar = $('emailStatusBar');
  bar.className = `email-status-bar ${state}`;
  bar.innerHTML = state === 'scanning'
    ? `<div class="spinner-sm"></div><span>${escapeHtml(text)}</span>`
    : `<span class="status-dot ${state}"></span><span>${escapeHtml(text)}</span>`;
}

function autoExtractEmail(tabId) {
  setEmailStatus('scanning', 'Reading email from page…');
  $('emailPreviewCard').style.display = 'none';
  $('evaluateRow').style.display      = 'none';

  chrome.tabs.sendMessage(tabId, { action: 'extractEmail' }, response => {
    if (chrome.runtime.lastError || !response || !response.body) {
      setEmailStatus('warn', 'No email open — please open an email first.');
      $('evaluateRow').style.display = 'block'; // show manual fallback link
      return;
    }

    extractedEmail = response;

    // Update preview card
    $('previewSender').textContent  = response.sender  || '(sender not detected)';
    $('previewSubject').textContent = response.subject || '(subject not detected)';
    const words = response.body.trim().split(/\s+/).length;
    $('previewMeta').textContent    = `${words.toLocaleString()} words extracted`;

    setEmailStatus('ready', 'Email loaded — ready to evaluate');
    $('emailPreviewCard').style.display = 'block';
    $('evaluateRow').style.display      = 'block';
  });
}

// Evaluate button (email mode)
const evaluateBtnHTML = `
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
  </svg>
  Evaluate Email`;

$('evaluateBtn').addEventListener('click', () => {
  if (!extractedEmail.body) {
    setEmailStatus('warn', 'No email content — please open an email first.');
    return;
  }
  runAnalysis(
    extractedEmail.sender,
    extractedEmail.subject,
    extractedEmail.body,
    $('evaluateBtn'),
    evaluateBtnHTML
  );
});

$('switchToManualBtn').addEventListener('click', () => {
  showManualMode();
  if (extractedEmail.sender)  $('sender').value       = extractedEmail.sender;
  if (extractedEmail.subject) $('subject').value      = extractedEmail.subject;
  if (extractedEmail.body)    $('emailContent').value = extractedEmail.body;
  const len = ($('emailContent').value || '').length;
  $('charCount').textContent = `${len.toLocaleString()} characters`;
});

// ─── Manual Mode ──────────────────────────────────────────────────────────────

$('emailContent').addEventListener('input', () => {
  const len = $('emailContent').value.length;
  $('charCount').textContent = `${len.toLocaleString()} character${len !== 1 ? 's' : ''}`;
});

$('clearBtn').addEventListener('click', () => {
  $('emailContent').value = '';
  $('sender').value       = '';
  $('subject').value      = '';
  $('charCount').textContent = '0 characters';
  $('results').style.display = 'none';
});

const analyzeBtnHTML = `
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
  </svg>
  Analyze Email`;

$('analyzeBtn').addEventListener('click', () => {
  const bodyText = $('emailContent').value.trim();
  if (!bodyText) {
    $('emailContent').style.borderColor = '#ef4444';
    setTimeout(() => { $('emailContent').style.borderColor = ''; }, 2000);
    $('emailContent').focus();
    return;
  }
  runAnalysis(
    $('sender').value.trim(),
    $('subject').value.trim(),
    bodyText,
    $('analyzeBtn'),
    analyzeBtnHTML
  );
});

// ─── Shared: "Check another" button ──────────────────────────────────────────

$('analyzeAgainBtn').addEventListener('click', () => {
  $('results').style.display = 'none';
  // If we're in email mode, re-extract; otherwise just clear
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const url = tabs[0]?.url || '';
    if (/mail\.google\.com|outlook\.|office\.com|mail\.yahoo\.com|proton\.me/.test(url)) {
      showEmailMode();
      autoExtractEmail(tabs[0].id);
    } else {
      showManualMode();
      $('emailContent').value = '';
      $('sender').value       = '';
      $('subject').value      = '';
      $('charCount').textContent = '0 characters';
    }
  });
});

// ─── Settings ─────────────────────────────────────────────────────────────────

$('settingsBtn').addEventListener('click', () => {
  $('mainView').style.display    = 'none';
  $('settingsView').style.display = 'block';
  chrome.storage.local.get(['apiKey'], ({ apiKey }) => {
    if (apiKey) $('apiKey').value = apiKey;
  });
});

$('backBtn').addEventListener('click', () => {
  $('settingsView').style.display = 'none';
  $('mainView').style.display     = 'block';
});

$('toggleKeyBtn').addEventListener('click', () => {
  const inp = $('apiKey');
  inp.type = inp.type === 'password' ? 'text' : 'password';
});

$('saveSettingsBtn').addEventListener('click', () => {
  const key = $('apiKey').value.trim();
  chrome.storage.local.set({ apiKey: key }, () => {
    const st = $('apiStatus');
    st.textContent = key ? '✓ API key saved — AI analysis enabled.' : 'API key cleared.';
    st.className   = 'api-status success';
    setTimeout(() => { st.textContent = ''; st.className = 'api-status'; }, 3000);
  });
});

// ─── Init ─────────────────────────────────────────────────────────────────────

chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
  const url = tabs[0]?.url || '';
  const isEmailPage = /mail\.google\.com|outlook\.(live|office)\.com|office365\.com|mail\.yahoo\.com|proton\.me|mail\.proton\.me/.test(url);

  if (isEmailPage) {
    showEmailMode();
    autoExtractEmail(tabs[0].id);
  } else {
    showManualMode();
  }
});
