'use strict';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* LOCAL EVALUATION DISABLED — AI call is required
function extractSnippet(text, pattern, ctx = 60) {
  const re = new RegExp(pattern.source, 'i');
  const m = re.exec(text);
  if (!m) return null;
  const matchStart = m.index;
  const matchEnd   = m.index + m[0].length;
  const start      = Math.max(0, matchStart - ctx);
  const end        = Math.min(text.length, matchEnd + ctx);
  const clean = s => s.replace(/\s+/g, ' ');
  return {
    before:  (start > 0 ? '…' : '') + clean(text.slice(start, matchStart)),
    matched: clean(m[0]),
    after:   clean(text.slice(matchEnd, end)) + (end < text.length ? '…' : '')
  };
}
*/

// ─── PII Masking ──────────────────────────────────────────────────────────────
//
// Applied to subject and body BEFORE sending to any external AI provider.
// The heuristic engine runs entirely on-device and is not affected.
// senderVal and headerData are not masked — they contain technical spam signals
// (domain names, DKIM selectors, TLS flags) that are needed for accurate detection.

function maskPII(text) {
  if (!text) return text;
  let out = text;

  // ── Email addresses ────────────────────────────────────────────────────────
  // Catches user@domain.tld in any position; run first so later patterns
  // don't partially overlap with the @ character.
  out = out.replace(
    /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    '[EMAIL REDACTED]'
  );

  // ── Phone numbers ──────────────────────────────────────────────────────────
  // Formatted: (555) 555-1234 / 555-555-1234 / +1 555.555.1234
  out = out.replace(
    /(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}/g,
    '[PHONE REDACTED]'
  );

  // ── Social Security Numbers ────────────────────────────────────────────────
  // Only the canonical dashed form (XXX-XX-XXXX) to avoid false positives
  out = out.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN REDACTED]');

  // ── Payment card numbers ───────────────────────────────────────────────────
  // 4×4 groups with space or dash (Visa / Mastercard / Discover)
  out = out.replace(/\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b/g, '[CARD REDACTED]');
  // Amex: 4-6-5
  out = out.replace(/\b\d{4}[\s\-]\d{6}[\s\-]\d{5}\b/g, '[CARD REDACTED]');
  // 16-digit run with no separators
  out = out.replace(/\b\d{16}\b/g, '[CARD REDACTED]');

  // ── IPv4 addresses ─────────────────────────────────────────────────────────
  out = out.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP REDACTED]');

  // ── Physical street addresses ──────────────────────────────────────────────
  // Matches "123 Main Street", "45 Oak Ave.", "7 Elm Blvd" etc.
  out = out.replace(
    /\b\d{1,5}\s+[A-Za-z]+(?:\s+[A-Za-z]+)?\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir|Trail|Trl)\.?\b/gi,
    '[ADDRESS REDACTED]'
  );

  // ── Date of birth (labelled only) ──────────────────────────────────────────
  out = out.replace(
    /\b(?:dob|date of birth|born(?:\s+on)?)[:\s]+[^\n,;]{1,40}/gi,
    '[DOB REDACTED]'
  );

  // ── Bank routing number (labelled) ────────────────────────────────────────
  out = out.replace(
    /\b(?:routing|aba)(?:\s+(?:number|no|#))?[:\s#]+\d{9}\b/gi,
    '[ROUTING REDACTED]'
  );

  // ── Bank account number (labelled) ────────────────────────────────────────
  out = out.replace(
    /\b(?:account|acct)(?:\s+(?:number|no|#))?[:\s#]+\d{6,17}\b/gi,
    '[ACCOUNT REDACTED]'
  );

  // ── Passport number (labelled) ────────────────────────────────────────────
  out = out.replace(
    /\bpassport(?:\s+(?:number|no|#))?[:\s#]+[A-Z0-9]{6,9}\b/gi,
    '[PASSPORT REDACTED]'
  );

  // ── Driver's licence number (labelled) ────────────────────────────────────
  out = out.replace(
    /\b(?:driver'?s?\s+)?(?:license|licence|dl|dlno)(?:\s+(?:number|no|#))?[:\s#]+[A-Z0-9]{5,15}\b/gi,
    '[DL REDACTED]'
  );

  // ── National / health insurance ID (labelled) ─────────────────────────────
  out = out.replace(
    /\b(?:national\s+id|medicare|medicaid|insurance\s+(?:id|number|no))(?:\s+(?:number|no|#))?[:\s#]+[A-Z0-9]{5,20}\b/gi,
    '[ID REDACTED]'
  );

  return out;
}

// ─── Spam Detection Engine (disabled — AI call required) ─────────────────────
/*
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

// Core analysis. Returns { score, verdict, findings[] }
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
*/

// ─── Header Authenticity Analysis ────────────────────────────────────────────

/** Extract the apex domain (last two labels) for alignment comparisons. */
function apexDomain(str) {
  if (!str) return '';
  // Strip angle-bracket email syntax: "Name <user@domain.com>" → "domain.com"
  const angle = str.match(/<([^>]+)>/);
  const addr  = angle ? angle[1] : str;
  const at    = addr.lastIndexOf('@');
  const dom   = (at >= 0 ? addr.slice(at + 1) : addr).toLowerCase().trim();
  // Remove "via " prefix Gmail sometimes prepends
  const clean = dom.replace(/^via\s+/i, '').trim();
  const parts = clean.split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : clean;
}

/** Returns true when two domain strings share the same registrable domain. */
function domainsAlign(a, b) {
  if (!a || !b) return false;
  return apexDomain(a) === apexDomain(b);
}

/**
 * Analyse header fields for sender authenticity signals.
 * @param {Object} h  { from, replyTo, mailedBy, signedBy, security, date }
 * @returns {{ checks, probability, addedSpamScore }}
 */
function analyzeHeaders(h) {
  h = h || {};
  const from     = (h.from     || '').trim();
  const replyTo  = (h.replyTo  || '').trim();
  const mailedBy = (h.mailedBy || '').trim().replace(/^via\s+/i, '');
  const signedBy = (h.signedBy || '').trim();
  const security = (h.security || '').trim();
  const dateStr  = (h.date     || '').trim();

  const fromDomain   = apexDomain(from);
  // Display name = text before the first '<'
  const displayName  = (from.match(/^([^<]+)</) || [])[1] || '';

  const checks  = [];
  let demerits  = 0;
  let hasData   = false;

  // ── 1. Mailed-by ↔ From domain (weight 35) ────────────────────────────────
  if (mailedBy && fromDomain) {
    hasData = true;
    if (domainsAlign(mailedBy, fromDomain)) {
      checks.push({ label: 'Mailed-by matches From domain',
        detail: `${apexDomain(mailedBy)} ↔ ${fromDomain}`, status: 'pass' });
    } else {
      demerits += 35;
      checks.push({ label: 'Mailed-by does NOT match From domain — likely spoofed',
        detail: `Mailed-by: ${mailedBy}  ≠  From: ${fromDomain}`, status: 'fail' });
    }
  } else if (mailedBy || fromDomain) {
    hasData = true;
    checks.push({ label: 'Mailed-by could not be fully compared',
      detail: mailedBy ? `Mailed-by: ${mailedBy}` : 'From domain not detected', status: 'skip' });
  }

  // ── 2. DKIM Signed-by ↔ From domain (weight 30) ───────────────────────────
  if (signedBy && fromDomain) {
    hasData = true;
    if (domainsAlign(signedBy, fromDomain)) {
      checks.push({ label: 'DKIM signature matches From domain',
        detail: `Signed-by: ${signedBy}`, status: 'pass' });
    } else {
      demerits += 30;
      checks.push({ label: 'DKIM signature domain mismatch',
        detail: `Signed-by: ${signedBy}  ≠  From: ${fromDomain}`, status: 'fail' });
    }
  } else if (fromDomain) {
    hasData = true;
    if (!signedBy) {
      demerits += 15;
      checks.push({ label: 'No DKIM signature found',
        detail: 'Cannot cryptographically verify the sender', status: 'warn' });
    }
  }

  // ── 3. Reply-To ↔ From domain (weight 20) ─────────────────────────────────
  if (replyTo && fromDomain) {
    hasData = true;
    const rtDomain = apexDomain(replyTo);
    if (rtDomain && !domainsAlign(rtDomain, fromDomain)) {
      demerits += 20;
      checks.push({ label: 'Reply-To redirects replies to a different domain',
        detail: `Replies → ${rtDomain}  ≠  From: ${fromDomain}`, status: 'fail' });
    } else {
      checks.push({ label: 'Reply-To aligns with sender domain',
        detail: `Replies stay within ${fromDomain}`, status: 'pass' });
    }
  }

  // ── 4. TLS encryption (weight 10) ─────────────────────────────────────────
  if (security) {
    hasData = true;
    if (/tls/i.test(security)) {
      checks.push({ label: 'TLS encryption present',
        detail: security, status: 'pass' });
    } else {
      demerits += 10;
      checks.push({ label: 'No TLS encryption detected',
        detail: `Security: ${security}`, status: 'warn' });
    }
  }

  // ── 5. Display name brand spoofing (weight 25) ────────────────────────────
  const KNOWN_BRANDS = {
    paypal: 'paypal.com', amazon: 'amazon.com', apple: 'apple.com',
    google: 'google.com', microsoft: 'microsoft.com', netflix: 'netflix.com',
    fedex: 'fedex.com', ups: 'ups.com', dhl: 'dhl.com', usps: 'usps.com',
    chase: 'chase.com', wellsfargo: 'wellsfargo.com',
    bankofamerica: 'bankofamerica.com', citibank: 'citi.com',
    instagram: 'instagram.com', facebook: 'meta.com', twitter: 'twitter.com'
  };
  if (displayName && fromDomain) {
    hasData = true;
    const nameLower = displayName.toLowerCase();
    let spoofFound = false;
    for (const [brand, legitDomain] of Object.entries(KNOWN_BRANDS)) {
      if (nameLower.includes(brand) && !domainsAlign(fromDomain, legitDomain)) {
        demerits += 25;
        checks.push({ label: `Display name impersonates "${brand}"`,
          detail: `Name: "${displayName.trim()}" but domain is ${fromDomain}`, status: 'fail' });
        spoofFound = true;
        break;
      }
    }
    if (!spoofFound) {
      checks.push({ label: 'No brand impersonation in display name',
        detail: `Sender: ${displayName.trim()}`, status: 'pass' });
    }
  }

  // ── 6. Date validity ──────────────────────────────────────────────────────
  if (dateStr) {
    hasData = true;
    const parsed = new Date(dateStr);
    if (isNaN(parsed.getTime())) {
      demerits += 8;
      checks.push({ label: 'Email date is unparseable',
        detail: `Date: ${dateStr}`, status: 'warn' });
    } else if (parsed.getTime() - Date.now() > 5 * 60 * 1000) {
      demerits += 15;
      checks.push({ label: 'Email date is in the future — likely forged',
        detail: parsed.toUTCString(), status: 'fail' });
    } else {
      checks.push({ label: 'Email date is valid',
        detail: parsed.toUTCString(), status: 'pass' });
    }
  }

  // Max possible demerits across all checks: 35+30+20+10+25+15 = 135
  const MAX = 135;
  const addedSpamScore = hasData ? Math.round((demerits / MAX) * 30) : 0;
  const probability    = hasData ? Math.max(0, Math.round(100 - (demerits / MAX) * 100)) : null;

  return { checks, probability, addedSpamScore };
}

/** Read header input fields for a given panel prefix ('em' or 'mn'). */
function readHeaderFields(prefix) {
  const v = id => {
    const el = document.getElementById(`hdr-${id}-${prefix}`);
    return el ? el.value.trim() : '';
  };
  return {
    from:     v('from'),
    replyTo:  v('replyto'),
    mailedBy: v('mailedby'),
    signedBy: v('signedby'),
    security: v('security'),
    date:     v('date'),
  };
}

// ─── AI Analysis Functions ────────────────────────────────────────────────────

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

async function analyzeWithOpenRouter(orKey, orModel, senderVal, subjectVal, bodyVal) {
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

  const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${orKey}`,
      'HTTP-Referer': 'https://github.com/spam-shield-extension',
      'X-Title': 'Spam Shield'
    },
    body: JSON.stringify({
      model: orModel || 'anthropic/claude-haiku-4-5',
      max_tokens: 768,
      messages: [{ role: 'user', content: prompt }]
    })
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `OpenRouter API error ${res.status}`);
  }

  const data = await res.json();
  const text = (data.choices[0].message.content || '').trim();
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error('Invalid response from OpenRouter');

  const parsed = JSON.parse(jsonMatch[0]);

  // Normalise findings to match our snippet format
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

function renderResults({ score, verdict, findings, authResult }) {
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

  verdictBadge.className   = `verdict-badge ${c.cls}`;
  verdictIcon.textContent  = c.icon;
  verdictLabel.textContent = c.label;
  scoreValue.textContent   = score;

  setTimeout(() => { scoreBarFill.style.width = `${score}%`; }, 50);

  // ── Sender Authenticity section ──────────────────────────────────────────────
  const authSection = $('authSection');
  const authBadge   = $('authBadge');
  const authChecks  = $('authChecks');

  if (authResult && authResult.checks.length > 0) {
    authSection.style.display = 'block';

    const { probability } = authResult;
    let authLevel, authCls;
    if      (probability === null) { authLevel = 'UNKNOWN'; authCls = 'auth-unknown'; }
    else if (probability >= 75)    { authLevel = 'HIGH';    authCls = 'auth-high';    }
    else if (probability >= 45)    { authLevel = 'MEDIUM';  authCls = 'auth-medium';  }
    else                           { authLevel = 'LOW';     authCls = 'auth-low';     }

    authBadge.textContent = probability !== null ? `${authLevel}  ${probability}%` : 'UNKNOWN';
    authBadge.className   = `auth-badge ${authCls}`;

    const statusIcons = { pass: '✅', fail: '🔴', warn: '⚠️', skip: '➖' };
    authChecks.innerHTML = '';
    for (const chk of authResult.checks) {
      const row = document.createElement('div');
      row.className = `auth-check-row auth-check-${chk.status}`;
      row.innerHTML = `
        <span class="auth-check-icon">${statusIcons[chk.status] || '•'}</span>
        <div class="auth-check-body">
          <span class="auth-check-label">${escapeHtml(chk.label)}</span>
          <span class="auth-check-detail">${escapeHtml(chk.detail)}</span>
        </div>`;
      authChecks.appendChild(row);
    }
  } else {
    authSection.style.display = 'none';
  }

  // ── Spam findings ────────────────────────────────────────────────────────────
  const hasRealFindings = findings.some(f => f.severity !== 'clean');
  findingsHdr.style.display = hasRealFindings ? 'flex' : 'none';

  findingsEl.innerHTML = '';
  const severityIcons = { high: '🔴', medium: '🟡', low: '🔵', clean: '✅' };

  for (const f of findings) {
    const itemClass = f.severity === 'clean' ? 'low' : f.severity;
    const div = document.createElement('div');
    div.className = `finding-item ${itemClass}`;

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

async function runAnalysis(senderVal, subjectVal, bodyVal, headerData, triggerBtn, originalBtnHTML) {
  setLoadingBtn(triggerBtn, true);
  $('results').style.display = 'none';

  try {
    const stored = await new Promise(res =>
      chrome.storage.local.get(['apiKey', 'orKey', 'orModel', 'aiProvider'], res)
    );
    const claudeKey  = stored.apiKey   || '';
    const orKey      = stored.orKey    || '';
    const orModel    = stored.orModel  || 'anthropic/claude-haiku-4-5';
    const preference = stored.aiProvider || 'anthropic'; // 'anthropic' | 'openrouter'

    const hasAnthropic   = claudeKey.startsWith('sk-ant-');
    const hasOpenRouter  = orKey.startsWith('sk-or-');

    // No API key configured — send user to settings to add one
    if (!hasAnthropic && !hasOpenRouter) {
      setLoadingBtn(triggerBtn, false, originalBtnHTML);
      $('mainView').style.display     = 'none';
      $('settingsView').style.display = 'block';
      if (stored.apiKey) $('apiKey').value = stored.apiKey;
      if (stored.orKey)  $('orKey').value  = stored.orKey;
      refreshProviderUI();
      const keyInput = $('apiKey');
      keyInput.focus();
      keyInput.style.borderColor = '#ef4444';
      setTimeout(() => { keyInput.style.borderColor = ''; }, 2000);
      return;
    }

    // PII-masked copies for external AI calls.
    // senderVal is intentionally NOT masked — the sender address/domain is a
    // core spam signal. headerData contains technical fields (domains, TLS)
    // that are also needed as-is.
    const maskedSubject = maskPII(subjectVal);
    const maskedBody    = maskPII(bodyVal);

    // Build ordered list of providers to try based on preference
    let providerOrder = [];
    if (hasAnthropic && hasOpenRouter) {
      providerOrder = preference === 'openrouter'
        ? ['openrouter', 'anthropic']
        : ['anthropic', 'openrouter'];
    } else if (hasAnthropic) {
      providerOrder = ['anthropic'];
    } else if (hasOpenRouter) {
      providerOrder = ['openrouter'];
    }

    let result;
    let lastError = null;

    for (const provider of providerOrder) {
      try {
        if (provider === 'anthropic') {
          result = await analyzeWithClaude(claudeKey, senderVal, maskedSubject, maskedBody);
        } else {
          result = await analyzeWithOpenRouter(orKey, orModel, senderVal, maskedSubject, maskedBody);
        }
        break; // success — stop trying
      } catch (e) {
        console.warn(`${provider} API error, trying next:`, e.message);
        lastError = e;
      }
    }

    // All AI providers failed — surface the error (no local fallback)
    if (!result) {
      throw lastError || new Error('All AI providers failed');
    }

    // Run header authenticity analysis and blend score
    const authResult = analyzeHeaders(headerData || {});
    result.score = Math.min(100, result.score + authResult.addedSpamScore);
    if      (result.score <= 25) result.verdict = 'safe';
    else if (result.score <= 55) result.verdict = 'suspicious';
    else                          result.verdict = 'spam';
    result.authResult = authResult;

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

  // ── Handle the extract response (shared by first attempt and retry) ──────────
  function handleExtractResponse(response) {
    if (!response || !response.body) {
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

    // Show To address in preview card
    const previewToRow = $('previewToRow');
    if (previewToRow) {
      if (response.to) {
        $('previewTo').textContent = response.to;
        previewToRow.style.display = '';
      } else {
        previewToRow.style.display = 'none';
      }
    }

    // Auto-populate header fields from content script data
    const headerMap = {
      'hdr-from-em':     response.from     || '',
      'hdr-replyto-em':  response.replyTo  || '',
      'hdr-mailedby-em': response.mailedBy || '',
      'hdr-signedby-em': response.signedBy || '',
      'hdr-security-em': response.security || '',
      'hdr-date-em':     response.date     || '',
    };
    let anyHeaderFilled = false;
    for (const [id, val] of Object.entries(headerMap)) {
      const el = document.getElementById(id);
      if (el) { el.value = val; }
      if (el && val) anyHeaderFilled = true;
    }
    // Hide rows whose value wasn't auto-filled
    document.querySelectorAll('#emailHeaderDetails .header-field-row').forEach(row => {
      const input = row.querySelector('input');
      if (input) row.style.display = input.value ? '' : 'none';
    });
    if (anyHeaderFilled) {
      const det = document.getElementById('emailHeaderDetails');
      if (det) det.open = true;
    }

    setEmailStatus('ready', 'Email loaded — ready to evaluate');
    $('emailPreviewCard').style.display = 'block';
    $('evaluateRow').style.display      = 'block';
  }

  // ── First attempt ─────────────────────────────────────────────────────────────
  chrome.tabs.sendMessage(tabId, { action: 'extractEmail' }, response => {
    if (!chrome.runtime.lastError) {
      // Content script responded normally
      handleExtractResponse(response);
      return;
    }

    // ── Stale context: re-inject content.js and retry ─────────────────────────
    // This happens whenever the extension is reloaded (e.g. after editing files)
    // while the email tab is already open. The old content script context becomes
    // invalid; chrome.scripting.executeScript injects a fresh copy into the tab.
    chrome.scripting.executeScript(
      { target: { tabId }, files: ['content.js'] },
      () => {
        if (chrome.runtime.lastError) {
          // Injection failed (e.g. restricted page) — surface the warning
          setEmailStatus('warn', 'No email open — please open an email first.');
          $('evaluateRow').style.display = 'block';
          return;
        }
        // Brief pause so the freshly-injected script can register its listener
        setTimeout(() => {
          chrome.tabs.sendMessage(tabId, { action: 'extractEmail' }, response2 => {
            if (chrome.runtime.lastError) {
              setEmailStatus('warn', 'No email open — please open an email first.');
              $('evaluateRow').style.display = 'block';
              return;
            }
            handleExtractResponse(response2);
          });
        }, 150);
      }
    );
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
    readHeaderFields('em'),
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
  $('emailContent').value    = '';
  $('sender').value          = '';
  $('subject').value         = '';
  $('charCount').textContent = '0 characters';
  $('results').style.display = 'none';
  // Clear manual header fields and close the panel
  ['from','replyto','mailedby','signedby','security','date'].forEach(f => {
    const el = document.getElementById(`hdr-${f}-mn`);
    if (el) el.value = '';
  });
  const det = document.getElementById('manualHeaderDetails');
  if (det) det.open = false;
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
    readHeaderFields('mn'),
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

/** Refresh the active-provider bar and ACTIVE tags based on current input values. */
function refreshProviderUI() {
  const claudeKey = ($('apiKey').value || '').trim();
  const orKey     = ($('orKey').value  || '').trim();

  const hasAnthropic  = claudeKey.startsWith('sk-ant-');
  const hasOpenRouter = orKey.startsWith('sk-or-');

  // Show/hide preference row
  $('prefRow').style.display = (hasAnthropic && hasOpenRouter) ? 'flex' : 'none';

  // Determine active provider
  let activeLabel = '';
  if (hasAnthropic && hasOpenRouter) {
    const pref = $('prefAnthropic').checked ? 'Anthropic' : 'OpenRouter';
    activeLabel = `${pref} (preferred) with ${pref === 'Anthropic' ? 'OpenRouter' : 'Anthropic'} as fallback`;
    $('claudeActiveTag').style.display = $('prefAnthropic').checked ? 'inline' : 'none';
    $('orActiveTag').style.display     = $('prefOpenRouter').checked ? 'inline' : 'none';
  } else if (hasAnthropic) {
    activeLabel = 'Anthropic Claude (active)';
    $('claudeActiveTag').style.display = 'inline';
    $('orActiveTag').style.display     = 'none';
  } else if (hasOpenRouter) {
    activeLabel = 'OpenRouter (active)';
    $('claudeActiveTag').style.display = 'none';
    $('orActiveTag').style.display     = 'inline';
  } else {
    $('claudeActiveTag').style.display = 'none';
    $('orActiveTag').style.display     = 'none';
  }

  const bar = $('activeProviderBar');
  if (activeLabel) {
    $('activeProviderText').textContent = activeLabel;
    bar.style.display = 'flex';
  } else {
    bar.style.display = 'none';
  }
}

$('settingsBtn').addEventListener('click', () => {
  $('mainView').style.display    = 'none';
  $('settingsView').style.display = 'block';

  chrome.storage.local.get(['apiKey', 'orKey', 'orModel', 'aiProvider'], data => {
    if (data.apiKey) $('apiKey').value = data.apiKey;
    if (data.orKey)  $('orKey').value  = data.orKey;
    if (data.orModel) {
      const sel = $('orModel');
      for (let i = 0; i < sel.options.length; i++) {
        if (sel.options[i].value === data.orModel) { sel.selectedIndex = i; break; }
      }
    }
    if (data.aiProvider === 'openrouter') {
      $('prefOpenRouter').checked = true;
    } else {
      $('prefAnthropic').checked = true;
    }
    refreshProviderUI();
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

$('toggleOrKeyBtn').addEventListener('click', () => {
  const inp = $('orKey');
  inp.type = inp.type === 'password' ? 'text' : 'password';
});

// Refresh UI whenever key fields or preference change
$('apiKey').addEventListener('input', refreshProviderUI);
$('orKey').addEventListener('input',  refreshProviderUI);
$('prefAnthropic').addEventListener('change',   refreshProviderUI);
$('prefOpenRouter').addEventListener('change',  refreshProviderUI);

$('saveSettingsBtn').addEventListener('click', () => {
  const claudeKey  = $('apiKey').value.trim();
  const orKey      = $('orKey').value.trim();
  const orModel    = $('orModel').value;
  const aiProvider = $('prefOpenRouter').checked ? 'openrouter' : 'anthropic';

  chrome.storage.local.set({ apiKey: claudeKey, orKey, orModel, aiProvider }, () => {
    const st = $('apiStatus');

    const hasAnthropic  = claudeKey.startsWith('sk-ant-');
    const hasOpenRouter = orKey.startsWith('sk-or-');

    let msg;
    if (hasAnthropic && hasOpenRouter) {
      msg = `✓ Both providers saved — ${aiProvider === 'openrouter' ? 'OpenRouter' : 'Anthropic'} preferred.`;
    } else if (hasAnthropic) {
      msg = '✓ Anthropic key saved — AI analysis enabled.';
    } else if (hasOpenRouter) {
      msg = '✓ OpenRouter key saved — AI analysis enabled.';
    } else {
      msg = 'Keys cleared — falling back to heuristic engine.';
    }

    st.textContent = msg;
    st.className   = 'api-status success';
    setTimeout(() => { st.textContent = ''; st.className = 'api-status'; }, 3500);

    refreshProviderUI();
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
