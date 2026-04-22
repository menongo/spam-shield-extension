'use strict';

// ─── Email Extractors for supported webmail clients ───────────────────────────

function extractGmail() {
  // Gmail selectors (as of 2024–2025)
  const body =
    document.querySelector('.a3s.aiL') ||
    document.querySelector('.ii.gt .a3s') ||
    document.querySelector('[data-message-id] .a3s') ||
    document.querySelector('.gs .ii .a3s') ||
    document.querySelector('[role="main"] .a3s');

  const subjectEl =
    document.querySelector('h2.hP') ||
    document.querySelector('[data-legacy-thread-id] h2');

  const senderEl =
    document.querySelector('.gD') ||
    document.querySelector('[email].gD') ||
    document.querySelector('span[email]');

  // ── Header fields (visible when user expands email details in Gmail) ──────────
  // These selectors target the expanded header detail row Gmail renders when the
  // user clicks the caret next to "to: me". Absence is treated as empty string —
  // a selector regression degrades silently to "no header data" rather than crash.

  // Mailed-by: appears in .aZo when detail row is expanded
  const mailedByEl =
    document.querySelector('.aZo') ||
    document.querySelector('.bzB');
  const mailedBy = mailedByEl ? mailedByEl.innerText.replace(/^mailed-by:\s*/i, '').trim() : '';

  // Signed-by (DKIM): adjacent row .aZp
  const signedByEl = document.querySelector('.aZp');
  const signedBy = signedByEl ? signedByEl.innerText.replace(/^signed-by:\s*/i, '').trim() : '';

  // Security/TLS: lock icon tooltip or visible text
  const securityEl =
    document.querySelector('[data-tooltip*="TLS"]') ||
    document.querySelector('[data-tooltip*="ncryption"]') ||
    document.querySelector('.iweboffl');
  const security = securityEl
    ? (securityEl.getAttribute('data-tooltip') || securityEl.innerText).replace(/\n/g, ' ').trim()
    : '';

  // Date: .g3 (short label) or .gK with title attr (full RFC date)
  const dateEl =
    document.querySelector('.g3') ||
    document.querySelector('.gK');
  const emailDate = dateEl
    ? (dateEl.getAttribute('title') || dateEl.getAttribute('aria-label') || dateEl.innerText).trim()
    : '';

  // Full From header — reconstruct "Display Name <email>" from the sender element
  let fullFrom = '';
  if (senderEl) {
    const name  = senderEl.getAttribute('name') || senderEl.innerText.trim();
    const email = senderEl.getAttribute('email') || '';
    fullFrom = email ? `${name} <${email}>` : name;
  }

  // Reply-To: shown in expanded header details when different from From.
  // Gmail uses .aZo/.aZp for mailed-by/signed-by; reply-to may appear as a
  // sibling row — scan all such elements for "reply-to" label text.
  let replyTo = '';
  const detailEls = document.querySelectorAll('.aZo, .aZp, .aZq, .aZr, .aZs, .aZt');
  for (const el of detailEls) {
    if (/reply.?to/i.test(el.innerText || '')) {
      replyTo = el.innerText.replace(/^reply.?to[:\s]*/i, '').trim();
      break;
    }
  }

  // To recipients: .aeF is the "to" area; .g2 are individual recipient spans
  let to = '';
  const toSpans = document.querySelectorAll('.aeF .g2');
  if (toSpans.length > 0) {
    to = Array.from(toSpans)
      .map(el => el.getAttribute('email') || el.innerText.trim())
      .filter(Boolean)
      .join(', ');
  }
  if (!to) {
    // Fallback: any visible span with an email attribute in the header region
    const fallbackToEl = document.querySelector('.aDi [email], [email].g2');
    if (fallbackToEl) {
      to = fallbackToEl.getAttribute('email') || fallbackToEl.innerText.trim();
    }
  }

  return {
    body:     body      ? body.innerText.trim()                                         : '',
    subject:  subjectEl ? subjectEl.innerText.trim()                                    : '',
    sender:   senderEl  ? (senderEl.getAttribute('email') || senderEl.innerText.trim()) : '',
    // Header fields (empty string when not available)
    from:     fullFrom,
    replyTo,
    mailedBy,
    signedBy,
    security,
    date:     emailDate,
    to,
  };
}

function extractOutlook() {
  // Outlook Web App selectors
  const body =
    document.querySelector('[class*="ReadingPane"] [class*="body"]') ||
    document.querySelector('.allowTextSelection') ||
    document.querySelector('[aria-label="Message body"]') ||
    document.querySelector('[class*="readingPane"] [class*="messageBody"]');

  const subjectEl =
    document.querySelector('[class*="ReadingPane"] [class*="subject"]') ||
    document.querySelector('[class*="subject"][class*="reading"]') ||
    document.querySelector('h1[class*="subject"]');

  const senderEl =
    document.querySelector('[class*="ReadingPane"] [class*="sender"] [class*="email"]') ||
    document.querySelector('[class*="from"] [class*="email"]') ||
    document.querySelector('[title*="@"]');

  return {
    body: body ? body.innerText.trim() : '',
    subject: subjectEl ? subjectEl.innerText.trim() : '',
    sender: senderEl ? (senderEl.getAttribute('title') || senderEl.innerText.trim()) : '',
    from: '', replyTo: '', mailedBy: '', signedBy: '', security: '', date: '', to: ''
  };
}

function extractYahooMail() {
  const body =
    document.querySelector('.msg-body') ||
    document.querySelector('[data-test-id="message-body"]') ||
    document.querySelector('.yk-content');

  const subjectEl =
    document.querySelector('[data-test-id="message-group-subject"]') ||
    document.querySelector('.yk-col h2');

  const senderEl =
    document.querySelector('[data-test-id="sender-email"]') ||
    document.querySelector('.yk-byline');

  return {
    body: body ? body.innerText.trim() : '',
    subject: subjectEl ? subjectEl.innerText.trim() : '',
    sender: senderEl ? senderEl.innerText.trim() : '',
    from: '', replyTo: '', mailedBy: '', signedBy: '', security: '', date: '', to: ''
  };
}

function extractProtonMail() {
  const body =
    document.querySelector('.message-content') ||
    document.querySelector('[class*="messageContent"]') ||
    document.querySelector('.proton-message-content');

  const subjectEl =
    document.querySelector('[class*="subject"]') ||
    document.querySelector('h2[class*="title"]');

  const senderEl =
    document.querySelector('[class*="sender"] [class*="email"]') ||
    document.querySelector('[class*="initials"] + span');

  return {
    body: body ? body.innerText.trim() : '',
    subject: subjectEl ? subjectEl.innerText.trim() : '',
    sender: senderEl ? senderEl.innerText.trim() : '',
    from: '', replyTo: '', mailedBy: '', signedBy: '', security: '', date: '', to: ''
  };
}

function extractEmail() {
  const url = window.location.href;

  let result = { body: '', subject: '', sender: '', from: '', replyTo: '', mailedBy: '', signedBy: '', security: '', date: '', to: '' };

  if (url.includes('mail.google.com')) {
    result = extractGmail();
  } else if (url.includes('outlook.') || url.includes('office.com')) {
    result = extractOutlook();
  } else if (url.includes('mail.yahoo.com')) {
    result = extractYahooMail();
  } else if (url.includes('proton.me') || url.includes('mail.proton.me')) {
    result = extractProtonMail();
  }

  // Fallback: if nothing found, grab selected text
  if (!result.body) {
    const selection = window.getSelection();
    if (selection && selection.toString().trim().length > 20) {
      result.body = selection.toString().trim();
    }
  }

  return result;
}

// ─── Message listener ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'extractEmail') {
    try {
      const data = extractEmail();
      sendResponse(data);
    } catch (e) {
      sendResponse({ body: '', subject: '', sender: '', error: e.message });
    }
  }
  return true; // Keep channel open for async
});
