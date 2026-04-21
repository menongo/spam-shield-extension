'use strict';

// ─── Email Extractors for supported webmail clients ───────────────────────────

function extractGmail() {
  // Gmail selectors (as of 2024–2025)
  const body =
    document.querySelector('.a3s.aiL') ||
    document.querySelector('.ii.gt .a3s') ||
    document.querySelector('[data-message-id] .a3s');

  const subjectEl =
    document.querySelector('h2.hP') ||
    document.querySelector('[data-legacy-thread-id] h2');

  const senderEl =
    document.querySelector('.gD') ||
    document.querySelector('[email].gD') ||
    document.querySelector('span[email]');

  return {
    body: body ? body.innerText.trim() : '',
    subject: subjectEl ? subjectEl.innerText.trim() : '',
    sender: senderEl ? (senderEl.getAttribute('email') || senderEl.innerText.trim()) : ''
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
    sender: senderEl ? (senderEl.getAttribute('title') || senderEl.innerText.trim()) : ''
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
    sender: senderEl ? senderEl.innerText.trim() : ''
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
    sender: senderEl ? senderEl.innerText.trim() : ''
  };
}

function extractEmail() {
  const url = window.location.href;

  let result = { body: '', subject: '', sender: '' };

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
