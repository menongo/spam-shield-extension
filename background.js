'use strict';

// Service Worker — keeps the extension alive and handles any cross-tab events.

chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === 'install') {
    console.log('[Spam Shield] Extension installed successfully.');
  }
});

// Handle messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'ping') {
    sendResponse({ status: 'ok' });
  }
  return true;
});
