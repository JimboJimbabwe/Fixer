/**
 * extract_storage.js
 * Paste into the browser DevTools console on the target page.
 * Extracts localStorage, sessionStorage, and cookies → downloads browser_storage.json
 */
(function () {
  'use strict';

  const data = {
    url:          window.location.href,
    capturedAt:   new Date().toISOString(),
    localStorage:  {},
    sessionStorage: {},
    cookiesParsed: {},
    cookiesRaw:   document.cookie,
  };

  // --- localStorage ---
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      let val = localStorage.getItem(key);
      try { val = JSON.parse(val); } catch (_) {}   // unwrap JSON-encoded values
      data.localStorage[key] = val;
    }
  } catch (e) {
    data.localStorage = { _error: e.message };
  }

  // --- sessionStorage ---
  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      let val = sessionStorage.getItem(key);
      try { val = JSON.parse(val); } catch (_) {}
      data.sessionStorage[key] = val;
    }
  } catch (e) {
    data.sessionStorage = { _error: e.message };
  }

  // --- Cookies (document.cookie → key/value pairs) ---
  if (document.cookie) {
    document.cookie.split(';').forEach(function (pair) {
      const idx = pair.indexOf('=');
      if (idx === -1) return;
      const key = pair.slice(0, idx).trim();
      const val = pair.slice(idx + 1).trim();
      data.cookiesParsed[key] = val;
    });
  }

  // --- Download as JSON ---
  const json = JSON.stringify(data, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = 'browser_storage.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  // --- Console summary ---
  console.log('%c[browser_storage] Exported → browser_storage.json', 'color:#4ade80;font-weight:bold');
  console.log('  localStorage keys : ', Object.keys(data.localStorage).length);
  console.log('  sessionStorage keys:', Object.keys(data.sessionStorage).length);
  console.log('  cookies           : ', Object.keys(data.cookiesParsed).length);
  if (Object.keys(data.cookiesParsed).length) console.table(data.cookiesParsed);

  return data;
}());
