/*
 * Browser Storage Capture  v2.0
 * ---------------------------------------------------------------------------
 * Paste into the DevTools console on the page you are testing.
 * (Chrome blocks pasting until you type "allow pasting" once.)
 *
 * Collects localStorage, sessionStorage, JS-visible cookies, URL query +
 * fragment parameters and the page's cache headers, then downloads ONE report:
 *     storage_report_<host>_<YYYYMMDD-HHMMSS>.txt
 * which storage_analyzer.py can parse (it reads the section headers, so hits
 * are reported as "localStorage > authToken" instead of just a line number).
 *
 * Limits: HttpOnly cookies are invisible to JavaScript - get those from
 * DevTools > Application > Cookies or from Burp. The report contains raw
 * secret values: treat it as sensitive and delete it when done.
 */
(async () => {
  'use strict';

  // ── Settings ─────────────────────────────────────────────────────────────
  const DOWNLOAD_REPORT = true;       // set false to only print to the console
  const CHECK_CACHE_HEADERS = true;   // re-requests the current page (GET, body discarded)
  const MAX_JSON_DEPTH = 6;

  // ── Sensitive-data heuristics ────────────────────────────────────────────
  // Keys are split into WORDS (camelCase / snake_case / kebab-case) and matched
  // exactly, so "authToken" and "user_password" match but "keyboard", "author",
  // "discard" and "tokenExpiry" do not. Values are only judged by shape.
  const SECRET_WORDS = new Set(['password', 'passwd', 'pwd', 'pass', 'passphrase', 'secret', 'secrets',
    'credential', 'credentials', 'cvv', 'cvc', 'ssn', 'pin', 'apikey', 'iban']);
  const TOKEN_WORDS = new Set(['token', 'tokens', 'jwt', 'auth', 'authorization', 'bearer', 'session',
    'sessionid', 'sid', 'csrf', 'xsrf', 'otp', 'sso', 'jsessionid', 'phpsessid']);
  const KEY_QUALIFIERS = new Set(['api', 'private', 'secret', 'access', 'encryption', 'signing', 'client', 'master', 'auth']);
  const CARD_QUALIFIERS = new Set(['number', 'num', 'no', 'pan']);
  const BENIGN_WORDS = new Set(['expiry', 'expires', 'expiration', 'exp', 'type', 'name', 'count', 'length',
    'timeout', 'ttl', 'enabled', 'disabled', 'status', 'url', 'endpoint', 'header', 'prefix', 'version',
    'timestamp', 'time', 'date', 'format', 'mode', 'flag', 'required', 'valid', 'expired', 'start',
    'end', 'last', 'active', 'show', 'hide', 'is', 'has']);
  const PLACEHOLDERS = new Set(['true', 'false', 'null', 'undefined', 'none', 'nil', '0', '1', '[]', '{}', '""']);

  const VALUE_PATTERNS = [
    [/\beyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]*/, 'JWT'],
    [/^\s*bearer\s+[\w.~+/=-]{10,}/i, 'bearer token'],
    [/-----BEGIN (?:[A-Z]+ )*PRIVATE KEY/, 'private key'],
    [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/, 'AWS access key'],
    [/\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_\w{50,}/, 'GitHub token'],
    [/\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/, 'Stripe live key'],
    [/\bxox[abprs]-[A-Za-z0-9-]{10,}/, 'Slack token'],
    [/\bAIza[\w-]{35}\b/, 'Google API key'],
    [/\bsk-ant-[\w-]{20,}/, 'Anthropic API key'],
    [/(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/, 'SSN-like value'],
  ];

  const cardBrandOk = (d) => {
    const n2 = +d.slice(0, 2), n3 = +d.slice(0, 3), n4 = +d.slice(0, 4), L = d.length;
    return (d[0] === '4' && [13, 16, 19].includes(L)) ||                                   // Visa
      (((n2 >= 51 && n2 <= 55) || (n4 >= 2221 && n4 <= 2720)) && L === 16) ||               // Mastercard
      ([34, 37].includes(n2) && L === 15) ||                                                 // Amex
      ((n4 === 6011 || n2 === 65 || (n3 >= 644 && n3 <= 649)) && L >= 16 && L <= 19) ||      // Discover
      (((n3 >= 300 && n3 <= 305) || [36, 38, 39].includes(n2)) && L >= 14 && L <= 19) ||    // Diners
      (n4 >= 3528 && n4 <= 3589 && L >= 16 && L <= 19);                                      // JCB
  };

  const luhn = (s) => {
    const d = s.replace(/\D/g, '');
    if (d.length < 13 || d.length > 19 || !cardBrandOk(d)) return false;
    let sum = 0;
    for (let i = 0; i < d.length; i++) {
      let n = +d[d.length - 1 - i];
      if (i % 2) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
    }
    return sum % 10 === 0;
  };

  const words = (key) => String(key).replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

  function keyReason(key, value) {
    const w = words(key);
    if (w.some((x) => BENIGN_WORDS.has(x))) return null;
    let cls = null;
    if (w.some((x) => SECRET_WORDS.has(x))) cls = 'secret';
    else if (w.includes('key') && w.some((x) => KEY_QUALIFIERS.has(x))) cls = 'secret';
    else if (w.includes('card') && w.some((x) => CARD_QUALIFIERS.has(x))) cls = 'secret';
    else if (w.some((x) => TOKEN_WORDS.has(x))) cls = 'token';
    if (!cls) return null;
    const v = String(value).trim();
    if (!v || PLACEHOLDERS.has(v.toLowerCase())) return null;
    if (v.length < (cls === 'secret' ? 4 : 12)) return null;
    return `key name "${key}"`;
  }

  function valueReason(value) {
    const v = String(value);
    for (const [re, label] of VALUE_PATTERNS) if (re.test(v)) return `value looks like ${label}`;
    for (const m of v.matchAll(/(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])/g)) {
      if (luhn(m[0])) return 'value looks like a payment card number';
    }
    return null;
  }

  function walkJson(node, path, depth, out) {
    if (depth > MAX_JSON_DEPTH || node === null) return;
    if (Array.isArray(node)) { node.forEach((n, i) => walkJson(n, `${path}[${i}]`, depth + 1, out)); return; }
    if (typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) walkJson(v, path ? `${path}.${k}` : k, depth + 1, out);
      return;
    }
    const leafKey = path.split('.').pop().replace(/\[\d+\]$/, '');
    const r = keyReason(leafKey, node) || valueReason(node);
    if (r) out.push(`${path}: ${r.replace(/^key name "[^"]*"/, 'key name')}`);
  }

  function inspect(key, value) {
    const direct = keyReason(key, value) || valueReason(value);
    if (direct) return direct;
    const v = String(value).trim();
    if (v[0] === '{' || v[0] === '[') {                      // JSON blob: check nested keys
      try {
        const hits = [];
        walkJson(JSON.parse(v), '', 0, hits);
        if (hits.length) return `nested ${hits.slice(0, 3).join('; ')}`;
      } catch (_) { /* not JSON */ }
    }
    return null;
  }

  // ── Report building ──────────────────────────────────────────────────────
  const lines = [];
  const flagged = [];
  const esc = (v) => String(v).replace(/\r/g, '').replace(/\n/g, '\\n');  // keep one item per line

  const section = (title) => { lines.push('', `--- ${title} ---`); };
  function addItem(key, value) {
    const reason = inspect(key, value);
    if (reason) {
      flagged.push(`${key}: ${reason}`);
      lines.push(`⚠️ Potential sensitive data (${reason}) - ${key}: ${esc(value)}`);
    } else {
      lines.push(`${key}: ${esc(value)}`);
    }
  }
  const safely = (title, fn) => {
    section(title);
    try { fn(); } catch (err) { lines.push(`[could not read: ${err.message}]`); }
  };

  const now = new Date();
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\..+/, '').replace('T', '-');
  lines.push('=== BROWSER STORAGE REPORT ===',
    `URL      : ${location.href}`,
    `Origin   : ${location.origin}`,
    `Captured : ${now.toISOString()}`,
    '# HttpOnly cookies are not visible to JavaScript and are not listed here.');

  safely('LOCAL STORAGE', () => {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      addItem(k, localStorage.getItem(k));
    }
  });

  safely('SESSION STORAGE', () => {
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      addItem(k, sessionStorage.getItem(k));
    }
  });

  const cookies = [];
  safely('COOKIES', () => {
    document.cookie.split(';').forEach((c) => {
      if (!c.trim()) return;
      const i = c.indexOf('=');
      const k = (i < 0 ? c : c.slice(0, i)).trim();
      const v = i < 0 ? '' : c.slice(i + 1).trim();   // values may themselves contain '='
      cookies.push(`${k}=${v}`);
      addItem(k, v);
    });
  });

  safely('URL PARAMETERS', () => {
    for (const [k, v] of new URLSearchParams(location.search).entries()) addItem(k, v);
  });

  safely('URL FRAGMENT', () => {     // e.g. #access_token=... from OAuth implicit flows
    const frag = location.hash.replace(/^#\/?/, '');
    if (frag.includes('=')) for (const [k, v] of new URLSearchParams(frag).entries()) addItem(k, v);
  });

  section('CACHE HEADERS');
  if (CHECK_CACHE_HEADERS) {
    try {
      const res = await fetch(location.href, { method: 'GET', cache: 'no-store', credentials: 'same-origin' });
      try { await res.body?.cancel(); } catch (_) { /* body already consumed */ }
      lines.push(`Status: ${res.status}  (GET, body discarded)`);
      for (const h of ['Cache-Control', 'Expires', 'Pragma']) lines.push(`${h}: ${res.headers.get(h) ?? '(none)'}`);
      const cc = (res.headers.get('Cache-Control') || '').toLowerCase();
      if (!cc) lines.push('⚠️ No Cache-Control header: the page may be cached by the browser or proxies');
      else {
        if (cc.includes('public')) lines.push("⚠️ Cache-Control contains 'public': shared caches may store this page");
        if (!cc.includes('no-store')) lines.push("⚠️ Cache-Control lacks 'no-store': sensitive pages should send it");
      }
    } catch (err) {
      lines.push(`[could not check cache headers: ${err.message}]`);
    }
  } else {
    lines.push('(skipped)');
  }

  section('CONSOLIDATED COOKIE LIST');
  lines.push(...(cookies.length ? cookies : ['(none)']));

  // ── Output: one console dump, one download ───────────────────────────────
  const reportText = lines.join('\n') + '\n';
  window.__storageReport = reportText;               // fallback if the download is blocked

  console.log(reportText);
  if (flagged.length) console.warn(`⚠️ ${flagged.length} potentially sensitive item(s):`, flagged);
  else console.log('No obviously sensitive keys/values found by the quick check. Run the analyzer for a full scan.');

  if (DOWNLOAD_REPORT) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([reportText], { type: 'text/plain' }));
    a.download = `storage_report_${location.hostname || 'page'}_${stamp}.txt`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(a.href); }, 0);
    console.log(`Report downloaded as ${a.download}  (also available as window.__storageReport)`);
  }
  console.log('Tip: check the Network tab for cache behaviour on other pages, and Application > Cookies for HttpOnly cookies.');
})();
