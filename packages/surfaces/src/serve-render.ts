import { sanitizeForDisplay } from '@hn/core';

/**
 * What `hn serve` shows (decision 12, section 8.8.4). Model text is rendered here, on the server, into HTML that can
 * hold no markup of the model's: every character is escaped first, then a few markdown forms become fixed tags. An image
 * is never an `<img>`: it is shown as text with its URL, so nothing is fetched to show it (a fetch could carry data
 * out). A link shows its full URL beside its text and needs a click. Raw HTML and Mermaid are text.
 */

const escapeHtml = (text: string): string => text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');

/** Only http and https become links; anything else (javascript:, data:, file:) stays text. */
const safeHref = (url: string): string | null => (/^https?:\/\/[^\s"'<>]+$/i.test(url) ? url : null);

function inline(escaped: string): string {
  // Images first, so `![a](u)` is never read as a link: shown as text, never loaded.
  let out = escaped.replace(/!\[([^\]]*)\]\(([^)\s]*)\)/g, (_all, alt: string, url: string) => `<span class="blocked-image">[image not loaded: ${alt || 'no description'} &mdash; ${url}]</span>`);
  out = out.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (all, label: string, url: string) => {
    const href = safeHref(url.replaceAll('&amp;', '&'));
    if (href === null) return all;
    return `<a href="${escapeHtml(href)}" rel="noopener noreferrer nofollow" target="_blank">${label}</a> <span class="url">(${escapeHtml(href)})</span>`;
  });
  out = out.replace(/`([^`]+)`/g, '<code>$1</code>');
  out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  return out;
}

/** Markdown to HTML with nothing of the model's able to become markup. */
export function renderMarkdown(raw: string): string {
  const text = sanitizeForDisplay(raw);
  const blocks: string[] = [];
  const parts = text.split(/^```[^\n]*\n?/m);
  parts.forEach((part, index) => {
    if (index % 2 === 1) {
      blocks.push(`<pre><code>${escapeHtml(part.replace(/\n$/, ''))}</code></pre>`);
      return;
    }
    for (const paragraph of part.split(/\n{2,}/)) {
      if (paragraph.trim() === '') continue;
      const lines = paragraph.split('\n').map((line) => inline(escapeHtml(line)));
      blocks.push(`<p>${lines.join('<br>')}</p>`);
    }
  });
  return blocks.join('\n');
}

export const CSP = "default-src 'self'; img-src 'self' data:; connect-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";

export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
};

export const LOGIN_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>hn</title><link rel="stylesheet" href="/app.css"></head>
<body><main><h1>hn</h1><p>Paste the token hn printed in your terminal.</p>
<form method="post" action="/login"><input name="token" type="password" autocomplete="off" autofocus><button>Open</button></form></main></body></html>`;

export const APP_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>hn</title><link rel="stylesheet" href="/app.css"></head>
<body><main><h1>hn</h1><div id="status"></div><div id="log"></div><div id="cards"></div>
<form id="prompt"><textarea id="text" rows="3"></textarea><button>Send</button></form></main><script src="/app.js"></script></body></html>`;

export const APP_CSS = `body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#fafafa;color:#111}main{max-width:820px;margin:0 auto;padding:16px}
#log p,#log pre{margin:.4em 0}pre{background:#eee;padding:8px;overflow:auto}.url{color:#666;font-size:12px;word-break:break-all}
.blocked-image{color:#a33;font-size:13px}.card{border:3px double #b00;background:#fff4f4;padding:10px;margin:10px 0}
.card .who{font-weight:bold}textarea{width:100%;box-sizing:border-box}
@media (prefers-color-scheme: dark){body{background:#111;color:#eee}pre{background:#222}.card{background:#311}}`;

/** The client. Every server text arrives already rendered and escaped; card fields are set as text, never as HTML. */
export const APP_JS = `'use strict';
const log = document.getElementById('log');
const cards = document.getElementById('cards');
let csrf = '';
fetch('/session', { credentials: 'same-origin' }).then((r) => r.json()).then((s) => {
  csrf = s.csrf;
  document.getElementById('status').textContent = 'session ' + s.sessionId + ', mode ' + s.mode + ', tier ' + s.tier;
});
const post = (path, body) => fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json', 'x-hn-csrf': csrf }, body: JSON.stringify(body) }).then((r) => r.json());
const events = new EventSource('/events');
let live = null;
events.addEventListener('text', (e) => { if (live === null) { live = document.createElement('pre'); log.appendChild(live); } live.textContent += JSON.parse(e.data).text; });
events.addEventListener('card', (e) => {
  const card = JSON.parse(e.data);
  const box = document.createElement('div'); box.className = 'card';
  const who = document.createElement('div'); who.className = 'who'; who.textContent = 'hn asks: ' + card.tool + ' (' + card.effect + ')';
  const what = document.createElement('pre'); what.textContent = card.summary + (card.target ? '\\n' + card.target : '');
  const yes = document.createElement('button'); yes.textContent = 'Allow once';
  const no = document.createElement('button'); no.textContent = 'Deny';
  const answer = (decision) => post('/approve', { approvalId: card.approvalId, decision }).then(() => box.remove());
  yes.onclick = () => answer('once'); no.onclick = () => answer('deny');
  box.append(who, what, yes, no); cards.appendChild(box);
});
document.getElementById('prompt').onsubmit = (event) => {
  event.preventDefault();
  const text = document.getElementById('text').value; document.getElementById('text').value = '';
  const mine = document.createElement('p'); mine.textContent = '> ' + text; log.appendChild(mine); live = null;
  post('/prompt', { text }).then((r) => { if (live) live.remove(); live = null; const answer = document.createElement('div'); answer.innerHTML = r.html; log.appendChild(answer); });
};`;
