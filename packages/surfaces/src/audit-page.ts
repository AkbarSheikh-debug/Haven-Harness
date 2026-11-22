/**
 * What the auditor screen is made of: a page with no content of its own, a stylesheet and a script. The CSP of `hn serve`
 * allows scripts and styles only from this server, so there is no inline script, no inline style and no handler in the
 * markup. Everything the broker's audit holds is put on the page with `textContent` and `createElement`, never as HTML, so
 * an approval whose action text looks like markup is shown as the characters it is. `String.raw` is used so the script needs
 * no escaping; it must contain no backtick and no dollar-brace.
 */

export const AUDIT_PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>hn team audit</title><link rel="stylesheet" href="/audit.css"></head>
<body><header><h1>hn team audit</h1><p class="sub">What the broker recorded: who did what, who approved it, and whether the record is whole. Read-only.</p></header>
<main>
<section id="status" role="status" aria-live="polite">Checking the broker...</section>
<nav id="tabs" aria-label="Views"><button type="button" data-tab="search" aria-pressed="true">Search</button><button type="button" data-tab="approvals" aria-pressed="false">Approvals</button><button type="button" data-tab="sessions" aria-pressed="false">Sessions</button><button type="button" data-tab="live" aria-pressed="false">Live</button><button type="button" data-tab="export" aria-pressed="false">Export</button></nav>
<section id="search" class="tab">
<form id="search-form" autocomplete="off"><label>Person <input name="user" maxlength="200"></label> <label>Session <input name="session" maxlength="100"></label> <label>Type starts with <input name="type" maxlength="64" placeholder="broker/model"></label> <label>Since <input name="since" maxlength="40" placeholder="2026-11-22T00:00:00Z"></label> <label>Until <input name="until" maxlength="40"></label> <button type="submit">Search</button></form>
<div id="search-note" class="note"></div><table id="rows" aria-label="Audit rows"><thead><tr><th>Row</th><th>Time</th><th>Type</th><th>What</th></tr></thead><tbody></tbody></table><button id="more" type="button" hidden>More rows</button>
</section>
<section id="approvals" class="tab" hidden><form id="approvals-form" autocomplete="off"><label>Person <input name="user" maxlength="200"></label> <label>State <select name="state"><option value="">any</option><option>pending</option><option>approved</option><option>denied</option><option>used</option><option>refused</option></select></label> <button type="submit">Show</button></form>
<div id="approvals-note" class="note"></div><table id="approval-table" aria-label="Approvals"><thead><tr><th>Id</th><th>Asked</th><th>By</th><th>Action</th><th>State</th><th>Decided by</th><th>Refused attempts</th><th>Rows</th></tr></thead><tbody></tbody></table></section>
<section id="sessions" class="tab" hidden><form id="sessions-form" autocomplete="off"><label>Person <input name="user" maxlength="200"></label> <button type="submit">Show</button></form>
<div id="sessions-note" class="note"></div><table id="session-table" aria-label="Sessions"><thead><tr><th>Person</th><th>Session</th><th>First seen</th><th>Model calls</th><th>Cost (USD)</th><th>Head anchored by the session</th></tr></thead><tbody></tbody></table></section>
<section id="live" class="tab" hidden><p><button id="live-toggle" type="button">Follow live</button> <span id="live-state"></span></p><ol id="live-rows" aria-label="New rows"></ol></section>
<section id="export" class="tab" hidden><p>An export is a run of rows with the broker's signed checkpoint at its end. It can be checked offline with <b>hn audit verify</b>.</p>
<p><a id="download" href="/audit/api/export" download="audit-export.json">Download the whole export</a></p><p><button id="verify" type="button">Check it here</button> <span id="verify-state"></span></p><div id="verify-note" class="note"></div></section>
<aside id="detail" hidden><h2>Row</h2><pre id="detail-text"></pre><button id="detail-close" type="button">Close</button></aside>
</main><script src="/audit.js"></script></body></html>`;

export const AUDIT_CSS = `:root{--bg:#fafafa;--fg:#14181d;--muted:#59636e;--line:#d0d7de;--card:#fff;--ok:#1a7f37;--bad:#b00020;--warn:#9a6700;--sel:#ddf4ff}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--fg:#e6edf3;--muted:#9198a1;--line:#2b323b;--card:#161b22;--ok:#3fb950;--bad:#ff7b72;--warn:#d29922;--sel:#102a43}}
*{box-sizing:border-box}[hidden]{display:none !important}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header{padding:12px 16px;border-bottom:1px solid var(--line)}h1{font-size:20px;margin:0}.sub{margin:2px 0 0;color:var(--muted)}main{padding:12px 16px;max-width:1280px;margin:0 auto}
section{margin:10px 0}input,select,button{font:inherit;padding:4px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg)}button{cursor:pointer}label{margin-right:10px;display:inline-block}
#status{padding:10px 12px;border:1px solid var(--line);border-left-width:6px;border-radius:6px;background:var(--card)}#status.ok{border-left-color:var(--ok)}#status.warn{border-left-color:var(--warn)}#status.bad{border-left-color:var(--bad);font-weight:600}
#tabs{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0}#tabs button[aria-pressed=true]{background:var(--sel);border-color:var(--fg)}
table{width:100%;border-collapse:collapse;background:var(--card);margin-top:8px}th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{color:var(--muted);font-weight:600}tbody tr{cursor:pointer}tbody tr:hover{background:var(--sel)}
.note{color:var(--muted);margin:6px 0}.note.bad{color:var(--bad);font-weight:600}.state-pending{color:var(--warn)}.state-denied{color:var(--bad)}.state-used,.state-approved{color:var(--ok)}
#live-rows{list-style:none;padding:0;margin:0;font-family:ui-monospace,Consolas,monospace;font-size:13px}#live-rows li{padding:3px 8px;border-bottom:1px solid var(--line);overflow-wrap:anywhere;background:var(--card)}
#detail{position:fixed;right:12px;bottom:12px;max-width:min(640px,92vw);max-height:60vh;overflow:auto;background:var(--card);border:1px solid var(--fg);border-radius:8px;padding:10px 12px}#detail pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:6px 0}`;

export const AUDIT_JS = String.raw`'use strict';
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var MAX_LIVE = 500;
  var live = null;
  var lastRow = 0;
  var nextOlder = null;

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function get(path) {
    return fetch(path, { credentials: 'same-origin' }).then(function (r) {
      return r.text().then(function (body) {
        var data = null;
        try { data = JSON.parse(body); } catch (e) { /* not JSON: the message is the body */ }
        if (!r.ok) throw new Error(data && data.error ? data.error : (body || ('HTTP ' + r.status)));
        return data;
      });
    });
  }
  function query(form) {
    var parts = [];
    Array.prototype.forEach.call(form.elements, function (field) {
      if (field.name && field.value) parts.push(encodeURIComponent(field.name) + '=' + encodeURIComponent(field.value));
    });
    return parts;
  }
  function brief(data) {
    var text = JSON.stringify(data);
    return text.length > 220 ? text.slice(0, 220) + '...' : text;
  }
  function cell(row, text, cls) { row.appendChild(el('td', cls || '', text === null || text === undefined ? '' : String(text))); }
  function note(id, text, bad) { var n = $(id); n.textContent = text; n.className = bad ? 'note bad' : 'note'; }

  function showDetail(row) {
    $('detail-text').textContent = JSON.stringify(row, null, 2);
    $('detail').hidden = false;
  }
  function rowLine(row) {
    var tr = el('tr');
    cell(tr, row.n); cell(tr, row.ts); cell(tr, row.type); cell(tr, brief(row.data));
    tr.addEventListener('click', function () { showDetail(row); });
    return tr;
  }

  // The checkpoint line says whether the broker has signed its current head, and whether the key is the one this screen was given.
  function loadStatus() {
    get('/audit/api/status').then(function (s) {
      var box = $('status');
      if (s.pinned && s.signatureOk && s.keyMatches) {
        box.className = 'ok';
        box.textContent = 'The broker has signed row ' + s.head + ' (the newest), at ' + s.signedAt + ', with the key you pinned (' + s.keyId + ').';
      } else if (s.pinned) {
        box.className = 'bad';
        box.textContent = 'NOT TRUSTED: the broker\'s checkpoint does not verify with the key you pinned. Do not rely on what this screen shows.';
      } else {
        box.className = 'warn';
        box.textContent = 'The broker says its newest row is ' + s.head + ' (checkpoint key ' + s.keyId + '). No public key was pinned (start with --pub), so nothing here has been checked against a key you trust.';
      }
    }).catch(function (e) { $('status').className = 'bad'; $('status').textContent = 'Could not reach the audit: ' + e.message; });
  }

  function search(after) {
    var parts = query($('search-form'));
    if (after) parts.push('after=' + after);
    parts.push('limit=100');
    note('search-note', 'Searching...');
    get('/audit/api/rows?' + parts.join('&')).then(function (data) {
      var body = $('rows').querySelector('tbody');
      if (!after) clear(body);
      data.rows.forEach(function (row) { body.appendChild(rowLine(row)); });
      nextOlder = data.next;
      $('more').hidden = data.next === null;
      note('search-note', data.rows.length === 0 && !after ? 'No rows match.' : 'Newest row: ' + data.head.n);
    }).catch(function (e) { note('search-note', e.message, true); });
  }

  function approvals() {
    var parts = query($('approvals-form'));
    note('approvals-note', 'Loading...');
    get('/audit/api/approvals' + (parts.length ? '?' + parts.join('&') : '')).then(function (data) {
      var body = $('approval-table').querySelector('tbody');
      clear(body);
      data.approvals.forEach(function (a) {
        var tr = el('tr');
        cell(tr, a.id); cell(tr, a.requestedAt); cell(tr, a.requester); cell(tr, a.action);
        cell(tr, a.state, 'state-' + a.state); cell(tr, a.decidedBy);
        cell(tr, a.refused.length === 0 ? '' : a.refused.map(function (r) { return r.approver + ': ' + r.reason; }).join('; '));
        cell(tr, a.rows.join(', '));
        tr.addEventListener('click', function () { showDetail(a); });
        body.appendChild(tr);
      });
      note('approvals-note', data.approvals.length === 0 ? 'No approvals match.' : data.approvals.length + ' shown' + (data.truncated ? ' (the newest only)' : ''));
    }).catch(function (e) { note('approvals-note', e.message, true); });
  }

  function sessions() {
    var parts = query($('sessions-form'));
    note('sessions-note', 'Loading...');
    get('/audit/api/sessions' + (parts.length ? '?' + parts.join('&') : '')).then(function (data) {
      var body = $('session-table').querySelector('tbody');
      clear(body);
      data.sessions.forEach(function (s) {
        var tr = el('tr');
        cell(tr, s.user); cell(tr, s.session); cell(tr, s.firstAt); cell(tr, s.modelCalls); cell(tr, s.usd.toFixed(4));
        cell(tr, s.anchor === null ? 'none: a cut tail on that laptop could not be told' : 'row ' + s.anchor.n);
        tr.addEventListener('click', function () { showDetail(s); });
        body.appendChild(tr);
      });
      note('sessions-note', data.sessions.length === 0 ? 'No sessions.' : data.sessions.length + ' shown');
    }).catch(function (e) { note('sessions-note', e.message, true); });
  }

  // The live view reads the broker's own stream, so following it adds one row to the record (who is looking), not one per refresh.
  function stopLive(message) {
    if (live !== null) { live.abort(); live = null; }
    $('live-toggle').textContent = 'Follow live';
    $('live-state').textContent = message || '';
  }
  function startLive() {
    var controller = new AbortController();
    live = controller;
    $('live-toggle').textContent = 'Stop';
    $('live-state').textContent = 'Following...';
    var list = $('live-rows');
    fetch('/audit/api/tail', { credentials: 'same-origin', signal: controller.signal }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error(t || ('HTTP ' + r.status)); });
      var reader = r.body.getReader();
      var decoder = new TextDecoder();
      var pending = '';
      function pump() {
        return reader.read().then(function (chunk) {
          if (chunk.done) { if (live === controller) stopLive('The broker ended the stream.'); return; }
          pending += decoder.decode(chunk.value, { stream: true });
          var at = pending.indexOf(String.fromCharCode(10));
          while (at !== -1) {
            var line = pending.slice(0, at);
            pending = pending.slice(at + 1);
            if (line) handle(JSON.parse(line));
            at = pending.indexOf(String.fromCharCode(10));
          }
          return pump();
        });
      }
      function handle(message) {
        if (message.type === 'row') {
          var li = el('li', '', '#' + message.row.n + '  ' + message.row.ts + '  ' + message.row.type + '  ' + brief(message.row.data));
          li.addEventListener('click', function () { showDetail(message.row); });
          list.insertBefore(li, list.firstChild);
          while (list.children.length > MAX_LIVE) list.removeChild(list.lastChild);
          lastRow = message.row.n;
          $('live-state').textContent = 'Following. Newest row ' + lastRow + '.';
        } else if (message.type === 'dropped' || message.type === 'closed') {
          stopLive('The broker ended the stream: ' + message.reason);
        }
      }
      return pump();
    }).catch(function (e) { if (live === controller) stopLive('Stopped: ' + e.message); });
  }

  function verify() {
    $('verify-state').textContent = 'Checking...';
    get('/audit/api/verify').then(function (v) {
      var box = $('verify-note');
      if (v.ok === null) { $('verify-state').textContent = ''; box.className = 'note'; box.textContent = v.message; return; }
      $('verify-state').textContent = v.ok ? 'VERIFIED' : 'NOT VERIFIED';
      box.className = v.ok ? 'note' : 'note bad';
      box.textContent = v.ok ? 'Rows ' + v.from + ' to ' + v.to + ' (' + v.rows + ') chain correctly and the last row is covered by a checkpoint signed with your pinned key.' : (v.reason || '') + (v.brokenAt ? ' (row ' + v.brokenAt + ')' : '');
    }).catch(function (e) { $('verify-state').textContent = ''; note('verify-note', e.message, true); });
  }

  Array.prototype.forEach.call($('tabs').querySelectorAll('button'), function (b) {
    b.addEventListener('click', function () {
      var name = b.getAttribute('data-tab');
      Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (s) { s.hidden = s.id !== name; });
      Array.prototype.forEach.call($('tabs').querySelectorAll('button'), function (x) { x.setAttribute('aria-pressed', x === b ? 'true' : 'false'); });
      if (name === 'approvals') approvals();
      if (name === 'sessions') sessions();
    });
  });
  $('search-form').addEventListener('submit', function (e) { e.preventDefault(); search(0); });
  $('approvals-form').addEventListener('submit', function (e) { e.preventDefault(); approvals(); });
  $('sessions-form').addEventListener('submit', function (e) { e.preventDefault(); sessions(); });
  $('more').addEventListener('click', function () { if (nextOlder) search(nextOlder); });
  $('live-toggle').addEventListener('click', function () { if (live === null) startLive(); else stopLive('Stopped.'); });
  $('verify').addEventListener('click', verify);
  $('detail-close').addEventListener('click', function () { $('detail').hidden = true; });
  loadStatus();
  search(0);
})();`;
