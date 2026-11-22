/**
 * What the replay screen is made of: a page with no content of its own, a stylesheet, and a script. The CSP of `hn serve`
 * allows scripts and styles only from this server, so there is no inline script, no inline style and no handler in the markup.
 * Everything a log holds is put on the page with `textContent` and `createElement`, never as HTML, so a command that
 * looks like markup is shown as the characters it is. `String.raw` is used so the script needs no escaping; it must
 * contain no backtick and no dollar-brace.
 */

export const replayPage = (follow: boolean): string => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>hn session replay</title><link rel="stylesheet" href="/replay.css"></head>
<body${follow ? ' data-follow="1"' : ''}><header><h1>hn session replay</h1><p class="sub">Step through what a session did, from its tamper-evident log. Read-only.</p></header>
<main>
<section id="picker"><label for="session">Session</label> <select id="session"></select> <span id="count"></span> <label class="follow"><input type="checkbox" id="follow"> Follow live</label> <span id="live" role="status" aria-live="polite"></span></section>
<section id="integrity" role="status" aria-live="polite"></section>
<section id="summary"></section>
<section id="controls" hidden>
<div class="buttons"><button id="first" type="button">First</button><button id="prev" type="button">Previous</button><button id="next" type="button">Next</button><button id="last" type="button">Last</button>
<button id="next-refusal" type="button">Next refusal</button><button id="next-taint" type="button">Next taint change</button></div>
<label class="scrub" for="scrubber">Step</label><input id="scrubber" type="range" min="0" max="0" value="0"><span id="position"></span>
<div id="filters" role="group" aria-label="Show"></div>
</section>
<div id="layout" hidden><ol id="timeline" aria-label="Steps"></ol>
<div id="panel"><div id="detail" aria-live="polite"></div><div id="state"></div></div></div>
</main><script src="/replay.js"></script></body></html>`;

export const REPLAY_PAGE = replayPage(false);

export const REPLAY_CSS = `:root{--bg:#fafafa;--fg:#14181d;--muted:#59636e;--line:#d0d7de;--card:#fff;--ok:#1a7f37;--bad:#b00020;--warn:#9a6700;--addbg:#e6ffec;--delbg:#ffebe9;--sel:#ddf4ff}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--fg:#e6edf3;--muted:#9198a1;--line:#2b323b;--card:#161b22;--ok:#3fb950;--bad:#ff7b72;--warn:#d29922;--addbg:#12261e;--delbg:#2d1214;--sel:#102a43}}
*{box-sizing:border-box}[hidden]{display:none !important}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header{padding:12px 16px;border-bottom:1px solid var(--line)}h1{font-size:20px;margin:0}.sub{margin:2px 0 0;color:var(--muted)}main{padding:12px 16px;max-width:1280px;margin:0 auto}
section{margin:10px 0}select,button{font:inherit;padding:4px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg)}button{cursor:pointer}button:focus-visible,select:focus-visible,input:focus-visible,li:focus-visible{outline:2px solid var(--sel);outline-offset:2px}
#integrity{padding:10px 12px;border:1px solid var(--line);border-left-width:6px;border-radius:6px;background:var(--card)}#integrity.verified{border-left-color:var(--ok)}#integrity.refused{border-left-color:var(--bad);font-weight:600}#integrity strong{display:block}
#summary{display:flex;flex-wrap:wrap;gap:6px 18px;color:var(--muted)}#summary b{color:var(--fg)}
.buttons{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px}.scrub{margin-right:6px}#scrubber{width:min(480px,60vw);vertical-align:middle}#position{margin-left:8px;color:var(--muted)}
#filters{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}#filters button[aria-pressed=true]{background:var(--sel);border-color:var(--fg)}
#layout{display:grid;grid-template-columns:minmax(260px,1fr) minmax(320px,1.4fr);gap:14px;align-items:start}@media (max-width:760px){#layout{grid-template-columns:1fr}}
#timeline{list-style:none;margin:0;padding:0;max-height:70vh;overflow:auto;border:1px solid var(--line);border-radius:6px;background:var(--card)}
#timeline li{padding:5px 10px;border-bottom:1px solid var(--line);cursor:pointer;border-left:5px solid transparent;overflow-wrap:anywhere}#timeline li[aria-current=step]{background:var(--sel)}
#timeline li.refused{border-left-color:var(--bad)}#timeline li.warn{border-left-color:var(--warn)}#timeline li.ok{border-left-color:var(--ok)}#timeline .n{color:var(--muted);margin-right:6px;font-variant-numeric:tabular-nums}
#panel{position:sticky;top:8px}#detail,#state{border:1px solid var(--line);border-radius:6px;background:var(--card);padding:10px 12px;margin-bottom:10px}
#detail h2{font-size:17px;margin:0 0 4px;overflow-wrap:anywhere}.meta{color:var(--muted);font-size:13px}.badge{display:inline-block;padding:0 6px;border-radius:4px;border:1px solid var(--line);font-size:12px;margin-right:6px}
.badge.refused{color:var(--bad);border-color:var(--bad)}.badge.warn{color:var(--warn);border-color:var(--warn)}.badge.ok{color:var(--ok);border-color:var(--ok)}
pre{margin:8px 0 0;padding:8px;background:var(--bg);border:1px solid var(--line);border-radius:6px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:40vh;overflow:auto}
.diff{margin-top:8px;border:1px solid var(--line);border-radius:6px;overflow:auto;max-height:40vh}.diff div{padding:0 8px;white-space:pre-wrap;overflow-wrap:anywhere;font-family:ui-monospace,Consolas,monospace;font-size:13px}.diff .add{background:var(--addbg)}.diff .del{background:var(--delbg)}.diff .head{color:var(--muted)}
.related{margin-top:8px;display:flex;flex-wrap:wrap;gap:6px}dl{margin:0;display:grid;grid-template-columns:max-content 1fr;gap:2px 14px}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}.yes{color:var(--warn);font-weight:600}.no{color:var(--ok)}
#state h3{font-size:14px;margin:0 0 6px}`;

export const REPLAY_JS = String.raw`'use strict';
(function () {
  var SESSION_ID = /^[A-Za-z0-9-]{1,64}$/;
  var MAX_DIFF_LINES = 400;
  var $ = function (id) { return document.getElementById(id); };
  var replay = null;
  var visible = [];
  var pos = 0;
  var filter = 'all';
  var pendingStep = null;
  var autoFollow = document.body.getAttribute('data-follow') === '1';
  var followTimer = null;
  var polling = false;
  var FILTERS = [
    ['all', 'Everything', function () { return true; }],
    ['gate', 'Gate decisions', function (s) { return s.kind === 'gate'; }],
    ['approvals', 'Approvals', function (s) { return s.kind === 'approval'; }],
    ['taint', 'Taint', function (s) { return s.kind === 'taint'; }],
    ['files', 'File changes', function (s, i, all) { return s.diff !== undefined || (i > 0 && s.state.filesChanged > all[i - 1].state.filesChanged); }],
    ['commands', 'Commands', function (s) { return s.kind === 'call' && /^The model asked for (bash|pwsh)/.test(s.title); }],
    ['refused', 'Refusals', function (s) { return s.tone === 'refused'; }]
  ];

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function get(path) {
    return fetch(path, { credentials: 'same-origin' }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error(t || ('HTTP ' + r.status)); });
      return r.json();
    });
  }

  function loadList(wanted) {
    return get('/replay/api/sessions').then(function (data) {
      var select = $('session');
      clear(select);
      var none = el('option', '', data.sessions.length === 0 ? 'No sessions recorded in this folder' : 'Choose a session');
      none.value = '';
      select.appendChild(none);
      data.sessions.forEach(function (s) {
        var o = el('option', '', s.id + '  (' + s.modified.replace('T', ' ').slice(0, 19) + ')');
        o.value = s.id;
        select.appendChild(o);
      });
      $('count').textContent = data.sessions.length + ' recorded';
      if (wanted && SESSION_ID.test(wanted)) { select.value = wanted; openSession(wanted); }
      else if (autoFollow && data.sessions.length > 0) { select.value = data.sessions[0].id; openSession(data.sessions[0].id); }
    });
  }

  // Everything of a previous session goes, before anything of the next one is shown, so a refused log can never sit beside another's steps.
  function wipe() {
    replay = null; visible = []; pos = 0;
    $('live').textContent = '';
    ['summary', 'timeline', 'detail', 'state', 'filters'].forEach(function (name) { clear($(name)); });
    $('position').textContent = '';
    $('controls').hidden = true; $('layout').hidden = true;
  }

  function openSession(id) {
    wipe();
    if (!SESSION_ID.test(id)) return;
    var box = $('integrity');
    box.className = ''; box.textContent = 'Checking the log...';
    get('/replay/api/session/' + encodeURIComponent(id)).then(function (data) {
      replay = data;
      // Opened to follow a live session: start at the newest step, and stay with it as more arrive.
      if (autoFollow && replay.trust === 'verified' && pendingStep === null) pendingStep = Math.max(0, replay.steps.length - 1);
      render();
      if (autoFollow && replay.trust === 'verified') startFollow();
    }).catch(function (error) {
      replay = null;
      box.className = 'refused'; box.textContent = 'Could not open this session: ' + error.message;
    });
  }

  function stat(label, value) {
    var s = el('span');
    s.appendChild(document.createTextNode(label + ' '));
    s.appendChild(el('b', '', String(value)));
    return s;
  }

  function render() {
    var verified = replay.trust === 'verified';
    header();
    if (!verified) return;
    buildFilters();
    $('controls').hidden = false; $('layout').hidden = false;
    pos = 0; setFilter('all', pendingStep === null ? 0 : pendingStep);
    pendingStep = null;
  }

  // The verdict and the totals. Called again each time a followed log grows, so the verdict is always about everything shown.
  function header() {
    var box = $('integrity');
    clear(box);
    var summary = $('summary');
    clear(summary);
    if (replay.trust !== 'verified') {
      box.className = 'refused';
      box.appendChild(el('strong', '', 'REFUSED: this log does not verify'));
      box.appendChild(document.createTextNode(replay.reason || ''));
      wipe();
      stopFollow();
      return;
    }
    box.className = 'verified';
    box.appendChild(el('strong', '', 'Log verified'));
    var note = 'The HMAC chain over all ' + replay.events + ' recorded events checks out, so nothing was edited, removed, reordered or added without the key.';
    if (replay.crashed) note += followTimer === null ? ' The file ends part-way through its last record, as a crash leaves it; what is shown is what verified.' : ' The last record is still being written; what is shown is what verified.';
    box.appendChild(document.createTextNode(note));
    var t = replay.totals;
    summary.appendChild(stat('Started', replay.createdAt || 'unknown'));
    summary.appendChild(stat('Turns', t.turns));
    summary.appendChild(stat('Tool calls', t.calls));
    summary.appendChild(stat('Refused by the gate', t.refused));
    summary.appendChild(stat('Approvals asked', t.approvalsAsked + ' (' + t.approvalsDenied + ' denied)'));
    summary.appendChild(stat('Files changed', t.files.length === 0 ? 'none' : t.files.join(', ')));
    summary.appendChild(stat('Untrusted input', t.untrustedAt === null ? 'never entered' : 'entered at step ' + (t.untrustedAt + 1)));
    var hiddenCount = Object.keys(replay.hidden).reduce(function (n, k) { return n + replay.hidden[k]; }, 0);
    if (hiddenCount > 0) summary.appendChild(stat('Bookkeeping events not shown', hiddenCount));
    if (replay.truncated) summary.appendChild(stat('Shown', 'the first ' + replay.shownSteps + ' steps only'));
  }

  function stopFollow() {
    if (followTimer !== null) { clearInterval(followTimer); followTimer = null; }
    $('follow').checked = false;
  }
  function startFollow() {
    if (followTimer !== null) return;
    followTimer = setInterval(poll, 1500);
    $('follow').checked = true;
  }
  // Asks only for what is new. The server verifies the whole log again each time and refuses if any of it changed.
  function poll() {
    if (polling || replay === null || replay.trust !== 'verified' || !replay.follow) return;
    polling = true;
    var id = replay.sessionId;
    var f = replay.follow;
    get('/replay/api/session/' + encodeURIComponent(id) + '?since=' + f.since + '&size=' + f.size + '&prefix=' + f.prefix).then(function (data) {
      polling = false;
      if (replay === null || replay.sessionId !== id || data.unchanged) return;
      if (data.trust !== 'verified') { replay = data; render(); return; }
      var atEnd = visible.length === 0 || pos === visible.length - 1;
      var keep = currentIndex();
      replay.steps = replay.steps.concat(data.steps);
      ['events', 'crashed', 'hidden', 'totals', 'shownSteps', 'truncated', 'follow'].forEach(function (k) { replay[k] = data[k]; });
      header();
      buildFilters();
      setFilter(filter, atEnd ? replay.steps.length : keep);
      $('live').textContent = data.steps.length === 0 ? '' : (atEnd ? 'Live: ' : 'Live: ' + data.steps.length + ' new step(s) added at the end, ') + replay.steps.length + ' steps';
    }).catch(function () { polling = false; });
  }

  function buildFilters() {
    var group = $('filters');
    clear(group);
    FILTERS.forEach(function (f) {
      var count = replay.steps.filter(function (s, i, all) { return f[2](s, i, all); }).length;
      var b = el('button', '', f[1] + ' (' + count + ')');
      b.type = 'button';
      b.setAttribute('data-filter', f[0]);
      b.addEventListener('click', function () { setFilter(f[0], currentIndex()); });
      group.appendChild(b);
    });
  }

  function currentIndex() { return visible.length === 0 ? 0 : visible[pos]; }

  function setFilter(name, keepIndex) {
    filter = name;
    var f = FILTERS.filter(function (x) { return x[0] === name; })[0];
    visible = [];
    replay.steps.forEach(function (s, i, all) { if (f[2](s, i, all)) visible.push(i); });
    Array.prototype.forEach.call($('filters').children, function (b) {
      b.setAttribute('aria-pressed', b.getAttribute('data-filter') === name ? 'true' : 'false');
    });
    var timeline = $('timeline');
    clear(timeline);
    visible.forEach(function (index, at) {
      var s = replay.steps[index];
      var li = el('li', s.tone);
      li.tabIndex = 0;
      li.appendChild(el('span', 'n', String(index + 1)));
      li.appendChild(document.createTextNode((s.tone === 'refused' ? 'REFUSED - ' : '') + s.title));
      li.addEventListener('click', function () { select(at); });
      timeline.appendChild(li);
    });
    $('scrubber').max = String(Math.max(0, visible.length - 1));
    var at = 0;
    for (var k = 0; k < visible.length; k += 1) { if (visible[k] >= keepIndex) { at = k; break; } at = k; }
    select(at);
  }

  function select(at) {
    if (visible.length === 0) {
      pos = 0; clear($('detail')); clear($('state'));
      $('detail').appendChild(el('p', '', 'No steps match this filter.'));
      $('position').textContent = '0 / 0';
      return;
    }
    pos = Math.max(0, Math.min(visible.length - 1, at));
    var step = replay.steps[visible[pos]];
    $('scrubber').value = String(pos);
    $('position').textContent = (pos + 1) + ' / ' + visible.length;
    Array.prototype.forEach.call($('timeline').children, function (li, i) {
      if (i === pos) { li.setAttribute('aria-current', 'step'); li.scrollIntoView({ block: 'nearest' }); } else li.removeAttribute('aria-current');
    });
    showDetail(step);
    showState(step);
    try { history.replaceState(null, '', '#' + replay.sessionId + ':' + step.index); } catch (e) { /* a page with no history is still usable */ }
  }

  function showDetail(step) {
    var d = $('detail');
    clear(d);
    d.appendChild(el('span', 'badge ' + step.tone, step.tone === 'refused' ? 'REFUSED' : step.tone === 'warn' ? 'WARNING' : step.tone === 'ok' ? 'OK' : step.kind));
    d.appendChild(el('h2', '', step.title));
    d.appendChild(el('div', 'meta', 'Step ' + (step.index + 1) + ' of ' + replay.steps.length + ', log event ' + step.seq + ', ' + step.ts + ', origin: ' + step.origin));
    if (step.detail !== undefined) {
      d.appendChild(el('pre', '', step.detail));
      if (step.detailCut) d.appendChild(el('div', 'meta', 'This text was cut for display.'));
    }
    if (step.diff !== undefined) d.appendChild(diffBlock(step.diff));
    if (step.callId) {
      var related = replay.steps.filter(function (s) { return s.callId === step.callId && s.index !== step.index; });
      if (related.length > 0) {
        d.appendChild(el('div', 'meta', 'Everything that happened to this call:'));
        var wrap = el('div', 'related');
        related.forEach(function (s) {
          var b = el('button', '', s.index + 1 + ': ' + s.title.slice(0, 60));
          b.type = 'button';
          b.addEventListener('click', function () {
            var at = visible.indexOf(s.index);
            if (at < 0) { setFilter('all', s.index); } else select(at);
          });
          wrap.appendChild(b);
        });
        d.appendChild(wrap);
      }
    }
  }

  function diffBlock(diff) {
    var wrap = el('div', 'diff');
    wrap.appendChild(el('div', 'head', (diff.kind === 'edit' ? 'Edit to ' : 'New contents of ') + diff.path));
    var lines = 0;
    function lineSet(text, cls, mark) {
      text.split('\n').forEach(function (line) {
        if (lines === MAX_DIFF_LINES) wrap.appendChild(el('div', 'head', '... more lines not shown'));
        lines += 1;
        if (lines > MAX_DIFF_LINES) return;
        wrap.appendChild(el('div', cls, mark + ' ' + line));
      });
    }
    if (diff.before !== null) lineSet(diff.before, 'del', '-');
    lineSet(diff.after, 'add', '+');
    if (diff.kind === 'write') wrap.appendChild(el('div', 'head', 'What the file held before was not recorded in the log.'));
    if (diff.cut) wrap.appendChild(el('div', 'head', 'Cut for display.'));
    return wrap;
  }

  function row(dl, label, value, cls) {
    dl.appendChild(el('dt', '', label));
    dl.appendChild(el('dd', cls || '', value));
  }

  function showState(step) {
    var s = step.state;
    var box = $('state');
    clear(box);
    box.appendChild(el('h3', '', 'The session as it stood after this step'));
    var dl = el('dl');
    row(dl, 'Untrusted input in the session', s.untrusted ? 'YES' : 'no', s.untrusted ? 'yes' : 'no');
    row(dl, 'Private data in reach', s.private ? 'yes' : 'no');
    row(dl, 'Reached outside', s.external ? 'yes' : 'no');
    row(dl, 'Mode', s.mode === null ? 'not changed so far' : s.mode);
    row(dl, 'Where it runs', s.box === null ? 'not recorded yet' : s.box);
    row(dl, 'Tool calls so far', String(s.calls));
    row(dl, 'Refused by the gate so far', String(s.refused));
    row(dl, 'Approvals asked / denied', s.approvalsAsked + ' / ' + s.approvalsDenied);
    row(dl, 'Files changed so far', String(s.filesChanged));
    box.appendChild(dl);
  }

  function jump(test) {
    for (var i = pos + 1; i < visible.length; i += 1) { if (test(replay.steps[visible[i]])) { select(i); return; } }
  }

  $('follow').addEventListener('change', function (e) { if (e.target.checked) startFollow(); else stopFollow(); });
  $('session').addEventListener('change', function (e) { var id = e.target.value; if (id) openSession(id); });
  $('first').addEventListener('click', function () { select(0); });
  $('prev').addEventListener('click', function () { select(pos - 1); });
  $('next').addEventListener('click', function () { select(pos + 1); });
  $('last').addEventListener('click', function () { select(visible.length - 1); });
  $('next-refusal').addEventListener('click', function () { jump(function (s) { return s.tone === 'refused'; }); });
  $('next-taint').addEventListener('click', function () { jump(function (s) { return s.kind === 'taint'; }); });
  $('scrubber').addEventListener('input', function (e) { select(Number(e.target.value)); });
  document.addEventListener('keydown', function (e) {
    if (replay === null || replay.trust !== 'verified') return;
    var t = e.target && e.target.tagName;
    if (t === 'INPUT' || t === 'SELECT' || t === 'TEXTAREA') return;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown' || e.key === 'j') { e.preventDefault(); select(pos + 1); }
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp' || e.key === 'k') { e.preventDefault(); select(pos - 1); }
    else if (e.key === 'Home') { e.preventDefault(); select(0); }
    else if (e.key === 'End') { e.preventDefault(); select(visible.length - 1); }
  });

  var hash = (location.hash || '').replace(/^#/, '').split(':');
  var wanted = hash[0];
  var asked = Number(hash[1]);
  if (hash[1] !== undefined && Number.isInteger(asked) && asked >= 0) pendingStep = asked;
  loadList(wanted).catch(function (error) { $('integrity').textContent = 'Could not list sessions: ' + error.message; });
})();`;
