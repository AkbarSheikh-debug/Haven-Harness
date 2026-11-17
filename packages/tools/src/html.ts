/**
 * HTML to readable text, in one pass over the input. A regular expression with a lazy gap would be quadratic on a
 * page made of thousands of unclosed tags, which is a way to hang the harness, so this walks the text once and
 * only ever moves forward.
 */

const SKIPPED = new Set(['script', 'style', 'noscript', 'svg', 'template', 'iframe', 'object', 'embed', 'head']);
const BLOCK = new Set(['p', 'div', 'br', 'tr', 'section', 'article', 'header', 'footer', 'nav', 'main', 'aside', 'ul', 'ol', 'table', 'pre', 'blockquote', 'form', 'dl', 'dt', 'dd', 'hr', 'figure']);
const HEADING = /^h[1-6]$/;
const NAMED: Readonly<Record<string, string>> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', copy: '(c)', mdash: '-', ndash: '-', hellip: '...' };
const MAX_LINK_CHARS = 200;

function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z]{2,8});/gi, (whole, body: string) => {
    if (body[0] === '#') {
      const code = body[1]?.toLowerCase() === 'x' ? Number.parseInt(body.slice(2), 16) : Number.parseInt(body.slice(1), 10);
      return code > 0 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff) ? String.fromCodePoint(code) : '';
    }
    return NAMED[body.toLowerCase()] ?? whole;
  });
}

export function htmlToText(html: string): string {
  const lower = html.toLowerCase();
  let out = '';
  let at = 0;
  let link: string | null = null;

  while (at < html.length) {
    const open = html.indexOf('<', at);
    if (open === -1) {
      out += html.slice(at);
      break;
    }
    out += html.slice(at, open);
    if (html.startsWith('<!--', open)) {
      const end = html.indexOf('-->', open + 4);
      if (end === -1) break;
      at = end + 3;
      continue;
    }
    const close = html.indexOf('>', open + 1);
    if (close === -1) {
      // A "<" with no ">" after it is text, not a tag.
      out += html.slice(open);
      break;
    }
    const tag = lower.slice(open + 1, close);
    const closing = tag.startsWith('/');
    const name = /^\/?\s*([a-z][a-z0-9]*)/.exec(tag)?.[1] ?? '';
    at = close + 1;
    if (name === '') {
      // `<!doctype>`, `<?xml?>` and stray angle brackets.
      continue;
    }
    if (!closing && SKIPPED.has(name)) {
      if (name === 'head') {
        const end = lower.indexOf('</head', at);
        const inner = html.slice(at, end === -1 ? html.length : end);
        const title = /<title[^>]*>([^<]*)/i.exec(inner)?.[1];
        if (title !== undefined && title.trim() !== '') out += `\n# ${title.trim()}\n`;
        at = end === -1 ? html.length : html.indexOf('>', end) + 1 || html.length;
      } else {
        const end = lower.indexOf(`</${name}`, at);
        at = end === -1 ? html.length : html.indexOf('>', end) + 1 || html.length;
      }
      continue;
    }
    if (name === 'a') {
      if (closing) {
        if (link !== null) out += ` <${link}>`;
        link = null;
      } else {
        const href = /href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(html.slice(open, close))?.slice(1).find((part) => part !== undefined);
        link = href !== undefined && /^https?:\/\//i.test(href.trim()) && href.length <= MAX_LINK_CHARS ? decodeEntities(href.trim()) : null;
      }
      continue;
    }
    if (name === 'li') {
      // Only the opening tag starts a line, so list items stay together.
      if (!closing) out += '\n- ';
    } else if (HEADING.test(name) && !closing) out += '\n\n## ';
    else if (BLOCK.has(name) || HEADING.test(name)) out += '\n';
  }

  return decodeEntities(out)
    .replace(/[ \t\f\v ]+/g, ' ')
    .replace(/ ?\n ?/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}
