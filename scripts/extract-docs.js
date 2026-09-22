/* ══════════════════════════════════════════════════════════════════
   Extracts the step-by-step guide and the FAQ from src/app.js and
   converts them to Markdown.

   Why extract instead of rewriting: this way the documents stay
   aligned with the text the user actually sees inside the app.

   Usage:  node scripts/extract-docs.js
   ══════════════════════════════════════════════════════════════════ */
const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..', 'src', 'app.js');
const OUT = path.join(__dirname, '..', 'docs');
const src = fs.readFileSync(SRC, 'utf-8');

/* Extracts the body of a function returning an HTML template */
function fnBody(name) {
  const start = src.indexOf(`function ${name}()`);
  if (start < 0) throw new Error(`function not found: ${name}`);
  const open = src.indexOf('`', start);
  let i = open + 1, depth = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === '\\') { i += 2; continue; }
    if (c === '$' && src[i + 1] === '{') { depth++; i += 2; continue; }
    if (c === '}' && depth > 0) { depth--; i++; continue; }
    if (c === '`' && depth === 0) break;
    i++;
  }
  return src.slice(open + 1, i);
}

/* Replaces ${...} placeholders with a readable value */
function stripPlaceholders(html) {
  return html.replace(/\$\{[^}]*\}/g, (m) => {
    // known cases appearing in the guide texts
    if (m.includes('r.m')) return 'M';
    if (m.includes('r.n')) return 'N';
    if (m.includes('nWords') || m.includes('words.length')) return '12';
    return '';
  });
}

const ENT = {
  '&middot;': '·', '&mdash;': '—', '&ndash;': '–', '&rarr;': '→',
  '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&nbsp;': ' ',
};
function decode(t) {
  return t.replace(/&[a-z]+;/g, (e) => ENT[e] !== undefined ? ENT[e] : e);
}

/* Converts an inline HTML fragment to Markdown */
function inline(t) {
  return decode(
    t.replace(/<strong>(.*?)<\/strong>/gs, '**$1**')
     .replace(/<b>(.*?)<\/b>/gs, '**$1**')
     .replace(/<em>(.*?)<\/em>/gs, '*$1*')
     .replace(/<i>(.*?)<\/i>/gs, '*$1*')
     .replace(/<code>(.*?)<\/code>/gs, '`$1`')
     .replace(/<br\s*\/?>/g, '\n')
     .replace(/<[^>]+>/g, '')
  ).replace(/[ \t]+/g, ' ').trim();
}

/* ── Step-by-step guide ──
   Walks every card in order of appearance, so the document follows
   the real sequence instead of grouping by type. */
function buildGuide() {
  const html = stripPlaceholders(fnBody('renderGuideSteps'));
  const out = ['# AmnesicWallet — Step-by-step guide', ''];

  const BLOCKS = new RegExp([
    '<h2>(?<h2>.*?)<\\/h2>',
    '<p class="hint"[^>]*>(?<hint>.*?)<\\/p>',
    '<p[^>]*>(?<p>.*?)<\\/p>',
    '<span class="sl-n">(?<n>.*?)<\\/span><span class="sl-t">(?<t>.*?)<\\/span>',
    '<code class="pd-full">(?<full>.*?)<\\/code>',
    '<div class="pd-row"><code>(?<k>.*?)<\\/code><span>(?<v>.*?)<\\/span><\\/div>',
    '<div class="note-box"[^>]*>(?<note>.*?)<\\/div>',
  ].join('|'), 'gs');

  const cards = html.split('<div class="card">').slice(1);
  for (const card of cards) {
    let inList = false;
    for (const m of card.matchAll(BLOCKS)) {
      const g = m.groups;
      if (g.k === undefined && inList) { out.push(''); inList = false; }

      if (g.h2 !== undefined) out.push(`## ${inline(g.h2)}`, '');
      else if (g.full !== undefined) out.push('```', inline(g.full), '```', '');
      else if (g.k !== undefined) { out.push(`- \`${inline(g.k)}\` — ${inline(g.v)}`); inList = true; }
      else if (g.n !== undefined) out.push(`**${inline(g.n)}.** ${inline(g.t)}`, '');
      else if (g.note !== undefined) { const t = inline(g.note); if (t) out.push(`> ${t}`, ''); }
      else { const t = inline(g.hint !== undefined ? g.hint : g.p); if (t) out.push(t, ''); }
    }
    if (inList) out.push('');
    out.push('---', '');
  }
  return out.join('\n').replace(/\n{3,}/g, '\n\n');
}

/* ── FAQ ── */
function buildFaq() {
  const html = stripPlaceholders(fnBody('renderGuideFaq'));
  const out = ['# AmnesicWallet — Frequently asked questions', ''];

  for (const d of html.matchAll(/<summary>(.*?)<\/summary><div class="faq-body">(.*?)<\/div><\/details>/gs)) {
    out.push(`## ${inline(d[1])}`, '');
    for (const p of d[2].matchAll(/<p[^>]*>(.*?)<\/p>/gs)) {
      const t = inline(p[1]);
      if (t) out.push(t, '');
    }
    out.push('---', '');
  }
  return out.join('\n').replace(/\n{3,}/g, '\n\n');
}

fs.mkdirSync(OUT, { recursive: true });
const g = buildGuide();
const f = buildFaq();
fs.writeFileSync(path.join(OUT, 'STEP-BY-STEP.md'), g);
fs.writeFileSync(path.join(OUT, 'FAQ.md'), f);

const nCap = (g.match(/^## /gm) || []).length;
const nFaq = (f.match(/^## /gm) || []).length;
console.log(`Guide: ${nCap} chapters, ${g.length} characters`);
console.log(`FAQ:   ${nFaq} entries, ${f.length} characters`);
