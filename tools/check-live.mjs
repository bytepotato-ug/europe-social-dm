#!/usr/bin/env node
// Checks that the encryption code europe.social delivers to browsers is exactly the file in this repository.
// Usage: node tools/check-live.mjs   (Node 18 or newer, no dependencies)
//
// It loads the start page the way a browser does, takes the address of dmcrypto.js from it, downloads that file and
// compares its SHA-256 with public/javascripts/dmcrypto.js here. The page links the file as dmcrypto.js?v=<first 12
// hex digits of its SHA-256>, so the check also confirms that the version marker matches the content.
//
// What this does and does not show: it covers this one file, as delivered to the machine it runs on at this moment.
// The rest of the web client (the page and its other scripts, which hold the key and show the text) is not public and
// not covered. A server that wanted to cheat could also answer this script differently from a browser; it sends an
// ordinary browser's request headers so that is not trivial, but a determined server can tell. Run it from your own
// network if you want your own answer. See PROTOCOL.md, section 9.2.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const SEITE = process.env.EUROPE_SOCIAL_URL || 'https://europe.social/';
const sha = b => createHash('sha256').update(b).digest('hex');
const hier = sha(readFileSync(new URL('../public/javascripts/dmcrypto.js', import.meta.url)));

// The same headers a current Firefox sends for a page it navigates to
const KOPF = {
  'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0',
  accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'accept-language': 'en-US,en;q=0.5',
};
const html = await (await fetch(SEITE, { headers: KOPF })).text();
const m = html.match(/src="(\/javascripts\/dmcrypto\.js\?v=([0-9a-f]+))"/);
if (!m) { console.error(`No dmcrypto.js found on ${SEITE}`); process.exit(2); }
const antwort = await fetch(new URL(m[1], SEITE), { headers: { ...KOPF, accept: '*/*', referer: SEITE } });
const live = sha(Buffer.from(await antwort.arrayBuffer()));

console.log(`repository: ${hier}`);
console.log(`delivered:  ${live}  (${new URL(m[1], SEITE)})`);
const marke = live.startsWith(m[2]);
if (!marke) console.log(`version marker ?v=${m[2]} does not match the delivered content`);
if (live === hier && marke) { console.log('OK: the delivered file is identical to this repository.'); process.exit(0); }
console.log('DIFFERENT: the delivered file is not the one in this repository (or this checkout is not up to date: git pull).');
process.exit(1);
