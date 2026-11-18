#!/usr/bin/env node
// Checks that the encryption code europe.social delivers to browsers is exactly the file in this repository.
// Usage: node tools/check-live.mjs   (Node 18 or newer, no dependencies)
//
// It loads the start page the way a browser does, takes the address of dmcrypto.js from it, downloads that file and
// compares its SHA-256 with public/javascripts/dmcrypto.js here. The page links the file as dmcrypto.js?v=<first 12
// hex digits of its SHA-256>, so the check also confirms that the version marker matches the content.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const SEITE = process.env.EUROPE_SOCIAL_URL || 'https://europe.social/';
const sha = b => createHash('sha256').update(b).digest('hex');
const hier = sha(readFileSync(new URL('../public/javascripts/dmcrypto.js', import.meta.url)));

const html = await (await fetch(SEITE, { headers: { 'user-agent': 'europe-social-dm check-live' } })).text();
const m = html.match(/src="(\/javascripts\/dmcrypto\.js\?v=([0-9a-f]+))"/);
if (!m) { console.error(`No dmcrypto.js found on ${SEITE}`); process.exit(2); }
const antwort = await fetch(new URL(m[1], SEITE), { headers: { 'user-agent': 'europe-social-dm check-live' } });
const live = sha(Buffer.from(await antwort.arrayBuffer()));

console.log(`repository: ${hier}`);
console.log(`delivered:  ${live}  (${new URL(m[1], SEITE)})`);
const marke = live.startsWith(m[2]);
if (!marke) console.log(`version marker ?v=${m[2]} does not match the delivered content`);
if (live === hier && marke) { console.log('OK: the delivered file is identical to this repository.'); process.exit(0); }
console.log('DIFFERENT: the delivered file is not the one in this repository (or this checkout is not up to date: git pull).');
process.exit(1);
