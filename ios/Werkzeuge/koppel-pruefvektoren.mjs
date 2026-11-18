// Prüfvektoren für „Gerät koppeln“ (KOPPELN.md), erzeugt mit public/javascripts/dmcrypto.js, der Referenz.
//   node ios/Werkzeuge/koppel-pruefvektoren.mjs
// Schreibt ios/EuropeKit/Tests/EuropeKitTests/Daten/koppeln.json. iOS (KoppelnTests) und Android (KoppelnTest) müssen
// Fingerabdruck, Commitment (seit 2026-11-16) und Prüfzahl gleich rechnen und das Chiffrat öffnen. Nur Testschlüssel, frisch erzeugt.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dmc = require('../../public/javascripts/dmcrypto.js');
const HIER = path.dirname(new URL(import.meta.url).pathname);
const ZIEL = path.join(HIER, '..', 'EuropeKit', 'Tests', 'EuropeKitTests', 'Daten', 'koppeln.json');
const sub = globalThis.crypto.subtle;
const pkcs8 = async k => dmc.b64u(new Uint8Array(await sub.exportKey('pkcs8', k)));

const uid = 7, id = 'AbCdEfGhIjKlMnOpQrStUv';
const dm = await dmc.neuesPaar(), eN = await dmc.neuesPaar(), eA = await dmc.neuesPaar(), nonce = dmc.kopplungNonce();
const wrapped = await dmc.kopplungEinpacken(dm.privat, eA.privat, eN.oeffentlich, eA.oeffentlich, uid, id);
// Gegenprobe in Node, bevor die Datei geschrieben wird
const zurueck = await dmc.kopplungAuspacken(wrapped, eN.privat, eN.oeffentlich, eA.oeffentlich, uid, id);
if (await dmc.oeffentlichVon(zurueck) !== dm.oeffentlich) throw new Error('Gegenprobe gescheitert');
const daten = {
  hinweis: 'Erzeugt von ios/Werkzeuge/koppel-pruefvektoren.mjs mit public/javascripts/dmcrypto.js. Nur Testschlüssel.',
  uid, id,
  dm: { privat: await pkcs8(dm.privat), oeffentlich: dm.oeffentlich },
  neu: { privat: await pkcs8(eN.privat), oeffentlich: eN.oeffentlich },
  alt: { privat: await pkcs8(eA.privat), oeffentlich: eA.oeffentlich },
  fingerabdruck: await dmc.kopplungFp(eN.oeffentlich),
  nonce,
  commit: await dmc.kopplungCommit(eN.oeffentlich, nonce),
  pruefzahl: await dmc.kopplungZahl(eN.oeffentlich, eA.oeffentlich),
  wrapped,
};
fs.writeFileSync(ZIEL, JSON.stringify(daten, null, 1) + '\n');
console.log('geschrieben:', path.relative(process.cwd(), ZIEL), 'Prüfzahl', daten.pruefzahl, 'Fingerabdruck', daten.fingerabdruck);
