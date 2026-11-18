// Prüfvektoren für die Direktnachrichten der iOS-App: erzeugt mit genau dem Code, den der Browser benutzt
// (public/javascripts/dmcrypto.js). Die Swift-Tests (EuropeKit, DmKryptoTests) müssen sie öffnen können.
//   node ios/Werkzeuge/dm-pruefvektoren.mjs           schreibt die Vektoren neu
//   node ios/Werkzeuge/dm-pruefvektoren.mjs --pruefen <datei>   öffnet, was Swift verschlüsselt hat (Gegenrichtung)
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const HIER = path.dirname(new URL(import.meta.url).pathname);
const dm = require(path.join(HIER, '..', '..', 'public', 'javascripts', 'dmcrypto.js'));
const ZIEL = path.join(HIER, '..', 'EuropeKit', 'Tests', 'EuropeKitTests', 'Daten', 'dm.json');
const sub = globalThis.crypto.subtle;
const pkcs8 = async k => dm.b64u(await sub.exportKey('pkcs8', k));
const importPrivat = async b => sub.importKey('pkcs8', dm.unb64u(b), { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);

if (process.argv[2] === '--pruefen') {
  // Gegenrichtung: Swift hat mit den Schlüsseln aus dm.json verschlüsselt, Node muss es öffnen
  const v = JSON.parse(fs.readFileSync(ZIEL, 'utf8'));
  const s = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
  const bob = await importPrivat(v.bob.privat);
  const r = await dm.entschluesseln(s.umschlag, { ich: v.bob.id, sid: v.ada.id, rid: v.bob.id, privat: bob });
  if (r.text !== s.text) throw new Error(`Text weicht ab: ${r.text}`);
  if (s.bild) {
    const daten = await r.bild(dm.unb64u(s.bild.chiffrat), r.anhaenge[0]);
    if (dm.b64u(daten) !== s.bild.klar) throw new Error('Bild weicht ab');
  }
  if (s.reaktion) {
    const e = await dm.reaktionEntschluesseln(s.reaktion.umschlag, { ich: v.bob.id, mid: s.reaktion.mid, sid: v.ada.id, konv: s.reaktion.konv, privat: bob });
    if (e.emoji !== s.reaktion.emoji) throw new Error('Reaktion weicht ab');
  }
  console.log('Swift → Browser: alles lesbar');
  process.exit(0);
}

const ada = await dm.neuesPaar(), bob = await dm.neuesPaar(), cleo = await dm.neuesPaar();
const A = 2, Bn = 3, C = 4;
const v1 = await dm.verschluesseln({ text: 'Hallo Bob 👋', sid: A, rid: Bn, senderPrivat: ada.privat, senderPub: ada.oeffentlich, empfPub: bob.oeffentlich });
// v2 mit Bild und Zitat
const k = await dm.inhaltsSchluessel();
const bildKlar = new TextEncoder().encode('kein echtes Bild, aber Bytes');
const bild = await dm.bildVerschluesseln(k, bildKlar, A, Bn);
const v2 = await dm.verschluesseln({ text: 'Mit Bild', sid: A, rid: Bn, senderPrivat: ada.privat, senderPub: ada.oeffentlich, empfPub: bob.oeffentlich,
  schluessel: k, anhaenge: [{ id: 'AAAAAAAAAAAAAAAAAAAAAA', n: bild.n, typ: 'image/jpeg', b: 800, h: 600, alt: 'Ein Hafen' }], zitat: { id: 7, von: Bn, t: 'Vorher', bild: false } });
// Gruppe g9 mit drei Mitgliedern
const g = await dm.verschluesseln({ text: 'An alle', sid: A, rid: 'g9', senderPrivat: ada.privat, senderPub: ada.oeffentlich, empfaenger: { [Bn]: bob.oeffentlich, [C]: cleo.oeffentlich } });
// Gruppenname (Ada versiegelt für Bob und Cleo), mit Umlauten und Emoji
const gruppenName = 'Café Größe Ärger 🍻';
const gn = await dm.gruppenNameVerschluesseln({ name: gruppenName, sid: A, senderPrivat: ada.privat, senderPub: ada.oeffentlich, empfaenger: { [Bn]: bob.oeffentlich, [C]: cleo.oeffentlich } });
// Reaktion von Bob auf Nachricht 42 in der Unterhaltung p2-3
const rx = await dm.reaktionVerschluesseln({ emoji: '❤️', mid: 42, sid: Bn, konv: 'p2-3', senderPrivat: bob.privat, senderPub: bob.oeffentlich, empfaenger: { [A]: ada.oeffentlich } });
// Eingepackter Schlüssel (PRF fest)
const prf = new Uint8Array(32).map((_, i) => i);
const gepackt = await dm.einpacken(ada.privat, prf, A, 'cred-ada');
// Bindung (seit 2026-11-19): Bob kennt als Empfänger den Inhaltsschlüssel der Gruppennachricht und legt anderen Text
// unter Adas Hüllen. Mit Bindung (Feld t) muss das bei Cleo scheitern; ohne t (ältere Fassungen) geht der Umschlag noch auf
// und gilt als nicht gebunden. Dazu die v1-Nachricht ohne t, so wie ältere Fassungen sie schicken.
const ohneT = text => { const u = JSON.parse(text); for (const z of Object.keys(u.k)) delete u.k[z].t; return JSON.stringify(u); };
const bobPrivat = await importPrivat(await pkcs8(bob.privat));
const echt = await dm.entschluesseln(g, { ich: Bn, sid: A, rid: 'g9', privat: bobPrivat });
const kGruppe = await sub.importKey('raw', echt.schluesselRoh, 'AES-GCM', false, ['encrypt']);
const ug = JSON.parse(g), ivF = globalThis.crypto.getRandomValues(new Uint8Array(12));
const cF = await sub.encrypt({ name: 'AES-GCM', iv: ivF, additionalData: new TextEncoder().encode('cs-dm-v1|' + A + '|g9|' + ug.s) }, kGruppe, new TextEncoder().encode('Nicht von Ada'));
const gefaelscht = JSON.stringify({ ...ug, n: dm.b64u(ivF), c: dm.b64u(cF) });
// Wiederherstellungscode: fester Code (Bytes 0…19) und ein mit ihm eingepackter Schlüssel
const codeRoh = new Uint8Array(20).map((_, i) => i * 13 + 7);
const codeGepackt = await dm.codeEinpacken(ada.privat, codeRoh, A);

const vektoren = {
  hinweis: 'Erzeugt von ios/Werkzeuge/dm-pruefvektoren.mjs mit public/javascripts/dmcrypto.js. Nur Testschlüssel.',
  ada: { id: A, privat: await pkcs8(ada.privat), oeffentlich: ada.oeffentlich },
  bob: { id: Bn, privat: await pkcs8(bob.privat), oeffentlich: bob.oeffentlich },
  cleo: { id: C, privat: await pkcs8(cleo.privat), oeffentlich: cleo.oeffentlich },
  v1: { umschlag: v1, text: 'Hallo Bob 👋' },
  v2: { umschlag: v2, text: 'Mit Bild', bildChiffrat: dm.b64u(bild.daten), bildKlar: dm.b64u(bildKlar) },
  gruppe: { umschlag: g, rid: 'g9', text: 'An alle' },
  bindung: { ohne: ohneT(v1), gefaelscht, gefaelschtOhne: ohneT(gefaelscht), gefaelschtText: 'Nicht von Ada' },
  gruppenname: { umschlag: gn, von: A, name: gruppenName },
  reaktion: { umschlag: rx, mid: 42, sid: Bn, konv: 'p2-3', emoji: '❤️' },
  einpacken: { prf: dm.b64u(prf), uid: A, credId: 'cred-ada', gepackt },
  code: { roh: dm.b64u(codeRoh), code: dm.codeText(codeRoh), uid: A, gepackt: codeGepackt },
  sicherheitsnummer: await dm.sicherheitsnummer(ada.oeffentlich, bob.oeffentlich),
  fingerabdruck: await dm.fingerabdruck(ada.oeffentlich),
};
fs.writeFileSync(ZIEL, JSON.stringify(vektoren, null, 1) + '\n');
console.log('geschrieben:', path.relative(process.cwd(), ZIEL));
