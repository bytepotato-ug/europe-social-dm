// Tests für den Web-Code (public/javascripts/dmcrypto.js), nur node:test, ohne Abhängigkeiten.
// Dieselben Prüfvektoren lesen auch die Swift- und Kotlin-Tests; alle drei müssen dasselbe rechnen.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dm = require('../public/javascripts/dmcrypto.js');
const sub = globalThis.crypto.subtle;
const DATEN = new URL('../ios/EuropeKit/Tests/EuropeKitTests/Daten/', import.meta.url);
const v = JSON.parse(fs.readFileSync(new URL('dm.json', DATEN), 'utf8'));
const kv = JSON.parse(fs.readFileSync(new URL('koppeln.json', DATEN), 'utf8'));
const privat = b => sub.importKey('pkcs8', dm.unb64u(b), { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);

test('Nachricht aus den Vektoren: Empfänger und Absender können lesen, Dritte und falscher Kontext nicht', async () => {
  const bob = await privat(v.bob.privat), ada = await privat(v.ada.privat), cleo = await privat(v.cleo.privat);
  const r = await dm.entschluesseln(v.v1.umschlag, { ich: v.bob.id, sid: v.ada.id, rid: v.bob.id, privat: bob });
  assert.equal(r.text, v.v1.text);
  assert.equal(r.absenderSchluessel, v.ada.oeffentlich);
  assert.equal((await dm.entschluesseln(v.v1.umschlag, { ich: v.ada.id, sid: v.ada.id, rid: v.bob.id, privat: ada })).text, v.v1.text);
  await assert.rejects(dm.entschluesseln(v.v1.umschlag, { ich: v.cleo.id, sid: v.ada.id, rid: v.bob.id, privat: cleo }));
  await assert.rejects(dm.entschluesseln(v.v1.umschlag, { ich: v.bob.id, sid: v.ada.id, rid: v.cleo.id, privat: bob }));
});

test('Nachricht mit Bild und Zitat (v2)', async () => {
  const bob = await privat(v.bob.privat);
  const r = await dm.entschluesseln(v.v2.umschlag, { ich: v.bob.id, sid: v.ada.id, rid: v.bob.id, privat: bob });
  assert.equal(r.text, v.v2.text);
  assert.equal(r.anhaenge.length, 1);
  const klar = await r.bild(dm.unb64u(v.v2.bildChiffrat), r.anhaenge[0]);
  assert.equal(dm.b64u(klar), v.v2.bildKlar);
});

test('Gruppe, Gruppenname und Reaktion', async () => {
  const bob = await privat(v.bob.privat), cleo = await privat(v.cleo.privat), ada = await privat(v.ada.privat);
  for (const [ich, k] of [[v.bob.id, bob], [v.cleo.id, cleo]]) {
    assert.equal((await dm.entschluesseln(v.gruppe.umschlag, { ich, sid: v.ada.id, rid: v.gruppe.rid, privat: k })).text, v.gruppe.text);
  }
  const n = await dm.gruppenNameEntschluesseln(v.gruppenname.umschlag, { ich: v.bob.id, von: v.gruppenname.von, privat: bob });
  assert.equal(n.name, v.gruppenname.name);
  const rx = v.reaktion;
  const e = await dm.reaktionEntschluesseln(rx.umschlag, { ich: v.ada.id, mid: rx.mid, sid: rx.sid, konv: rx.konv, privat: ada });
  assert.equal(e.emoji, rx.emoji);
  // An eine andere Nachricht gehängt, fällt die Reaktion auf
  await assert.rejects(dm.reaktionEntschluesseln(rx.umschlag, { ich: v.ada.id, mid: rx.mid + 1, sid: rx.sid, konv: rx.konv, privat: ada }));
});

test('Veränderter Umschlag fällt auf (GCM)', async () => {
  const bob = await privat(v.bob.privat);
  const u = JSON.parse(v.v1.umschlag);
  const c = dm.unb64u(u.c); c[0] ^= 1; u.c = dm.b64u(c);
  await assert.rejects(dm.entschluesseln(JSON.stringify(u), { ich: v.bob.id, sid: v.ada.id, rid: v.bob.id, privat: bob }));
});

test('Schlüssel per Passkey-PRF und per Wiederherstellungscode auspacken', async () => {
  const e = v.einpacken;
  const k = await dm.auspacken(e.gepackt, dm.unb64u(e.prf), e.uid, e.credId);
  assert.equal(await dm.oeffentlichVon(k), v.ada.oeffentlich);
  await assert.rejects(dm.auspacken(e.gepackt, new Uint8Array(32), e.uid, e.credId));
  const c = v.code;
  assert.equal(dm.codeText(dm.unb64u(c.roh)), c.code);
  const k2 = await dm.codeAuspacken(c.gepackt, dm.codeLesen(c.code.toLowerCase()), c.uid);
  assert.equal(await dm.oeffentlichVon(k2), v.ada.oeffentlich);
});

test('Sicherheitsnummer und Fingerabdruck wie in den Vektoren, Reihenfolge egal', async () => {
  assert.equal(await dm.sicherheitsnummer(v.ada.oeffentlich, v.bob.oeffentlich), v.sicherheitsnummer);
  assert.equal(await dm.sicherheitsnummer(v.bob.oeffentlich, v.ada.oeffentlich), v.sicherheitsnummer);
  assert.equal(await dm.fingerabdruck(v.ada.oeffentlich), v.fingerabdruck);
});

test('Länge versteckt: kurze Nachrichten sind gleich groß', async () => {
  const a = await dm.neuesPaar(), b = await dm.neuesPaar();
  const groesse = async text => {
    const u = JSON.parse(await dm.verschluesseln({ text, sid: 1, rid: 2, senderPrivat: a.privat, senderPub: a.oeffentlich, empfPub: b.oeffentlich }));
    return dm.unb64u(u.c).length;
  };
  assert.equal(await groesse('ok'), 64 + 16);
  assert.equal(await groesse('Treffen wir uns morgen um acht am Bahnhof?'), 64 + 16);
  assert.equal(await groesse('x'.repeat(65)), 128 + 16);
});

test('Gerät koppeln: Commitment, Prüfzahl und Weitergabe wie in den Vektoren', async () => {
  assert.equal(await dm.kopplungFp(kv.neu.oeffentlich), kv.fingerabdruck);
  assert.equal(await dm.kopplungCommit(kv.neu.oeffentlich, kv.nonce), kv.commit);
  assert.equal(await dm.kopplungZahl(kv.neu.oeffentlich, kv.alt.oeffentlich), kv.pruefzahl);
  const k = await dm.kopplungAuspacken(kv.wrapped, await privat(kv.neu.privat), kv.neu.oeffentlich, kv.alt.oeffentlich, kv.uid, kv.id);
  assert.equal(await dm.oeffentlichVon(k), kv.dm.oeffentlich);
  // Ein anderer Einmal-Schlüssel ergibt ein anderes Commitment
  const fremd = await dm.neuesPaar();
  assert.notEqual(await dm.kopplungCommit(fremd.oeffentlich, kv.nonce), kv.commit);
});

test('Bindung: ein Empfänger kann keinen anderen Text unter die Hüllen des Absenders legen', async () => {
  const bob = await privat(v.bob.privat), ada = await privat(v.ada.privat), cleo = await privat(v.cleo.privat);
  const lesen = (u, o) => dm.entschluesseln(u, { sid: v.ada.id, ...o });
  // Jede Hülle trägt die Bindung t (HMAC-SHA-256, 43 Zeichen), und sie gilt
  for (const h of Object.values(JSON.parse(v.gruppe.umschlag).k)) assert.match(h.t, /^[A-Za-z0-9_-]{43}$/);
  assert.equal((await lesen(v.gruppe.umschlag, { ich: v.cleo.id, rid: 'g9', privat: cleo })).gebunden, true);
  // Der Angriff: Bob ist Empfänger, kennt damit den Inhaltsschlüssel und verschlüsselt eigenen Text darunter.
  // Adas Hüllen für Cleo und für Adas eigene Geräte lässt er stehen. Hier frisch nachgebaut, nicht nur aus dem Vektor.
  const echt = await lesen(v.gruppe.umschlag, { ich: v.bob.id, rid: 'g9', privat: bob });
  const k = await sub.importKey('raw', echt.schluesselRoh, 'AES-GCM', false, ['encrypt']);
  const u = JSON.parse(v.gruppe.umschlag), iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const c = await sub.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(`cs-dm-v1|${v.ada.id}|g9|${u.s}`) }, k, new TextEncoder().encode('Nicht von Ada'));
  const gefaelscht = JSON.stringify({ ...u, n: dm.b64u(iv), c: dm.b64u(c) });
  for (const [ich, p] of [[v.cleo.id, cleo], [v.ada.id, ada], [v.bob.id, bob]]) {
    await assert.rejects(lesen(gefaelscht, { ich, rid: 'g9', privat: p }), /changed after it was sent/);
    await assert.rejects(lesen(v.bindung.gefaelscht, { ich, rid: 'g9', privat: p }), /changed after it was sent/);
  }
});

test('Bindung: Umschläge älterer Fassungen (ohne t) gehen auf und gelten als nicht gebunden', async () => {
  const bob = await privat(v.bob.privat), cleo = await privat(v.cleo.privat);
  const alt = await dm.entschluesseln(v.bindung.ohne, { ich: v.bob.id, sid: v.ada.id, rid: v.bob.id, privat: bob });
  assert.equal(alt.text, v.v1.text);
  assert.equal(alt.gebunden, false);
  // Das ist die Grenze des Übergangs (PROTOCOL.md 9.6): Ohne t ist die Fälschung lesbar, aber als nicht gebunden erkennbar
  const f = await dm.entschluesseln(v.bindung.gefaelschtOhne, { ich: v.cleo.id, sid: v.ada.id, rid: 'g9', privat: cleo });
  assert.equal(f.text, v.bindung.gefaelschtText);
  assert.equal(f.gebunden, false);
});

test('Bindung: die sichtbaren Felder v und b sind mitgesichert', async () => {
  const bob = await privat(v.bob.privat);
  const lesen = u => dm.entschluesseln(JSON.stringify(u), { ich: v.bob.id, sid: v.ada.id, rid: v.bob.id, privat: bob });
  const u = JSON.parse(v.v2.umschlag);
  assert.equal((await lesen(u)).anhaenge.length, 1);
  await assert.rejects(lesen({ ...u, b: [] }), /changed after it was sent/);
  const alsV1 = { ...u, v: 1 }; delete alsV1.b;
  await assert.rejects(lesen(alsV1), /changed after it was sent/);
  // Ein t, das zu einer anderen Hülle gehört, gilt nicht
  const vertauscht = JSON.parse(v.v2.umschlag);
  vertauscht.k[v.bob.id].t = JSON.parse(v.v1.umschlag).k[v.bob.id].t;
  await assert.rejects(lesen(vertauscht), /changed after it was sent/);
});

test('Reaktionen: jedes Emoji ergibt dasselbe Chiffrat-Maß', async () => {
  const a = await dm.neuesPaar(), b = await dm.neuesPaar();
  const laengen = new Set();
  for (const emoji of ['👍', '❤️', '✅', '👍🏽', '🇪🇺', '1️⃣', '👨‍👩‍👧', '🏳️‍🌈']) {
    const u = await dm.reaktionVerschluesseln({ emoji, mid: 1, sid: 1, konv: 'p1-2', senderPrivat: a.privat, senderPub: a.oeffentlich, empfaenger: { 2: b.oeffentlich } });
    laengen.add(dm.unb64u(JSON.parse(u).c).length);
    const r = await dm.reaktionEntschluesseln(u, { ich: 2, mid: 1, sid: 1, konv: 'p1-2', privat: b.privat });
    assert.equal(r.emoji, emoji);
    assert.equal(r.gebunden, true);
  }
  assert.deepEqual([...laengen], [48 + 16]);
});

test('Kaputte Umschläge: immer ein abgelehntes Promise, nie ein synchroner Wurf', async () => {
  const bob = await privat(v.bob.privat);
  for (const kaputt of [u => { u.k[v.bob.id].e = 'A'; }, u => { u.k[v.bob.id] = 'x'; }, u => { u.k[v.bob.id].t = 'A'; }, u => { u.n = 5; }]) {
    const u = JSON.parse(v.v1.umschlag); kaputt(u);
    let p;
    assert.doesNotThrow(() => { p = dm.entschluesseln(JSON.stringify(u), { ich: v.bob.id, sid: v.ada.id, rid: v.bob.id, privat: bob }); });
    await assert.rejects(p);
  }
});
