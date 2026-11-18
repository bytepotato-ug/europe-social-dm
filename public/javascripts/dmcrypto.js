// europe.social: Ende-zu-Ende-Verschlüsselung der Direktnachrichten, nur mit WebCrypto (keine Fremdbibliothek).
// Läuft gleich im Browser (window.csDm) und in Node (module.exports), damit die Tests genau diesen Code prüfen.
//
// Schlüssel: Jedes Konto hat ein ECDH-Schlüsselpaar (P-256). Der private Schlüssel verlässt den Browser nur
// verschlüsselt: mit AES-256-GCM unter einem Schlüssel, der per HKDF aus der WebAuthn-PRF des Passkeys stammt.
// Die PRF liefert nur der Authenticator und nur nach Touch ID oder PIN; der Server sieht sie nie.
//
// Nachricht: zufälliger Inhaltsschlüssel K, Text mit AES-256-GCM verschlüsselt. K wird für Empfänger UND Absender
// eingepackt, je mit frischem Wegwerfschlüssel E: KEK = HKDF(ECDH(E, P) || ECDH(S, P)). Der zweite Teil bindet
// den statischen Schlüssel des Absenders S ein: Nur wer S besitzt, kann eine Nachricht in seinem Namen bauen.
// Keine Forward Secrecy: Wer später den privaten Schlüssel erbeutet, kann alte Nachrichten lesen.
//
// Bilder (v2): Jedes Bild wird mit demselben Inhaltsschlüssel K und eigenem Zufalls-IV verschlüsselt und als Chiffrat
// hochgeladen. Kennung, IV, Art, Maße und Beschreibung stehen im verschlüsselten Text ({ t, a: [...] }); der
// Server sieht nur die Kennungen (Feld b), um Zugriff und Löschen zu regeln. Ein vertauschtes oder fremdes Chiffrat
// fällt beim Entschlüsseln auf (GCM), weil der IV zum Bild gehört.
(function (wurzel, fabrik) {
  if (typeof module === 'object' && module.exports) module.exports = fabrik(globalThis.crypto);
  else wurzel.csDm = fabrik(wurzel.crypto);
})(typeof self !== 'undefined' ? self : this, function (krypto) {
  'use strict';
  var sub = krypto.subtle;
  var KURVE = { name: 'ECDH', namedCurve: 'P-256' };
  var MAX = 1000; // Zeichen je Direktnachricht (lib/routes/nachrichten.js)
  var MAX_BILDER = 4, MAX_ALT = 500, MAX_ZITAT = 140, MAX_DAUER = 300;
  var ARTEN = ['image/webp', 'image/jpeg', 'image/gif'];
  var TONARTEN = ['audio/webm', 'audio/mp4', 'audio/ogg']; // Sprachnachrichten (MediaRecorder: Chrome/Firefox WebM, Safari MP4)
  var enc = new TextEncoder();
  var dec = new TextDecoder('utf-8', { fatal: true });

  function b64u(buf) {
    var b = new Uint8Array(buf), s = '';
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64u(str) {
    if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) throw new Error('Invalid encoding.');
    var s = atob(str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4));
    var b = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
    return b;
  }
  function verbinden(a, b) { var r = new Uint8Array(a.length + b.length); r.set(a, 0); r.set(b, a.length); return r; }
  function zufall(n) { return krypto.getRandomValues(new Uint8Array(n)); }

  // Gleiche Regeln wie lib/text.js auf dem Server: Der Server sieht den Text nicht mehr und kann ihn nicht bereinigen.
  function saeubern(roh) {
    var s = String(roh == null ? '' : roh);
    if (typeof s.toWellFormed === 'function') s = s.toWellFormed();
    s = s.normalize('NFC').replace(/\r\n?/g, '\n').replace(/\t/g, ' ');
    s = s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, '')
      .replace(/[؜‎‏‪-‮⁦-⁩]/g, '')
      .replace(/[­᠎​⁠-⁤﻿]/g, '');
    s = s.replace(/^\p{M}+/u, '').replace(/(\P{M})(\p{M}{3})\p{M}+/gu, '$1$2');
    s = s.replace(/\n{3,}/g, '\n\n').replace(/[  　]{3,}/g, '  ').trim();
    return Array.from(s).slice(0, MAX).join('').trim();
  }
  function laenge(text) { return Array.from(String(text)).length; }

  function hkdf(ikm, salz, info, nutzung) {
    return sub.importKey('raw', ikm, 'HKDF', false, ['deriveKey']).then(function (basis) {
      return sub.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: salz, info: enc.encode(info) }, basis,
        { name: 'AES-GCM', length: 256 }, false, nutzung);
    });
  }

  // Fester PRF-Eingabewert für alle Konten. Er muss nicht geheim sein: Das Geheimnis steckt im Passkey.
  function prfSalz() { return sub.digest('SHA-256', enc.encode('europe.social e2ee v1')).then(function (h) { return new Uint8Array(h); }); }

  function hueller(prf, uid, credId) {
    if (!prf || prf.byteLength < 32) return Promise.reject(new Error('This passkey doesn’t provide a key (PRF).'));
    return hkdf(new Uint8Array(prf), new Uint8Array(0), 'cs-wrap-v1|' + uid + '|' + credId, ['encrypt', 'decrypt']);
  }

  function neuesPaar() {
    return sub.generateKey(KURVE, true, ['deriveBits']).then(function (p) {
      return sub.exportKey('raw', p.publicKey).then(function (raw) { return { privat: p.privateKey, oeffentlich: b64u(raw) }; });
    });
  }

  // Privaten Schlüssel für einen Passkey einpacken: "iv.chiffrat", beides base64url.
  function einpacken(privat, prf, uid, credId) {
    return Promise.all([sub.exportKey('pkcs8', privat), hueller(prf, uid, credId)]).then(function (x) {
      var iv = zufall(12);
      return sub.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode('cs-wrap-v1|' + uid) }, x[1], x[0])
        .then(function (c) { return b64u(iv) + '.' + b64u(c); });
    });
  }
  function auspacken(gepackt, prf, uid, credId) {
    var t = String(gepackt).split('.');
    if (t.length !== 2) return Promise.reject(new Error('Wrapped key unreadable.'));
    return hueller(prf, uid, credId).then(function (k) {
      return sub.decrypt({ name: 'AES-GCM', iv: unb64u(t[0]), additionalData: enc.encode('cs-wrap-v1|' + uid) }, k, unb64u(t[1]));
    }).then(function (pkcs8) { return sub.importKey('pkcs8', pkcs8, KURVE, true, ['deriveBits']); });
  }
  // Wiederherstellungscode (seit 2026-11-12): für Passkeys ohne PRF (Firefox auf Android, manche Passwortmanager) und als
  // Rückweg für alle. 20 Zufallsbytes (160 Bit), angezeigt als 32 Zeichen Crockford-Base32 in Vierergruppen. Wie bei der
  // PRF stammt der Schlüssel per HKDF aus dem Geheimnis; der Server sieht den Code nie. Raten lohnt nicht: 2^160 Möglichkeiten,
  // darum kein langsames Ableiten nötig. Format der Fassung wie einpacken: "iv.chiffrat".
  var CODE_ZEICHEN = '0123456789ABCDEFGHJKMNPQRSTVWXYZ', CODE_BYTES = 20;
  function codeText(roh) {
    var bits = 0, wert = 0, aus = '';
    for (var i = 0; i < roh.length; i++) {
      wert = (wert << 8) | roh[i]; bits += 8;
      while (bits >= 5) { aus += CODE_ZEICHEN[(wert >>> (bits - 5)) & 31]; bits -= 5; }
    }
    return aus.match(/.{4}/g).join('-');
  }
  function codeNeu() { var roh = zufall(CODE_BYTES); return { roh: roh, code: codeText(roh) }; }
  // Eingabe lesen: Groß- und Kleinschreibung egal, Leerzeichen und Striche egal, O als 0, I und L als 1 (Crockford)
  function codeLesen(text) {
    var s = String(text == null ? '' : text).toUpperCase().replace(/[\s\-–—_.]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
    if (s.length !== CODE_BYTES * 8 / 5) throw new Error('This recovery code is incomplete.');
    var roh = new Uint8Array(CODE_BYTES), bits = 0, wert = 0, n = 0;
    for (var i = 0; i < s.length; i++) {
      var z = CODE_ZEICHEN.indexOf(s[i]);
      if (z < 0) throw new Error('This recovery code contains a character that doesn’t belong.');
      wert = ((wert << 5) | z) & 0xffff; bits += 5;
      if (bits >= 8) { roh[n++] = (wert >>> (bits - 8)) & 255; bits -= 8; }
    }
    return roh;
  }
  function codeHueller(roh, uid) {
    if (!roh || roh.length !== CODE_BYTES) return Promise.reject(new Error('This recovery code is incomplete.'));
    return hkdf(roh, new Uint8Array(0), 'cs-code-v1|' + uid, ['encrypt', 'decrypt']);
  }
  function codeEinpacken(privat, roh, uid) {
    return Promise.all([sub.exportKey('pkcs8', privat), codeHueller(roh, uid)]).then(function (x) {
      var iv = zufall(12);
      return sub.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode('cs-code-v1|' + uid) }, x[1], x[0])
        .then(function (c) { return b64u(iv) + '.' + b64u(c); });
    });
  }
  function codeAuspacken(gepackt, roh, uid) {
    var t = String(gepackt).split('.');
    if (t.length !== 2) return Promise.reject(new Error('Wrapped key unreadable.'));
    return codeHueller(roh, uid).then(function (k) {
      return sub.decrypt({ name: 'AES-GCM', iv: unb64u(t[0]), additionalData: enc.encode('cs-code-v1|' + uid) }, k, unb64u(t[1]));
    }).then(function (pkcs8) { return sub.importKey('pkcs8', pkcs8, KURVE, true, ['deriveBits']); },
      function () { throw new Error('This recovery code doesn’t match your account.'); });
  }

  // Öffentlichen Schlüssel aus dem privaten gewinnen (prüft, dass beide zusammengehören).
  function oeffentlichVon(privat) {
    return sub.exportKey('jwk', privat).then(function (j) {
      return sub.importKey('jwk', { kty: j.kty, crv: j.crv, x: j.x, y: j.y, ext: true }, KURVE, true, []);
    }).then(function (pub) { return sub.exportKey('raw', pub); }).then(b64u);
  }

  function pubImport(raw) {
    var b = unb64u(raw);
    if (b.length !== 65 || b[0] !== 4) return Promise.reject(new Error('Invalid public key.'));
    return sub.importKey('raw', b, KURVE, true, []);
  }
  function ecdh(privat, oeff) { return sub.deriveBits({ name: 'ECDH', public: oeff }, privat, 256).then(function (z) { return new Uint8Array(z); }); }
  function kontext(sid, rid, s) { return 'cs-dm-v1|' + sid + '|' + rid + '|' + s; }

  // basis: Kontexttext der Nachricht (Zusatzdaten für GCM und HKDF-Info); fuer: Konto, für das eingepackt wird
  function kek(z1, z2, ephRaw, basis, fuer, nutzung) {
    return hkdf(verbinden(z1, z2), ephRaw, basis + '|' + fuer, nutzung);
  }

  // Kern für Nachrichten und Reaktionen: klar (Bytes) mit Inhaltsschlüssel k verschlüsseln und k für jedes Ziel
  // ({ kontonummer: öffentlicher Schlüssel }, Absender eingeschlossen) einpacken. kopf: weitere sichtbare Felder.
  function versiegeln(basis, klar, o, ziele, kopf, schluessel) {
    var aad = enc.encode(basis);
    return Promise.all([schluessel ? Promise.resolve(schluessel) : sub.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']), pubImport(o.senderPub)]).then(function (x) {
      var k = x[0], iv = zufall(12);
      return Promise.all([sub.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, k, klar), sub.exportKey('raw', k)]).then(function (y) {
        var umschlag = { v: kopf.v, s: o.senderPub, n: b64u(iv), c: b64u(y[0]), k: {} };
        Object.keys(kopf).forEach(function (f) { if (f !== 'v') umschlag[f] = kopf[f]; });
        return Promise.all(Object.keys(ziele).map(function (fuer) {
          return Promise.all([pubImport(ziele[fuer]), sub.generateKey(KURVE, true, ['deriveBits'])]).then(function (z) {
            var p = z[0], eph = z[1];
            return Promise.all([ecdh(eph.privateKey, p), ecdh(o.senderPrivat, p), sub.exportKey('raw', eph.publicKey)]).then(function (w) {
              var ephRaw = new Uint8Array(w[2]);
              return kek(w[0], w[1], ephRaw, basis, fuer, ['encrypt']).then(function (kk) {
                var iv2 = zufall(12);
                return sub.encrypt({ name: 'AES-GCM', iv: iv2 }, kk, y[1]).then(function (wk) {
                  umschlag.k[fuer] = { e: b64u(ephRaw), n: b64u(iv2), w: b64u(wk) };
                });
              });
            });
          });
        })).then(function () { return JSON.stringify(umschlag); });
      });
    });
  }
  // Gegenstück: liefert { klar (Bytes), schluessel (Inhaltsschlüssel, nur zum Entschlüsseln), u (Umschlag) }
  function oeffnen(u, basis, o) {
    var mein = u.k[o.ich], inhalt, roh;
    return Promise.all([pubImport(mein.e), pubImport(u.s)]).then(function (x) {
      return Promise.all([ecdh(o.privat, x[0]), ecdh(o.privat, x[1])]);
    }).then(function (z) {
      return kek(z[0], z[1], unb64u(mein.e), basis, String(o.ich), ['decrypt']);
    }).then(function (kk) {
      return sub.decrypt({ name: 'AES-GCM', iv: unb64u(mein.n) }, kk, unb64u(mein.w));
    }).then(function (kRaw) {
      roh = new Uint8Array(kRaw);
      return sub.importKey('raw', kRaw, 'AES-GCM', false, ['decrypt']);
    }).then(function (k) {
      inhalt = k;
      return sub.decrypt({ name: 'AES-GCM', iv: unb64u(u.n), additionalData: enc.encode(basis) }, k, unb64u(u.c));
    }).then(function (klar) { return { klar: new Uint8Array(klar), schluessel: inhalt, roh: roh, u: u }; });
  }
  function umschlagLesen(text, o) {
    var u;
    try { u = JSON.parse(text); } catch (e) { throw new Error('Envelope unreadable.'); }
    if (!u || !u.k || !u.k[o.ich] || typeof u.s !== 'string') throw new Error('Nicht für dieses Konto verschlüsselt.');
    return u;
  }
  // Ziele: in Gruppen alle Mitglieder (o.empfaenger), sonst Empfänger und Absender
  function zieleVon(o) {
    if (o.empfaenger) { var z = {}; Object.keys(o.empfaenger).forEach(function (id) { z[String(id)] = o.empfaenger[id]; }); z[String(o.sid)] = o.senderPub; return z; }
    var ziele = {}; ziele[String(o.rid)] = o.empfPub; ziele[String(o.sid)] = o.senderPub; return ziele;
  }

  // Antwort auf eine bestimmte Nachricht: Nummer, Absender und ein kurzer Auszug stehen verschlüsselt in der Antwort
  function zitatPruefen(q) {
    if (!q || typeof q !== 'object') return null;
    var id = Number(q.id), von = Number(q.von);
    if (!(id > 0) || id % 1 || !(von > 0) || von % 1) return null;
    var t = Array.from(saeubern(typeof q.t === 'string' ? q.t : '')).slice(0, MAX_ZITAT).join('');
    return { id: id, von: von, t: t, bild: q.bild === true };
  }
  // Inhaltsschlüssel aus den Rohbytes einer eigenen Nachricht, zum Bearbeiten (gleicher Schlüssel, damit Bilder lesbar bleiben)
  function schluesselAus(roh) { return sub.importKey('raw', roh, 'AES-GCM', true, ['encrypt', 'decrypt']); }

  // ----- Reaktionen: ein Emoji je Person und Nachricht, verschlüsselt und an genau diese Nachricht gebunden -----
  var segmente = typeof Intl !== 'undefined' && Intl.Segmenter ? new Intl.Segmenter('en', { granularity: 'grapheme' }) : null;
  function emojiPruefen(e) {
    if (typeof e !== 'string') return '';
    e = e.normalize('NFC').trim();
    if (!e || e.length > 32 || /[\s\u0000-\u001F]/.test(e)) return '';
    if (segmente && Array.from(segmente.segment(e)).length !== 1) return '';
    if (!/\p{Extended_Pictographic}|\p{Regional_Indicator}{2}|\u20E3/u.test(e)) return '';
    return e;
  }
  // konv: Unterhaltung, gleich aus beiden Blickwinkeln (zu zweit „p<kleinere>-<größere Nummer>“, Gruppe „g<Nummer>“)
  function reaktionsKontext(mid, sid, konv, s) { return 'cs-dm-reaktion-v1|' + mid + '|' + sid + '|' + konv + '|' + s; }
  // o: emoji, mid (Nachrichtennummer), sid (wer reagiert), konv, senderPrivat, senderPub,
  //    empfaenger ({ kontonummer: öffentlicher Schlüssel } aller anderen Beteiligten)
  function reaktionVerschluesseln(o) {
    var emoji = emojiPruefen(o.emoji);
    if (!emoji) return Promise.reject(new Error('Invalid reaction.'));
    if (!o.empfaenger) return Promise.reject(new Error('Reactions need the recipients.'));
    return versiegeln(reaktionsKontext(o.mid, o.sid, o.konv, o.senderPub), enc.encode(emoji), o, zieleVon(o), { v: 1 });
  }
  // o: ich, mid, sid (wer reagiert hat), konv, privat. Liefert { emoji, absenderSchluessel }
  function reaktionEntschluesseln(text, o) {
    var u;
    try { u = umschlagLesen(text, o); } catch (e) { return Promise.reject(e); }
    if (u.v !== 1) return Promise.reject(new Error('Unbekannte Fassung.'));
    return oeffnen(u, reaktionsKontext(o.mid, o.sid, o.konv, u.s), o).then(function (r) {
      var emoji = emojiPruefen(dec.decode(r.klar));
      if (!emoji) throw new Error('Keine Reaktion.');
      return { emoji: emoji, absenderSchluessel: u.s };
    });
  }

  // ----- Bilder -----
  // Inhaltsschlüssel für eine Nachricht mit Bildern: vor dem Hochladen erzeugt, beim Senden an verschluesseln übergeben
  function inhaltsSchluessel() { return sub.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']); }
  function bildKontext(sid, rid) { return enc.encode('cs-dm-bild-v1|' + sid + '|' + rid); }
  // Liefert { n: IV (base64url), daten: Chiffrat }
  function bildVerschluesseln(k, bytes, sid, rid) {
    var iv = zufall(12);
    return sub.encrypt({ name: 'AES-GCM', iv: iv, additionalData: bildKontext(String(sid), String(rid)) }, k, bytes)
      .then(function (c) { return { n: b64u(iv), daten: new Uint8Array(c) }; });
  }
  // Ein Anhang aus dem verschlüsselten Teil (Bild oder Sprachnachricht): streng geprüft, alles Unbekannte fällt weg
  function anhangPruefen(a) {
    if (!a || typeof a !== 'object' || typeof a.id !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(a.id)) return null;
    if (typeof a.n !== 'string' || !/^[A-Za-z0-9_-]{16}$/.test(a.n)) return null;
    if (TONARTEN.indexOf(a.typ) >= 0) {
      var d = Number(a.d);
      if (!(d >= 1 && d <= MAX_DAUER) || d % 1) return null;
      return { id: a.id, n: a.n, typ: a.typ, d: d };
    }
    if (ARTEN.indexOf(a.typ) < 0) return null;
    var b = Number(a.b), h = Number(a.h);
    if (!(b >= 1 && b <= 8192 && h >= 1 && h <= 8192) || b % 1 || h % 1) return null;
    var alt = saeubern(typeof a.alt === 'string' ? a.alt : '');
    alt = Array.from(alt).slice(0, MAX_ALT).join('');
    return { id: a.id, n: a.n, typ: a.typ, b: b, h: h, alt: alt };
  }

  // Länge verstecken: Der Klartext wird vor dem Verschlüsseln mit Leerzeichen auf die nächste Stufe aufgefüllt
  // (64, 128, 256 … Bytes), sonst verriete die Größe des Chiffrats ungefähr, wie lang die Nachricht ist. Alle Clients
  // lesen das ohne Änderung: v1 schneidet Leerzeichen am Ende ab (saeubern), v2 ist JSON, das Leerraum am Ende erlaubt.
  // Höchstwerte wie die Grenze des Servers (lib/routes/nachrichten.js, umschlagPruefen), damit nichts abgelehnt wird.
  var MAX_V1 = MAX * 4, MAX_V2 = MAX * 4 + MAX_BILDER * (MAX_ALT * 4 + 200) + 64 + 700;
  function auffuellen(bytes, hoechstens) {
    var stufe = 64;
    while (stufe < bytes.length) stufe *= 2;
    stufe = Math.min(stufe, hoechstens);
    if (stufe <= bytes.length) return bytes;
    var r = new Uint8Array(stufe).fill(0x20);
    r.set(bytes, 0);
    return r;
  }

  // senderPrivat: eigener privater Schlüssel; senderPub, empfPub: öffentliche Schlüssel (base64url, roh).
  // Mit Bildern: o.anhaenge = [{ id, n, typ, b, h, alt }], o.schluessel = der Inhaltsschlüssel, mit dem sie verschlüsselt sind
  // In Gruppen: o.rid = 'g' + Gruppennummer, o.empfaenger = { kontonummer: öffentlicher Schlüssel } aller Mitglieder.
  function verschluesseln(o) {
    var text = saeubern(o.text);
    var anhaenge = (o.anhaenge || []).map(anhangPruefen);
    if (anhaenge.some(function (a) { return !a; }) || anhaenge.length > MAX_BILDER) return Promise.reject(new Error('Invalid picture.'));
    if (!text && !anhaenge.length) return Promise.reject(new Error('The message is empty.'));
    if (anhaenge.length && !o.schluessel) return Promise.reject(new Error('Pictures need the message key.'));
    var zitat = o.zitat ? zitatPruefen(o.zitat) : null;
    if (o.zitat && !zitat) return Promise.reject(new Error('Invalid reply.'));
    var sid = String(o.sid), rid = String(o.rid);
    // v1: nur Text. v2: JSON mit Text, Anhängen und Zitat; b listet die Anhänge sichtbar (auch leer)
    var json = anhaenge.length || zitat;
    var inhalt = { t: text };
    if (anhaenge.length) inhalt.a = anhaenge;
    if (zitat) inhalt.q = zitat;
    var klar = json ? JSON.stringify(inhalt) : text;
    var kopf = json ? { v: 2, b: anhaenge.map(function (a) { return a.id; }) } : { v: 1 };
    return versiegeln(kontext(sid, rid, o.senderPub), auffuellen(enc.encode(klar), json ? MAX_V2 : MAX_V1), o, zieleVon(o), kopf, o.schluessel);
  }

  // ich: eigene Nutzer-ID; privat: eigener privater Schlüssel. Liefert { text, absenderSchluessel, anhaenge, bild }:
  // bild(chiffrat, anhang) entschlüsselt ein heruntergeladenes Bild mit dem Schlüssel dieser Nachricht.
  function entschluesseln(umschlagText, o) {
    var u;
    try { u = umschlagLesen(umschlagText, o); } catch (e) { return Promise.reject(e); }
    if (u.v !== 1 && u.v !== 2) return Promise.reject(new Error('Unbekannte Fassung.'));
    var sichtbar = u.v === 2 && Array.isArray(u.b) ? u.b : [];
    var sid = String(o.sid), rid = String(o.rid);
    return oeffnen(u, kontext(sid, rid, u.s), o).then(function (r) {
      var text = dec.decode(r.klar), anhaenge = [], zitat = null;
      if (u.v === 2) {
        var j;
        try { j = JSON.parse(text); } catch (e) { throw new Error('Inhalt unlesbar.'); }
        text = j && typeof j.t === 'string' ? j.t : '';
        anhaenge = (Array.isArray(j && j.a) ? j.a : []).map(anhangPruefen)
          .filter(function (a) { return a && sichtbar.indexOf(a.id) >= 0; }).slice(0, MAX_BILDER);
        zitat = j ? zitatPruefen(j.q) : null;
      }
      return {
        text: saeubern(text), absenderSchluessel: u.s, anhaenge: anhaenge, zitat: zitat, schluesselRoh: r.roh,
        bild: function (chiffrat, a) {
          return sub.decrypt({ name: 'AES-GCM', iv: unb64u(a.n), additionalData: bildKontext(sid, rid) }, r.schluessel, chiffrat).then(function (d) { return new Uint8Array(d); });
        },
      };
    });
  }

  // ----- Gruppennamen: verschlüsselt für alle Mitglieder, wie eine Nachricht -----
  // Kontext: wer versiegelt hat (Kontonummer, steht beim Server als name_von) und dessen Schlüssel. Bewusst ohne
  // Gruppennummer, damit ein Name schon beim Anlegen versiegelt werden kann; der Server könnte einen Namen daher in
  // eine andere Gruppe derselben Person verschieben, aber keinen erfinden oder lesen. Empfänger prüfen den Schlüssel
  // des Versiegelnden gegen den gemerkten (wie bei Nachrichten).
  var MAX_GRUPPENNAME = 50;
  function gruppenNameKontext(von, s) { return 'cs-dm-gname-v1|' + von + '|' + s; }
  function gruppenNamePruefen(roh) { return Array.from(saeubern(roh)).slice(0, MAX_GRUPPENNAME).join('').trim(); }
  // o: name, sid (wer versiegelt), senderPrivat, senderPub, empfaenger ({ kontonummer: Schlüssel } aller anderen Mitglieder)
  function gruppenNameVerschluesseln(o) {
    var name = gruppenNamePruefen(o.name);
    if (!name) return Promise.reject(new Error('The group name is empty.'));
    if (!o.empfaenger) return Promise.reject(new Error('Group names need the members.'));
    return versiegeln(gruppenNameKontext(String(o.sid), o.senderPub), auffuellen(enc.encode(name), MAX_V1), o, zieleVon(o), { v: 1 });
  }
  // o: ich, von (wer versiegelt hat), privat. Liefert { name, absenderSchluessel, ziele (Kontonummern, für die eingepackt ist) }
  function gruppenNameEntschluesseln(text, o) {
    var u;
    try { u = umschlagLesen(text, o); } catch (e) { return Promise.reject(e); }
    if (u.v !== 1) return Promise.reject(new Error('Unbekannte Fassung.'));
    return oeffnen(u, gruppenNameKontext(String(o.von), u.s), o).then(function (r) {
      var name = gruppenNamePruefen(dec.decode(r.klar));
      if (!name) throw new Error('Kein Name.');
      return { name: name, absenderSchluessel: u.s, ziele: Object.keys(u.k) };
    });
  }

  // Kurzer Fingerabdruck zum Vergleichen: 20 Hex-Zeichen in Fünfergruppen.
  function fingerabdruck(pubRaw) {
    return sub.digest('SHA-256', unb64u(pubRaw)).then(function (h) {
      var b = new Uint8Array(h).slice(0, 10), s = '';
      for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
      return s.match(/.{5}/g).join(' ');
    });
  }

  // Gemeinsame Sicherheitsnummer zweier Konten: beide Seiten sehen dieselbe Zahl (Reihenfolge der Schlüssel egal).
  // 40 Ziffern in Achtergruppen zu je fünf, zum Vorlesen oder Nebeneinanderlegen. Weicht sie ab, liest jemand mit.
  function sicherheitsnummer(pubA, pubB) {
    var a = unb64u(pubA), b = unb64u(pubB), erst = a, dann = b;
    for (var i = 0; i < a.length; i++) { if (a[i] !== b[i]) { if (a[i] > b[i]) { erst = b; dann = a; } break; } }
    return sub.digest('SHA-256', verbinden(enc.encode('cs-sicherheitsnummer-v1'), verbinden(erst, dann))).then(function (h) {
      var d = new DataView(h), gruppen = [];
      for (var j = 0; j < 8; j++) gruppen.push(String(d.getUint32(j * 4) % 100000).padStart(5, '0'));
      return gruppen.join(' ');
    });
  }

  // ----- Gerät koppeln (seit 2026-11-15, Protokoll in KOPPELN.md): ein entsperrtes Gerät gibt den DM-Schlüssel an ein
  // neues Gerät desselben Kontos weiter. Beide erzeugen ein Einmal-Paar (neuesPaar), der Server reicht nur die öffentlichen
  // Hälften und das Chiffrat durch. Dass der Server nicht dazwischen sitzt, bestätigt der Mensch: Er vergleicht die
  // Prüfzahl auf beiden Geräten oder scannt den QR-Code des neuen Geräts (der trägt dessen Fingerabdruck).
  var KOPPEL = 'cs-pair-v1';
  // Fingerabdruck des Einmal-Schlüssels des neuen Geräts für den QR-Code: 12 Bytes SHA-256, base64url (16 Zeichen)
  function kopplungFp(pubN) {
    return sub.digest('SHA-256', verbinden(enc.encode(KOPPEL + '|'), unb64u(pubN))).then(function (h) { return b64u(new Uint8Array(h).slice(0, 12)); });
  }
  // Prüfzahl: sechs Ziffern aus beiden Einmal-Schlüsseln (Reihenfolge fest: neues Gerät zuerst)
  function kopplungZahl(pubN, pubA) {
    return sub.digest('SHA-256', verbinden(enc.encode('cs-pair-sas-v1|'), verbinden(unb64u(pubN), unb64u(pubA)))).then(function (h) {
      return String(new DataView(h).getUint32(0) % 1000000).padStart(6, '0');
    });
  }
  // Commitment (seit 2026-11-16): Das neue Gerät schickt zuerst nur commit = SHA-256(„cs-pair-commit-v1|“ ‖ pubN ‖ nonce)
  // und legt pubN und nonce erst offen, wenn das andere Gerät mit seinem Schlüssel angenommen hat. Das andere Gerät prüft
  // das Commitment selbst. Ohne diesen Schritt könnte ein bösartiger Server nach pubA einen eigenen Schlüssel würfeln,
  // der dieselbe sechsstellige Prüfzahl ergibt (rund 10^6 Versuche, Sekunden).
  function kopplungNonce() { return b64u(zufall(16)); }
  function kopplungCommit(pubN, nonce) {
    return sub.digest('SHA-256', verbinden(enc.encode('cs-pair-commit-v1|'), verbinden(unb64u(pubN), unb64u(nonce)))).then(function (h) { return b64u(new Uint8Array(h)); });
  }
  function kopplungsSchluessel(ephPrivat, fremdPub, pubN, pubA, uid, id) {
    return pubImport(fremdPub).then(function (f) { return ecdh(ephPrivat, f); }).then(function (z) {
      return hkdf(z, verbinden(unb64u(pubN), unb64u(pubA)), KOPPEL + '|' + uid + '|' + id, ['encrypt', 'decrypt']);
    });
  }
  // Entsperrtes Gerät: DM-Schlüssel (pkcs8, wie einpacken) für das neue Gerät verschlüsseln. "iv.chiffrat"
  function kopplungEinpacken(dmPrivat, ephPrivat, pubN, pubA, uid, id) {
    return Promise.all([sub.exportKey('pkcs8', dmPrivat), kopplungsSchluessel(ephPrivat, pubN, pubN, pubA, uid, id)]).then(function (x) {
      var iv = zufall(12);
      return sub.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode(KOPPEL + '|' + uid + '|' + id) }, x[1], x[0])
        .then(function (c) { return b64u(iv) + '.' + b64u(c); });
    });
  }
  // Neues Gerät: auspacken. Ob der Schlüssel zum Konto gehört, prüft der Aufrufer (oeffentlichVon gegen /dm/keys/me).
  function kopplungAuspacken(gepackt, ephPrivat, pubN, pubA, uid, id) {
    var t = String(gepackt).split('.');
    if (t.length !== 2) return Promise.reject(new Error('Wrapped key unreadable.'));
    return kopplungsSchluessel(ephPrivat, pubA, pubN, pubA, uid, id).then(function (k) {
      return sub.decrypt({ name: 'AES-GCM', iv: unb64u(t[0]), additionalData: enc.encode(KOPPEL + '|' + uid + '|' + id) }, k, unb64u(t[1]));
    }).then(function (pkcs8) { return sub.importKey('pkcs8', pkcs8, KURVE, true, ['deriveBits']); });
  }

  return {
    kopplungFp: kopplungFp, kopplungZahl: kopplungZahl, kopplungNonce: kopplungNonce, kopplungCommit: kopplungCommit, kopplungEinpacken: kopplungEinpacken, kopplungAuspacken: kopplungAuspacken,
    MAX: MAX, sicherheitsnummer: sicherheitsnummer, b64u: b64u, unb64u: unb64u, saeubern: saeubern, laenge: laenge, prfSalz: prfSalz, codeNeu: codeNeu, codeLesen: codeLesen, codeText: codeText, codeEinpacken: codeEinpacken, codeAuspacken: codeAuspacken,
    neuesPaar: neuesPaar, einpacken: einpacken, auspacken: auspacken, oeffentlichVon: oeffentlichVon,
    verschluesseln: verschluesseln, entschluesseln: entschluesseln, fingerabdruck: fingerabdruck,
    inhaltsSchluessel: inhaltsSchluessel, bildVerschluesseln: bildVerschluesseln, MAX_BILDER: MAX_BILDER, MAX_ALT: MAX_ALT,
    emojiPruefen: emojiPruefen, reaktionVerschluesseln: reaktionVerschluesseln, reaktionEntschluesseln: reaktionEntschluesseln,
    auffuellen: auffuellen, gruppenNameVerschluesseln: gruppenNameVerschluesseln, gruppenNameEntschluesseln: gruppenNameEntschluesseln, MAX_GRUPPENNAME: MAX_GRUPPENNAME, schluesselAus: schluesselAus, MAX_ZITAT: MAX_ZITAT, MAX_DAUER: MAX_DAUER, TONARTEN: TONARTEN,
  };
});
