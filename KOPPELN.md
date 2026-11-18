# Gerät koppeln: Protokoll (Deutsch)

Deutscher Originaltext aus dem europe.social-Repo, gekürzt um die Teile zur Oberfläche. Eine englische Zusammenfassung
steht in [PROTOCOL.md](PROTOCOL.md#33-pairing-a-device). Referenz der Krypto: `public/javascripts/dmcrypto.js`.

Worum es geht: Ein Gerät, auf dem die Direktnachrichten offen sind, gibt den DM-Schlüssel an ein neues Gerät desselben
Kontos weiter, Ende-zu-Ende über Einmal-Schlüssel. Der Server reicht nur die öffentlichen Hälften und das Chiffrat
durch. Dass er nicht dazwischen sitzt, bestätigt der Mensch per Prüfzahl oder QR-Code. Daneben gibt es zwei Wege ohne
zweites Gerät: den Passkey (jeder Passkey, der PRF liefert und noch keine Fassung hat, bekommt eine, sobald der
Schlüssel auf einem Gerät offen ist) und den Wiederherstellungscode (PROTOCOL.md, Abschnitt 3).

## Ablauf

Rollen: **N** (neues Gerät, DMs gesperrt) und **A** (Gerät mit offenem DM-Schlüssel), beide im selben Konto
angemeldet. Referenz der Krypto: `public/javascripts/dmcrypto.js` (`kopplungFp`, `kopplungZahl`, `kopplungEinpacken`,
`kopplungAuspacken`); Prüfvektoren `ios/EuropeKit/Tests/EuropeKitTests/Daten/koppeln.json` (mit `nonce` und `commit`) (erzeugt von
`ios/Werkzeuge/koppel-pruefvektoren.mjs`). Alle öffentlichen Schlüssel: P-256, unkomprimiert 65 Bytes, base64url ohne
Füllzeichen (87 Zeichen), wie überall.

**Seit 2026-11-16 mit Commitment** (Befund einer internen Sicherheitsprüfung):
Vorher schickte N seinen Einmal-Schlüssel gleich im ersten Schritt. Ein bösartiger Server konnte A einen eigenen
Schlüssel geben, nach dem Annehmen pubA lesen und danach für N einen Schlüssel suchen, der dieselbe sechsstellige Zahl
ergibt (rund 10^6 Versuche, wenige Sekunden). Jetzt legt sich N zuerst fest und zeigt pubN erst, wenn A angenommen hat.
Der Server muss sich so auf jeden Schlüssel festlegen, bevor er den anderen kennt; ein Treffer gelingt ihm nur mit
Wahrscheinlichkeit 1 zu 1 000 000 je Versuch, und jeder Versuch kostet eine Bestätigung durch den Menschen. Der QR-Weg
war schon vorher sicher. Anfragen ohne Commitment (alte Fassungen) nimmt der Server nicht mehr an.

| Schritt | Wer | Was |
|---|---|---|
| 1 | N | Einmal-Paar eN und Nonce (16 Bytes) erzeugen, `POST /dm/pair {commit, device}` mit commit = `kopplungCommit(pubN, nonce)` → `{id, commit, pub: null, nonce: null, peer: null, wrapped: null, created_at, expires_at}` (10 Minuten) |
| 2 | N | QR-Code mit `https://europe.social/messages/pair#<id>.<fp>` zeigen, fp = `kopplungFp(pubN)`; alle 2 s `GET /dm/pair/<id>` |
| 3 | A | sieht die Anfrage: `GET /dm/pair` (offene Anfragen des Kontos) oder öffnet den QR-Link; merkt sich `commit` |
| 4 | A | Einmal-Paar eA, `POST /dm/pair/<id>/accept {pub}` (genau einmal und nur vor dem Offenlegen, sonst 409) |
| 5 | N | sieht `peer`, legt offen: `POST /dm/pair/<id>/reveal {pub, nonce}` (genau einmal, nur nach der Annahme; der Server prüft das Commitment) |
| 6 | A | wartet auf `pub` und `nonce`, prüft **selbst** `kopplungCommit(pub, nonce) == commit` aus Schritt 3 und, über den QR-Link, `kopplungFp(pub) == fp`; sonst „This code doesn’t match. Nothing was shared.“ und Abbruch |
| 7 | beide | Prüfzahl = `kopplungZahl(pubN, pubA)` anzeigen. N wartet, A fragt „Zeigt dein anderes Gerät dieselbe Zahl?“. Kam A über den QR-Link und stimmt fp, weiß A schon, dass pubN echt ist, und fragt nur noch, ob das Gerät hinzugefügt werden soll (A zeigt die Zahl trotzdem) |
| 8 | A | nach „Ja“: `kopplungEinpacken(dmPrivat, eA, pubN, pubA, uid, id)` → `POST /dm/pair/<id>/key {wrapped}` (erst nach dem Offenlegen) |
| 9 | N | sieht `wrapped`, `kopplungAuspacken(wrapped, eN, pubN, pubA, uid, id)`, prüft den öffentlichen Schlüssel gegen `/dm/keys/me` (`publicKey`), speichert wie nach dem Code, `POST /dm/pair/<id>/delete` |

Krypto im Einzelnen:

- commit = base64url(SHA-256(utf8("cs-pair-commit-v1|") ‖ pubN_roh ‖ nonce_roh)), 43 Zeichen; nonce 16 Zufallsbytes, base64url (22 Zeichen)
- fp = base64url(SHA-256(utf8("cs-pair-v1|") ‖ pubN_roh)[0..12]), 16 Zeichen
- Prüfzahl = uint32 big endian (SHA-256(utf8("cs-pair-sas-v1|") ‖ pubN_roh ‖ pubA_roh)[0..4]) mod 1 000 000, sechs
  Ziffern mit führenden Nullen; angezeigt als „951 722“
- z = ECDH(eigener Einmal-Schlüssel, fremder Einmal-Schlüssel), 32 Bytes
- k = HKDF-SHA256(ikm z, salt pubN_roh ‖ pubA_roh, info utf8("cs-pair-v1|<uid>|<id>")), 32 Bytes, AES-256-GCM
- wrapped = base64url(iv, 12 Bytes) "." base64url(GCM(k, iv, pkcs8(DM-Schlüssel), aad utf8("cs-pair-v1|<uid>|<id>")))
  — dasselbe Format wie `einpacken` (pkcs8, „iv.chiffrat“)

Server (`lib/routes/nachrichten.js`, Tabelle `dm_pairings`, Spalten `commit_n`, `nonce_n`): jede Sitzung des Kontos darf
jeden Schritt, fremde Konten bekommen 404. Höchstens drei offene Anfragen je Konto (die älteste weicht), nach 10 Minuten
weg (Aufräumen jede Minute). `POST /dm/pair` braucht einen DM-Schlüssel am Konto (sonst 400) und ist gebremst (10 je
Stunde und Konto, `accept`/`reveal`/`key` 60 je Stunde), weil jede Anfrage allen Geräten eine Mitteilung schickt. Der
Server prüft Formate, Reihenfolge und das Commitment; maßgeblich ist die Prüfung auf A.

Warum kein Geheimnis im QR-Code: Er trägt nur den Fingerabdruck des Einmal-Schlüssels von N. Der Server kennt ihn auch;
entscheidend ist, dass A ihn **vom Bildschirm von N** bekommt und nicht vom Server. Darum zeichnet jedes Gerät seinen
QR-Code selbst, nie der Server.

## Was das neue Gerät nicht prüft (bekannte Grenze, Stand 2026-11-19)

Die Prüfzahl und der QR-Code schützen das Gerät A: Es gibt den Schlüssel nur heraus, wenn der Mensch bestätigt hat.
Das neue Gerät N fragt bisher niemanden. Es nimmt den Schlüssel an, der unter dem ausgehandelten Einmal-Schlüssel
ankommt, und vergleicht ihn mit dem öffentlichen Schlüssel, den der Server für das Konto nennt (`/dm/keys/me`). Ein
bösartiger Server könnte eine Kopplungsanfrage deshalb selbst beantworten und N einen eigenen Schlüssel geben. Den
echten Schlüssel bekommt er so nicht, aber was N danach sendet, könnte er lesen; Kontakte mit gemerktem Schlüssel sähen
„sender key changed“. Über den QR-Weg weiß A, dass pubN echt ist, N weiß aber nicht, dass pubA echt ist.

Abhilfe (in Arbeit): Auch N fragt seinen Menschen, ob das andere Gerät dieselbe Zahl zeigt, bevor es einen Schlüssel
annimmt. Die Zahl hängt an beiden Einmal-Schlüsseln; ein untergeschobener Schlüssel ergibt eine andere Zahl, und ohne
ein zweites Gerät, das überhaupt eine Zahl zeigt, gibt es nichts zu bestätigen.
