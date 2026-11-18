# europe.social: encrypted direct messages

This repository contains the code that encrypts and decrypts direct messages on [europe.social](https://europe.social),
in the browser and in the apps for iPhone, iPad, Mac and Android. It is published so that anyone can read, run and
test how it works. Everything else about europe.social (server, website, apps around this core) is not part of it;
what that means for what you can and cannot verify is in
[PROTOCOL.md, section 9.2](PROTOCOL.md#92-the-web-app-is-delivered-by-the-server-and-only-its-crypto-core-is-public).

- **[PROTOCOL.md](PROTOCOL.md)**: how it works, what the server sees, and the known limitations
- **[SERVER.md](SERVER.md)**: the database tables and the envelope check of the (closed) server
- **[KOPPELN.md](KOPPELN.md)**: the device pairing protocol in detail (German)
- **[SECURITY.md](SECURITY.md)**: how to report a problem

## In short

- Every account has its own key pair, created on the user's device. The private key reaches the server only
  encrypted, unlocked by a passkey (WebAuthn PRF), a recovery code, or handed over from another device of the same
  account.
- Each message gets a fresh key (AES-256-GCM). That key is wrapped for every participant with ECDH (P-256) and HKDF,
  and every wrap is bound to the exact content with an HMAC, so a recipient cannot put other words under the sender's
  name. Text, pictures, voice messages, replies, reactions and group names are encrypted.
- Apps remember the keys of the people you write with and warn you when one changes. A safety number lets two people
  check that nobody is in between.
- No third-party crypto library: WebCrypto, CryptoKit, the Java standard library. Two small pieces the Java library
  lacks are written out in the Kotlin code (HKDF, and deriving a public key from a private one), see
  [PROTOCOL.md, section 2](PROTOCOL.md#2-building-blocks).

What the server can still see (who writes to whom and when, group membership) and what this design does not protect
against (no forward secrecy yet, among others) is written down in
[PROTOCOL.md, sections 8 and 9](PROTOCOL.md#8-what-the-server-sees). What changed and why is in
[section 11](PROTOCOL.md#11-changes-to-the-protocol); the first outside review, on the day of publication, found a way
for a recipient to forge a message with the server's help. The binding closes it for messages sent by current
clients; what remains during the transition is in
[section 9.6](PROTOCOL.md#96-no-signatures-deniability-and-messages-without-binding).

## Layout

The paths are the same as in the europe.social repository, so the files can be compared one to one.

| Path | What |
|---|---|
| `public/javascripts/dmcrypto.js` | Reference implementation, runs in the browser and in Node |
| `ios/EuropeKit/` | Swift package (CryptoKit) used by the iPhone, iPad and Mac apps |
| `android/kern/` | Kotlin module (JVM) used by the Android app |
| `ios/EuropeKit/Tests/EuropeKitTests/Daten/` | Shared test vectors, produced by the reference implementation |
| `ios/Werkzeuge/` | Scripts that produce the test vectors |
| `test/` | Tests for the web code |
| `tools/check-live.mjs` | Compares the file europe.social delivers with this repository |

Code identifiers and comments are German; [PROTOCOL.md](PROTOCOL.md#10-glossary) has a glossary. Some comments
mention files of the private repository that are not here (`public/javascripts/app.js`, `lib/text.js`,
`lib/routes/nachrichten.js`, `ios/PLAN.md`, `Konten`); the part of `nachrichten.js` that checks envelopes is quoted
in [SERVER.md](SERVER.md).

## Running the tests

```bash
node --test test/*.test.mjs                # web, Node 20 or newer
(cd ios/EuropeKit && swift test)           # Swift, needs Xcode
(cd android && ./gradlew :kern:test)       # Kotlin, needs a JDK 21 or newer
```

All three read the same test vectors: a message encrypted in the browser must open in Swift and Kotlin. In the other
direction, the Kotlin tests encrypt and let the web code open the result (skipped if Node is not installed), and the
Swift tests write what they encrypted to a file that the CI opens with the web code
(`node ios/Werkzeuge/dm-pruefvektoren.mjs --pruefen "$TMPDIR/europe-dm-swift.json"`).

## Is this really the code that runs?

- **Browser:** for the file in this repository, you can check it yourself at any time:

  ```bash
  node tools/check-live.mjs
  ```

  It downloads `dmcrypto.js` the way a browser does and compares it with this repository. The CI of this repository
  runs the same check every day. The CI of the private europe.social repository refuses to deploy if any file here
  differs from the one in production. The check covers this one file as delivered to the machine that runs it; the
  page and the other scripts of the web client, which call this file and handle keys and text, are not public. See
  [PROTOCOL.md, section 9.2](PROTOCOL.md#92-the-web-app-is-delivered-by-the-server-and-only-its-crypto-core-is-public).
- **Apps:** the apps are built from exactly these source files (same check). The app store builds are not
  reproducible, so you cannot verify a downloaded app binary against this source.

## License

Copyright BYTEPOTATO UG (haftungsbeschränkt). Licensed under the GNU Affero General Public License v3.0, see
[LICENSE](LICENSE). europe.social and the europe.social logo are not covered by this license.

---

## Kurz auf Deutsch

Hier liegt der Code, mit dem europe.social Direktnachrichten im Browser und in den Apps ver- und entschlüsselt,
Datei für Datei derselbe wie in Produktion. Er ist öffentlich, damit jeder nachlesen, ausführen und testen kann, wie
die Verschlüsselung arbeitet. Wie das Verfahren funktioniert, was der Server trotzdem sieht und wo die Grenzen liegen,
steht in [PROTOCOL.md](PROTOCOL.md). Ob die Seite genau diese Datei ausliefert, prüft `node tools/check-live.mjs`;
der übrige Web-Client ist nicht öffentlich, was das für die Prüfbarkeit heißt, steht in PROTOCOL.md, Abschnitt 9.2.
Sicherheitslücken bitte vertraulich melden, siehe [SECURITY.md](SECURITY.md).
