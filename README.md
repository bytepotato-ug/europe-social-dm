# europe.social: encrypted direct messages

This repository contains the code that encrypts and decrypts direct messages on [europe.social](https://europe.social),
in the browser and in the apps for iPhone, iPad, Mac and Android. It is published so that anyone can check how it
works. Everything else about europe.social (server, website, apps around this core) is not part of it.

- **[PROTOCOL.md](PROTOCOL.md)**: how it works, what the server sees, and the known limitations
- **[SERVER.md](SERVER.md)**: the database tables and the envelope check of the (closed) server
- **[KOPPELN.md](KOPPELN.md)**: the device pairing protocol in detail (German)
- **[SECURITY.md](SECURITY.md)**: how to report a problem

## In short

- Every account has its own key pair, created on the user's device. The private key reaches the server only
  encrypted, unlocked by a passkey (WebAuthn PRF), a recovery code, or handed over from another device of the same
  account.
- Each message gets a fresh key (AES-256-GCM). That key is wrapped for every participant with ECDH (P-256) and HKDF.
  Text, pictures, voice messages, replies, reactions and group names are encrypted.
- Apps remember the keys of the people you write with and warn you when one changes. A safety number lets two people
  check that nobody is in between.
- Only platform cryptography: WebCrypto, CryptoKit, the Java standard library. No third-party crypto library.

What the server can still see (who writes to whom and when, group membership) and what this design does not protect
against (no forward secrecy yet, among others) is written down in
[PROTOCOL.md, sections 8 and 9](PROTOCOL.md#8-what-the-server-sees).

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

Code identifiers and comments are German; [PROTOCOL.md](PROTOCOL.md#10-glossary) has a glossary.

## Running the tests

```bash
node --test test/*.test.mjs                
(cd ios/EuropeKit && swift test)           # Swift, needs Xcode
(cd android && ./gradlew :kern:test)       # Kotlin, needs a JDK 21 or newer
```

All three read the same test vectors: a message encrypted in the browser must open in Swift and Kotlin, and the
Kotlin tests also encrypt and let the web code open the result (if Node is installed).

## Is this really the code that runs?

- **Browser:** yes, and you can check it yourself at any time:

  ```bash
  node tools/check-live.mjs
  ```

  It downloads `dmcrypto.js` the way your browser does and compares it with this repository. The CI of this repository
  runs the same check every day. The CI of the private europe.social repository refuses to deploy if any file here
  differs from the one in production.
- **Apps:** the apps are built from exactly these source files (same check). The app store builds are not
  reproducible, so you cannot verify a downloaded app binary against this source.

## License

Copyright BYTEPOTATO UG (haftungsbeschränkt). Licensed under the GNU Affero General Public License v3.0, see
[LICENSE](LICENSE). europe.social and the europe.social logo are not covered by this license.

---

## Kurz auf Deutsch

Hier liegt der Code, mit dem europe.social Direktnachrichten im Browser und in den Apps ver- und entschlüsselt,
Datei für Datei derselbe wie in Produktion. Er ist öffentlich, damit jeder prüfen kann, dass wir eure Nachrichten
nicht lesen können. Wie das Verfahren funktioniert, was der Server trotzdem sieht und wo die Grenzen liegen, steht in
[PROTOCOL.md](PROTOCOL.md). Ob die Seite genau diesen Code ausliefert, prüft `node tools/check-live.mjs`.
Sicherheitslücken bitte vertraulich melden, siehe [SECURITY.md](SECURITY.md).
