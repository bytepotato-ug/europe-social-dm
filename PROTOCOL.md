# europe.social direct messages: protocol

This document describes how direct messages (DMs) on europe.social are encrypted. It is written against the code in
this repository, which is byte for byte the code that runs on europe.social and in the apps (see
[README.md](README.md#is-this-really-the-code-that-runs)). Where this document and the code disagree, the code wins;
please report the difference.

The reference implementation is [`public/javascripts/dmcrypto.js`](public/javascripts/dmcrypto.js) (WebCrypto only,
no third-party library). The Swift ([`ios/EuropeKit/Sources/EuropeKit`](ios/EuropeKit/Sources/EuropeKit)) and Kotlin
([`android/kern/src/main/kotlin`](android/kern/src/main/kotlin/com/bytepotato/europesocial/kern)) implementations
are tested against shared test vectors produced by the reference.

Identifiers in the code are German. A short glossary is at the end.

## 1. Goals and non-goals

**Goals**

- The server stores and forwards DMs but cannot read their content: text, pictures, voice messages, replies (quotes),
  reactions and group names.
- A message can only be created in the name of an account by someone holding that account's private key, and what
  arrives is what that account wrote ([4.3](#43-binding-the-wraps-to-the-content), with the limits in
  [9.6](#96-no-signatures-deniability-and-messages-without-binding)).
- Users can check that they talk to the right key (safety number) and are warned when a contact's key changes.
- Losing a device does not lose the messages: the key can be unlocked with a passkey, a recovery code, or handed
  over from another device.

**Non-goals (today)**

- Forward secrecy and post-compromise security. See [section 9](#9-known-limitations).
- Hiding metadata (who writes to whom, when, how often). See [section 8](#8-what-the-server-sees).

## 2. Building blocks

| Purpose | Primitive |
|---|---|
| Key agreement | ECDH on NIST P-256 |
| Symmetric encryption | AES-256-GCM, 12-byte random IV, 16-byte tag |
| Key derivation | HKDF-SHA-256 |
| Hashing | SHA-256 |
| Encoding | base64url without padding; public keys as uncompressed points (65 bytes, 87 characters) |

The primitives come from the platform: WebCrypto in browsers, CryptoKit on Apple platforms, the Java standard
library (JCA) on Android. No third-party cryptography library is used. Two things JCA does not offer are written out in
[`Krypto.kt`](android/kern/src/main/kotlin/com/bytepotato/europesocial/kern/Krypto.kt): HKDF (RFC 5869, a few lines
over the platform's HMAC) and deriving the public key from a private key that was just unwrapped (one point
multiplication on P-256 with `BigInteger`, not constant time; it runs once, locally, when a key is imported, and its
result is compared with the public key the account is known by).

Every derivation and every AES-GCM call is bound to a context string that names its purpose and, where it matters,
the account and conversation (for example `cs-dm-v1|<sender>|<recipient>|<sender key>`), so a ciphertext cannot be
moved into another context without failing authentication.

## 3. Account key

Each account has **one** long-term ECDH key pair (`neuesPaar`). It is created on the user's device. The server
stores the public key and serves it to other users. The private key never reaches the server unencrypted.

All devices of an account share this key. It reaches a new device in one of three ways, all of which encrypt the
private key (PKCS#8) with AES-256-GCM under a key the server never sees:

### 3.1 Passkey (WebAuthn PRF)

- PRF input: `SHA-256("europe.social e2ee v1")`, the same for all accounts. It does not need to be secret; the secret
  is inside the authenticator.
- The authenticator returns the PRF output only after user verification (Touch ID, Face ID, PIN).
- Wrapping key: `HKDF(ikm = PRF output, salt = empty, info = "cs-wrap-v1|<account>|<credential id>")`
- Wrapped key: `iv "." AES-GCM(wrapping key, iv, pkcs8, aad = "cs-wrap-v1|<account>")`
- The server stores one wrapped copy per passkey (`einpacken` / `auspacken`).

When the key is unlocked on a device, every passkey of the account that supports PRF and has no wrapped copy yet
receives one automatically.

### 3.2 Recovery code

For passkeys without PRF (some password managers, Firefox on Android) and as a way back for everyone.

- 20 random bytes (160 bit), shown as 32 characters of Crockford base32 in groups of four.
- Wrapping key: `HKDF(ikm = code bytes, salt = empty, info = "cs-code-v1|<account>")`, AAD `cs-code-v1|<account>`.
- No slow key derivation: guessing 2^160 values is not feasible.
- The server stores one wrapped copy per account and never sees the code (`codeEinpacken` / `codeAuspacken`).

### 3.3 Pairing a device

An unlocked device hands the key to a new device of the same account over ECDH between two one-time keys. The human
confirms the pairing by comparing a six-digit number or by scanning a QR code shown on the new device. The new device
first commits to its one-time key (`SHA-256("cs-pair-commit-v1|" ‖ pub ‖ nonce)`) and reveals it only after the other
device has answered, so a malicious server cannot search for a key that produces the same six digits.
The full protocol, message by message, is in [KOPPELN.md](KOPPELN.md).

## 4. Messages

Implemented in `versiegeln`, `oeffnen`, `verschluesseln` and `entschluesseln`.

### 4.1 Content

1. A fresh random 256-bit content key **K** per message.
2. The plaintext is padded with spaces to the next size step (64, 128, 256, ... bytes, capped at the maximum message
   size), so the ciphertext size reveals only a rough length class (`auffuellen`).
3. `c = AES-GCM(K, iv, padded plaintext, aad = context)` with context
   `cs-dm-v1|<sender account>|<recipient account or g<group>>|<sender public key>`.

Version 1 carries text only. Version 2 carries JSON `{ t: text, a: [attachments], q: quote }`.

### 4.2 Key wrapping, per recipient

K is wrapped separately for every recipient **and for the sender** (so the sender can read their own messages on
other devices). For each target with public key P:

1. A fresh ephemeral key pair E.
2. `z1 = ECDH(E, P)`, `z2 = ECDH(S, P)` where S is the sender's long-term private key.
3. `KEK = HKDF(ikm = z1 ‖ z2, salt = E public key, info = context "|" <target account>)`
4. `w = AES-GCM(KEK, iv2, K)`

`z2` binds the sender's long-term key: only someone holding S (or the recipient's own private key, see
[9.6](#96-no-signatures-deniability-and-messages-without-binding)) can produce a wrap that opens.

### 4.3 Binding the wraps to the content

A wrap only says "S gave K to this recipient". K itself is known to every recipient, so without a further step a
recipient could encrypt different content under K and reuse the sender's wraps for the other recipients. Since
2026-11-19 every wrap therefore carries a tag over the visible parts of the envelope:

1. `BK = HKDF(ikm = z2, salt = E public key, info = context "|" <target account> "|bind-v1")`
2. `t = HMAC-SHA-256(BK, "cs-dm-bind-v1|" v "|" n "|" c "|" <attachment ids joined by ",">)`

BK comes from `z2 = ECDH(S, P)` alone, so only the sender and this one recipient can compute it. The receiving client
recomputes `t` before it decrypts anything; if it does not match, the message is rejected. The tag covers the version
`v`, the IV `n`, the ciphertext `c` and the attachment list `b`, so none of them can be altered. The same applies to
reactions and group names, which use the same envelope. Implemented in `bindeText`, `bindeSchluessel`, `versiegeln`
and `oeffnen`; `entschluesseln` reports for every message whether it was bound (`gebunden`).

Clients released before 2026-11-19 neither send nor check `t`; they ignore the field. What that means during the
transition is in [9.6](#96-no-signatures-deniability-and-messages-without-binding).

### 4.4 Envelope

```json
{
  "v": 1,
  "s": "<sender public key>",
  "n": "<iv>",
  "c": "<ciphertext>",
  "k": { "<account>": { "e": "<ephemeral public key>", "n": "<iv2>", "w": "<wrapped K>", "t": "<binding tag>" } }
}
```

Version 2 adds `"b": [<attachment ids>]` (see 4.5). The receiving client checks that `s` is the key it has pinned for
the sender (section 7) before showing the message as genuine.

The server checks the shape of every envelope before storing it (excerpt in [SERVER.md](SERVER.md)): `s` must equal
the sender's registered public key, and the set of accounts in `k` must be exactly the participants of the
conversation. It cannot check anything inside, and it cannot recompute `t`.

### 4.5 Pictures and voice messages

Each file is encrypted with the same K and its own IV, AAD `cs-dm-bild-v1|<sender>|<recipient>`, and uploaded as
ciphertext. ID, IV, type, dimensions, duration and alt text travel inside the encrypted message. The envelope lists
only the attachment IDs (`b`) so the server can control access and delete files with the message. A swapped or foreign
file fails authentication because its IV belongs to it.

### 4.6 Replies, edits, reactions, group names

- **Replies:** the quoted message number, author and a short excerpt are inside the encrypted content.
- **Edits:** the sender re-encrypts with the same K, so attached pictures stay readable.
- **Reactions:** one emoji per person and message, encrypted like a message with the context
  `cs-dm-reaktion-v1|<message>|<reacting account>|<conversation>|<key>`, so a reaction cannot be moved to another
  message (`reaktionVerschluesseln`). The emoji is padded with spaces to a fixed 48 bytes, so every reaction has the
  same ciphertext size (since 2026-11-19; before that the size gave away which group of emoji it was).
- **Group names:** encrypted for all members with the context `cs-dm-gname-v1|<sealing account>|<key>`
  (`gruppenNameVerschluesseln`). See [9.7](#97-group-name-not-bound-to-the-group).

## 5. Groups

A group message is a normal envelope with one wrap per current member (up to the group size limit). The conversation
identifier in the context is `g<group number>`. Membership changes are made through the server, which records them as
plaintext events ("A added B"). Clients always encrypt to the member list the server reports; see
[9.4](#94-group-membership-is-managed-by-the-server).

## 6. Notifications

The server only knows that a message exists, not what it says. A notification therefore reads "New encrypted message"
with the sender's display name. On iPhone and iPad the notification payload is additionally encrypted for the device so
that Apple's push service sees only ciphertext; the tag Apple sees is an HMAC, not the conversation ID.

## 7. Verifying keys

- **Pinning (trust on first use):** clients remember the public key of every contact (`SchluesselMerken`). If a
  contact's key changes, the message is marked "sender key changed" and the user is asked once to accept the new key.
  Before sending, the client checks the keys of all participants against the pinned ones and asks once if one has
  changed.
- **Safety number:** both people in a conversation see the same 40-digit number,
  `SHA-256("cs-sicherheitsnummer-v1" ‖ smaller key ‖ larger key)`, as eight groups of five digits
  (`sicherheitsnummer`). If the numbers differ, someone is in the middle.

## 8. What the server sees

The server stores and therefore knows:

- who sends a message to whom, and when; that and when a message was edited or deleted; read state;
- typing notices and read receipts as they pass through, if the account has them switched on, and each account's
  settings for them and for who may send it DMs;
- which conversations and groups an account has muted;
- the rough size class of each message (padding), the number and size of attachments;
- group membership, who added or removed whom, when someone left, the disappearing-message timer and who set it;
- who reacted to which message and when (not which emoji; reactions from clients released before 2026-11-19 are not
  padded, their size narrows the emoji down to a group);
- every account's public key and the wrapped copies of its private key (one per PRF passkey, one for the recovery
  code), which it cannot open;
- short-lived pairing requests: the commitment, two one-time public keys, the nonce, the name the new device gives
  itself ("Firefox on Mac") and the wrapped key, deleted after 10 minutes.

The tables are listed in [SERVER.md](SERVER.md).

The server does **not** see: message text, quotes, attachments, voice messages, alt texts, which emoji was used,
group names (see 9.7 for the exception), recovery codes, PRF outputs, private keys.

## 9. Known limitations

We list these so you do not have to find them.

### 9.1 No forward secrecy

There is one long-term key per account and no ratchet. Whoever obtains an account's private key later (from a device,
or by obtaining both a wrapped copy and the passkey or recovery code) can read all past messages of that account that
they can get hold of. Signal and similar protocols protect against this; we do not yet.

### 9.2 The web app is delivered by the server, and only its crypto core is public

In the browser, all code is loaded from europe.social on every visit. A compromised or malicious server could deliver
different code. Open source cannot prevent this. `tools/check-live.mjs` compares the one file in this repository that
runs in the browser, `dmcrypto.js`, with what the server delivers to the machine that runs the check. That is all it
shows:

- The rest of the web client is not public: the page and its other scripts, which call this file, keep the unlocked
  key in the browser (IndexedDB), remember contacts' keys and put the decrypted text on the screen. A changed copy of
  those could read messages without touching `dmcrypto.js`.
- A server could answer the check differently from a real visitor.

So publishing this file lets you read and test how the encryption works; it does not prove what a given browser was
sent. The page allows scripts only from europe.social itself (Content Security Policy, no inline scripts). The
iPhone, iPad, Mac and Android apps are distributed through the app stores and do not load code from the server; their
builds are not reproducible (see [README](README.md#is-this-really-the-code-that-runs)).

### 9.3 The server distributes public keys

On first contact, a client trusts the key the server reports. Pinning (section 7) detects any later change; the
safety number detects a wrong key from the start, if users compare it.

### 9.4 Group membership is managed by the server

Clients encrypt to the member list the server reports. A malicious server could add a member to a group; that member
would receive messages sent after the change. Members see the member list and the "added" event in the conversation,
but the change is not authenticated by the group's members cryptographically.

### 9.5 Metadata

See section 8. Padding hides exact lengths, not the existence, timing or participants of a message.

### 9.6 No signatures, deniability, and messages without binding

Messages are authenticated by the ECDH term `z2` and the binding tag ([4.3](#43-binding-the-wraps-to-the-content)),
not by a signature. The recipient of a wrap can compute everything the sender can for that one wrap, so they could
construct a message to themselves that appears to come from the sender. There is therefore no proof a third party
could verify that someone sent a message.

**Messages without a binding tag.** Until 2026-11-19 no client sent the tag, and an earlier version of this document
claimed that other members of a group cannot forge a message from someone else. That was wrong: anyone who had
received a message knew its content key K and could encrypt other content under K, leaving the sender's wraps for
the other recipients (and for the sender's own devices) in place. The result opened as a message from the sender.
Storing such an envelope needs the server's help or write access to its database, because the server only accepts an
envelope from the account named in `s`; but a server that helps is exactly what end-to-end encryption is meant to
withstand. An outside review found this on 2026-11-18; the binding tag closes it for every message that carries one.

What is still open during the transition:

- App versions released before 2026-11-19 do not send the tag. Their messages, and every message stored before that
  date, can still be altered as described.
- Because such messages must stay readable, current clients accept an envelope without tags and report it as not
  bound (`gebunden: false`). A malicious server could strip the tags from a new message to make it look like an old
  one. The website and the apps do not show this difference to the user yet.

Removing this needs two more steps, in this order: senders add tags to their old messages (the tag key is derived
from `z2` alone so that this is possible afterwards), then clients refuse messages without tags. This section will
say so when it is done.

### 9.7 Group name not bound to the group

The context of an encrypted group name names the sealing person and key, not the group (so a name can be sealed
before the group exists). The server could move a name into another group of the same person; it cannot read or
invent one. Without JavaScript in the browser, naming or renaming a group sends the name in plaintext; clients replace it with
an encrypted name the next time a member opens the group, and the server then removes the plaintext from the group's
history.

### 9.8 Disappearing messages

The timer is enforced by the server, which deletes the ciphertext. Recipients may have kept a copy.

### 9.9 Replay, order, withholding

Nothing ties an envelope to its message number or to a time. The server assigns both. It could deliver an old
message a second time, show messages in a different order or with a different time, withhold a message, an edit or
a deletion, or bring back a reaction its author removed. It cannot change what a bound message says, move a message
into another conversation, or attach a reaction to another message.

### 9.10 The device that receives the key during pairing

Pairing protects the device that hands the key over: it only does so after the human has compared the number or
scanned the code ([3.3](#33-pairing-a-device)). The new device, in turn, accepts the key it is sent and checks it
against the public key the server reports for the account. A malicious server could therefore answer a pairing
request itself and hand the new device a key of its own; messages that device then sends would be readable by the
server, and contacts who have the real key pinned would see a "sender key changed" warning. The server cannot obtain
the real key this way. Planned, not built yet: the new device will also ask its user to confirm the number before it
accepts a key.

## 10. Glossary

| Code | Meaning |
|---|---|
| `verschluesseln` / `entschluesseln` | encrypt / decrypt a message |
| `versiegeln` / `oeffnen` / `umschlag` | seal / open / envelope |
| `einpacken` / `auspacken` | wrap / unwrap a private key |
| `schluessel`, `privat`, `oeffentlich` | key, private, public |
| `sid`, `rid`, `ich` | sender, recipient, own account |
| `empfaenger`, `ziele` | recipients, targets of the wraps |
| `anhang`, `bild`, `zitat`, `reaktion` | attachment, picture, quote, reaction |
| `gruppenName` | group name |
| `kopplung` | device pairing |
| `pruefzahl`, `sicherheitsnummer`, `fingerabdruck` | check number, safety number, fingerprint |
| `auffuellen` | pad |
| `bindeText`, `bindeSchluessel`, `gebunden` | what the binding tag covers, its key, bound |
| `saeubern` | sanitise text (control characters, invisible characters) |
| `SchluesselMerken` | remembered (pinned) keys |

## 11. Changes to the protocol

| Date | Change |
|---|---|
| 2026-11-12 | Recovery code as a second way to unlock the key (3.2) |
| 2026-11-15 | Pairing a device (3.3) |
| 2026-11-16 | Pairing: the new device commits to its one-time key first (found in an internal review) |
| 2026-11-19 | Wraps bound to the content (4.3); reactions padded to a fixed size (4.6); replies written by the Android code are readable in the Swift code (a missing field made the whole message unreadable); the Swift code accepts emoji made of several parts as reactions. Found in an outside review on 2026-11-18, the day this repository was published. |
