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
- A message can only be created in the name of an account by someone holding that account's private key.
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

All primitives come from the platform: WebCrypto in browsers, CryptoKit on Apple platforms, the Java standard
library (JCA) on Android. Every derivation and every AES-GCM call is bound to a context string that names its purpose
and, where it matters, the account and conversation (for example `cs-dm-v1|<sender>|<recipient>|<sender key>`), so a
ciphertext cannot be moved into another context without failing authentication.

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
[9.6](#96-no-signatures-deniability)) can produce a wrap that opens.

### 4.3 Envelope

```json
{
  "v": 1,
  "s": "<sender public key>",
  "n": "<iv>",
  "c": "<ciphertext>",
  "k": { "<account>": { "e": "<ephemeral public key>", "n": "<iv2>", "w": "<wrapped K>" } }
}
```

Version 2 adds `"b": [<attachment ids>]` (see 4.4). The receiving client checks that `s` is the key it has pinned for
the sender (section 7) before showing the message as genuine.

The server checks the shape of every envelope before storing it (excerpt in [SERVER.md](SERVER.md)): `s` must equal
the sender's registered public key, and the set of accounts in `k` must be exactly the participants of the
conversation. It cannot check anything inside.

### 4.4 Pictures and voice messages

Each file is encrypted with the same K and its own IV, AAD `cs-dm-bild-v1|<sender>|<recipient>`, and uploaded as
ciphertext. ID, IV, type, dimensions, duration and alt text travel inside the encrypted message. The envelope lists
only the attachment IDs (`b`) so the server can control access and delete files with the message. A swapped or foreign
file fails authentication because its IV belongs to it.

### 4.5 Replies, edits, reactions, group names

- **Replies:** the quoted message number, author and a short excerpt are inside the encrypted content.
- **Edits:** the sender re-encrypts with the same K, so attached pictures stay readable.
- **Reactions:** one emoji per person and message, encrypted like a message with the context
  `cs-dm-reaktion-v1|<message>|<reacting account>|<conversation>|<key>`, so a reaction cannot be moved to another
  message (`reaktionVerschluesseln`).
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

- who sends a message to whom, and when; read state;
- the rough size class of each message (padding), the number and size of attachments;
- group membership, who added or removed whom, when someone left, the disappearing-message timer;
- who reacted to which message and when (not which emoji);
- every account's public key and the wrapped copies of its private key (one per PRF passkey, one for the recovery
  code), which it cannot open;
- short-lived pairing requests: two one-time public keys and the wrapped key, deleted after 10 minutes.

The server does **not** see: message text, quotes, attachments, voice messages, alt texts, which emoji was used,
group names (see 9.7 for the exception), recovery codes, PRF outputs, private keys.

## 9. Known limitations

We list these so you do not have to find them.

### 9.1 No forward secrecy

There is one long-term key per account and no ratchet. Whoever obtains an account's private key later (from a device,
or by obtaining both a wrapped copy and the passkey or recovery code) can read all past messages of that account that
they can get hold of. Signal and similar protocols protect against this; we do not yet.

### 9.2 The web app is delivered by the server

In the browser, the code that encrypts is loaded from europe.social on every visit. A compromised or malicious server
could deliver different code. Open source cannot prevent this by itself, it only makes it detectable:
`tools/check-live.mjs` compares the file the server delivers with this repository. The iPhone, iPad, Mac and Android
apps are distributed through the app stores and do not load code from the server.

### 9.3 The server distributes public keys

On first contact, a client trusts the key the server reports. Pinning (section 7) detects any later change; the
safety number detects a wrong key from the start, if users compare it.

### 9.4 Group membership is managed by the server

Clients encrypt to the member list the server reports. A malicious server could add a member to a group; that member
would receive messages sent after the change. Members see the member list and the "added" event in the conversation,
but the change is not authenticated by the group's members cryptographically.

### 9.5 Metadata

See section 8. Padding hides exact lengths, not the existence, timing or participants of a message.

### 9.6 No signatures, deniability

Messages are authenticated by the ECDH term `z2`, not by a signature. Other members of a group cannot forge a message
from someone else, but the recipient of a wrap could construct a wrap for themselves that appears to come from the
sender. There is therefore no proof a third party could verify that someone sent a message.

### 9.7 Group name not bound to the group

The context of an encrypted group name names the sealing person and key, not the group (so a name can be sealed
before the group exists). The server could move a name into another group of the same person; it cannot read or
invent one. Without JavaScript in the browser, naming or renaming a group sends the name in plaintext; clients replace it with
an encrypted name the next time a member opens the group, and the server then removes the plaintext from the group's
history.

### 9.8 Disappearing messages

The timer is enforced by the server, which deletes the ciphertext. Recipients may have kept a copy.

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
| `saeubern` | sanitise text (control characters, invisible characters) |
| `SchluesselMerken` | remembered (pinned) keys |
