# What the server stores and checks

The europe.social server is not open source. This page shows the parts of it that matter for direct messages: the
database tables that hold DM data, and the function that checks every envelope before it is stored. Both are
excerpts of the production code, taken from commit `7fe4949bd7ec` of the private repository on 2026-11-18. Comments
in the code are German.

## Database tables

Everything the server knows about DMs lives in these SQLite tables. Message content exists only as `envelope`
(see [PROTOCOL.md, section 4.3](PROTOCOL.md#43-envelope)). The column `direct_messages.text` dates from before
encryption; the server writes an empty string into it and does not accept plaintext messages. On 2026-11-18 the
production database held no row with text in it and no row without an envelope.

```sql
CREATE TABLE IF NOT EXISTS direct_messages (
  id INTEGER PRIMARY KEY,
  sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  read INTEGER NOT NULL DEFAULT 0
);
-- added later: envelope TEXT, edited_at INTEGER, expires_at INTEGER

CREATE TABLE IF NOT EXISTS dm_keys (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS dm_key_wraps (
  credential_id TEXT PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  wrapped TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
-- Dieselbe Fassung, eingepackt mit dem Wiederherstellungscode (dmcrypto.js, codeEinpacken), höchstens eine je Konto.
-- Für Passkeys ohne PRF und als Rückweg; den Code kennt nur der Nutzer.
CREATE TABLE IF NOT EXISTS dm_key_codes (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  wrapped TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
-- Gerät koppeln (KOPPELN.md): kurzlebig (10 Minuten), der Server sieht nur Einmal-Schlüssel und Chiffrat.
CREATE TABLE IF NOT EXISTS dm_pairings (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pub_n TEXT NOT NULL,
  pub_a TEXT,
  wrapped TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS dm_pairings_user ON dm_pairings(user_id, expires_at);
-- added later to dm_pairings: device TEXT, commit_n TEXT, nonce_n TEXT

CREATE TABLE IF NOT EXISTS dm_blobs (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message_id INTEGER REFERENCES direct_messages(id) ON DELETE CASCADE,
  groesse INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS dm_blobs_message ON dm_blobs(message_id);
CREATE INDEX IF NOT EXISTS dm_blobs_user ON dm_blobs(user_id, created_at);
-- added later: group_message_id INTEGER

CREATE TABLE IF NOT EXISTS dm_groups (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS dm_group_members (
  group_id INTEGER NOT NULL REFERENCES dm_groups(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  added_by INTEGER,
  joined_at INTEGER NOT NULL,
  last_read_id INTEGER NOT NULL DEFAULT 0,
  muted INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS dm_group_members_user ON dm_group_members(user_id);
CREATE TABLE IF NOT EXISTS dm_group_messages (
  id INTEGER PRIMARY KEY,
  group_id INTEGER NOT NULL REFERENCES dm_groups(id) ON DELETE CASCADE,
  sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  envelope TEXT,
  ereignis TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS dm_group_messages_group ON dm_group_messages(group_id, id);
-- Reaktionen: ein Emoji je Person und Nachricht, verschlüsselt (der Server sieht wer und wann, nicht welches)
CREATE TABLE IF NOT EXISTS dm_reactions (
  id INTEGER PRIMARY KEY,
  message_id INTEGER REFERENCES direct_messages(id) ON DELETE CASCADE,
  group_message_id INTEGER REFERENCES dm_group_messages(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  envelope TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS dm_reactions_message ON dm_reactions(message_id, user_id) WHERE message_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS dm_reactions_group_message ON dm_reactions(group_message_id, user_id) WHERE group_message_id IS NOT NULL;
-- added later: dm_groups.timer, dm_groups.name_env (encrypted name), dm_groups.name_von;
--   dm_group_messages.edited_at, dm_group_messages.expires_at

CREATE TABLE IF NOT EXISTS dm_konv (
  konv TEXT PRIMARY KEY,
  timer INTEGER NOT NULL DEFAULT 0,
  gesetzt_von INTEGER,
  gesetzt_at INTEGER
);
CREATE TABLE IF NOT EXISTS dm_mutes (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  partner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, partner_id)
);
```

`dm_konv` and `dm_mutes` hold the disappearing-message timer and muted conversations. The server additionally knows
each account's settings for who may send DMs, typing indicators and read receipts.

## Envelope check

Every message and reaction passes through this function before it is stored. It checks form and size, that the
envelope names the sender's registered public key, and that the content key is wrapped for exactly the participants
of the conversation. It cannot see or check anything inside the ciphertext.

```js
  // Umschlag prüfen. ziele: Kontonummern, für die eingepackt sein muss (genau diese, man selbst eingeschlossen).
  // reaktion: nur ein Emoji, nie Bilder. gruppe: passt die Liste nicht, hat sich die Mitgliedschaft geändert (409, der
  // Browser holt die Schlüssel neu und versucht es noch einmal)
  function umschlagPruefen(ctx, roh, me, ziele, { reaktion = false, gruppe: inGruppe = false } = {}) {
    const kaputt = T(ctx, 'This message could not be encrypted. Please reload the page.');
    if (typeof roh !== 'string' || roh.length > 40000 + ziele.length * 400) throw new Error(kaputt);
    let e;
    try { e = JSON.parse(roh); } catch { throw new Error(kaputt); }
    // v1: nur Text. v2: Text und Bilder; b listet die Bilder (sichtbar, damit der Server Zugriff und Löschen regeln kann),
    // Art, Maße, Beschreibung und Schlüssel stehen im verschlüsselten Teil
    const v2 = !reaktion && !!e && e.v === 2;
    const ok = x => typeof x === 'string' && x.length <= (v2 ? 30000 : 8000) && B64U.test(x);
    const eigen = get('SELECT public_key FROM dm_keys WHERE user_id = ?', me.id);
    if (!eigen) throw new Error(T(ctx, 'Set up encrypted messages first: open Messages and unlock them with your passkey.'));
    const vorhanden = Object.keys(e?.k || {}).sort();
    const soll = ziele.map(String).sort();
    if (vorhanden.join() !== soll.join()) {
      if (inGruppe && e && e.k && typeof e.k === 'object' && !Array.isArray(e.k)) throw Object.assign(new Error(T(ctx, 'Who’s in this conversation has changed. Please send it again.')), { veraltet: true });
      throw new Error(kaputt);
    }
    if (!e || (e.v !== 1 && !v2) || e.s !== eigen.public_key || !ok(e.n) || !ok(e.c)
      || !vorhanden.every(z => e.k[z] && ok(e.k[z].e) && ok(e.k[z].n) && ok(e.k[z].w) && Object.keys(e.k[z]).length === 3)
      || Object.keys(e).length !== (v2 ? 6 : 5)) throw new Error(kaputt);
    if (v2 && !(Array.isArray(e.b) && e.b.length <= MAX_BILDER && new Set(e.b).size === e.b.length && e.b.every(x => typeof x === 'string' && BILD_ID.test(x)))) throw new Error(kaputt);
    const grenze = reaktion ? 64 : MAX * 4 + (v2 ? MAX_BILDER * (MAX_ALT * 4 + 200) + 64 + 700 : 0) + 16;
    if (Buffer.from(e.c, 'base64url').length > grenze) throw new Error(reaktion ? kaputt : T(ctx, 'Messages can be up to {n} characters.', { n: MAX }));
    return { text: JSON.stringify(e), bilder: v2 ? e.b : [] };
  }
```
