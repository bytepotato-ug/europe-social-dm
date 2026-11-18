import CryptoKit
import Foundation

/// Direktnachrichten, bitgenau wie public/javascripts/dmcrypto.js (dort steht das Verfahren ausführlich):
/// Inhaltsschlüssel K (AES-256-GCM, Zusatzdaten = Kontext), K je Ziel eingepackt mit
/// KEK = HKDF-SHA256(ECDH(E, P) ‖ ECDH(S, P), Salz = E roh, Info = Kontext|Ziel). Ziele sind Empfänger und Absender,
/// in Gruppen alle Mitglieder. Bilder mit demselben K und eigenem IV. Geprüft gegen Vektoren aus dem Browser-Code.
public enum DmKrypto {
    public static let hoechstens = 1000
    public static let hoechstensBilder = 4
    static let bildArten = ["image/webp", "image/jpeg", "image/gif"]
    static let tonArten = ["audio/webm", "audio/mp4", "audio/ogg"]

    public enum Fehler: Error, Equatable { case nichtFuerMich, unbekannteFassung, unlesbar, leer, schluessel }

    /// Sichtbarer Teil auf dem Server: v, s (Absender), n (IV), c (Chiffrat), k (je Ziel), b (Anhänge, nur v2)
    public struct Umschlag: Codable, Sendable {
        public struct Eingepackt: Codable, Sendable { let e: String; let n: String; let w: String }
        let v: Int
        let s: String
        let n: String
        let c: String
        let k: [String: Eingepackt]
        let b: [String]?
    }

    /// Anhang im verschlüsselten Teil: Bild (typ, b, h, alt) oder Sprachnachricht (typ, d)
    public struct Anhang: Codable, Hashable, Sendable {
        public let id: String
        public let n: String
        public let typ: String
        public var b: Int?
        public var h: Int?
        public var alt: String?
        public var d: Int?
        public init(id: String, n: String, typ: String, b: Int? = nil, h: Int? = nil, alt: String? = nil, d: Int? = nil) {
            self.id = id; self.n = n; self.typ = typ; self.b = b; self.h = h; self.alt = alt; self.d = d
        }
        public var istTon: Bool { DmKrypto.tonArten.contains(typ) }

        /// dmcrypto.js, anhangPruefen: alles Unbekannte fällt weg
        func geprueft() -> Anhang? {
            guard id.range(of: #"^[A-Za-z0-9_-]{22}$"#, options: .regularExpression) != nil,
                  n.range(of: #"^[A-Za-z0-9_-]{16}$"#, options: .regularExpression) != nil else { return nil }
            if DmKrypto.tonArten.contains(typ) {
                guard let d, (1...300).contains(d) else { return nil }
                return Anhang(id: id, n: n, typ: typ, d: d)
            }
            guard DmKrypto.bildArten.contains(typ), let b, let h, (1...8192).contains(b), (1...8192).contains(h) else { return nil }
            return Anhang(id: id, n: n, typ: typ, b: b, h: h, alt: String(DmKrypto.saeubern(alt ?? "").unicodeScalars.prefix(500).map(Character.init)))
        }
    }

    /// Antwort auf eine bestimmte Nachricht: Nummer, Absender, kurzer Auszug
    public struct Zitat: Codable, Hashable, Sendable {
        public let id: Int
        public let von: Int
        public let t: String
        public let bild: Bool
        public init(id: Int, von: Int, t: String, bild: Bool) { self.id = id; self.von = von; self.t = t; self.bild = bild }
    }

    /// Entschlüsselter Inhalt einer Nachricht
    public struct Inhalt: Sendable {
        public let text: String
        public let absenderSchluessel: String
        public let anhaenge: [Anhang]
        public let zitat: Zitat?
        /// Inhaltsschlüssel (zum Entschlüsseln der Anhänge und zum Bearbeiten mit gleichen Bildern)
        public let schluessel: SymmetricKey
    }

    // MARK: Kontexte (Zusatzdaten und HKDF-Info)

    static func kontext(sid: String, rid: String, s: String) -> String { "cs-dm-v1|\(sid)|\(rid)|\(s)" }
    static func reaktionsKontext(mid: Int, sid: Int, konv: String, s: String) -> String { "cs-dm-reaktion-v1|\(mid)|\(sid)|\(konv)|\(s)" }
    static func bildKontext(sid: String, rid: String) -> Data { Data("cs-dm-bild-v1|\(sid)|\(rid)".utf8) }

    /// Unterhaltung zu zweit, gleich aus beiden Blickwinkeln
    public static func konv(_ a: Int, _ b: Int) -> String { "p\(min(a, b))-\(max(a, b))" }

    // MARK: Kern

    static func oeffentlich(_ b64: String) throws -> P256.KeyAgreement.PublicKey {
        guard let roh = Data(b64u: b64), roh.count == 65, roh.first == 4 else { throw Fehler.schluessel }
        return try P256.KeyAgreement.PublicKey(x963Representation: roh)
    }

    static func ecdh(_ privat: P256.KeyAgreement.PrivateKey, _ oeff: P256.KeyAgreement.PublicKey) throws -> Data {
        try privat.sharedSecretFromKeyAgreement(with: oeff).withUnsafeBytes { Data($0) }
    }

    static func kek(_ z1: Data, _ z2: Data, eph: Data, basis: String, fuer: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: z1 + z2), salt: eph, info: Data("\(basis)|\(fuer)".utf8), outputByteCount: 32)
    }

    /// klar mit K verschlüsseln und K für jedes Ziel ({ Kontonummer: öffentlicher Schlüssel }, Absender eingeschlossen) einpacken
    static func versiegeln(basis: String, klar: Data, privat: P256.KeyAgreement.PrivateKey, pub: String, ziele: [String: String],
                           v: Int, b: [String]?, schluessel: SymmetricKey? = nil) throws -> String {
        let k = schluessel ?? SymmetricKey(size: .bits256)
        let kiste = try AES.GCM.seal(klar, using: k, nonce: AES.GCM.Nonce(), authenticating: Data(basis.utf8))
        let kRoh = k.withUnsafeBytes { Data($0) }
        var eingepackt: [String: Umschlag.Eingepackt] = [:]
        for (fuer, zielPub) in ziele {
            let p = try oeffentlich(zielPub)
            let eph = P256.KeyAgreement.PrivateKey()
            let ephRoh = eph.publicKey.x963Representation
            let kk = kek(try ecdh(eph, p), try ecdh(privat, p), eph: ephRoh, basis: basis, fuer: fuer)
            let w = try AES.GCM.seal(kRoh, using: kk, nonce: AES.GCM.Nonce())
            eingepackt[fuer] = .init(e: ephRoh.b64u, n: Data(w.nonce).b64u, w: (w.ciphertext + w.tag).b64u)
        }
        let u = Umschlag(v: v, s: pub, n: Data(kiste.nonce).b64u, c: (kiste.ciphertext + kiste.tag).b64u, k: eingepackt, b: b)
        return String(decoding: try JSONEncoder().encode(u), as: UTF8.self)
    }

    static func oeffnen(_ u: Umschlag, basis: String, ich: Int, privat: P256.KeyAgreement.PrivateKey) throws -> (Data, SymmetricKey) {
        guard let mein = u.k[String(ich)], let ephRoh = Data(b64u: mein.e) else { throw Fehler.nichtFuerMich }
        let kk = kek(try ecdh(privat, try oeffentlich(mein.e)), try ecdh(privat, try oeffentlich(u.s)), eph: ephRoh, basis: basis, fuer: String(ich))
        let kRoh = try AES.GCM.open(try kiste(mein.n, mein.w), using: kk)
        let k = SymmetricKey(data: kRoh)
        let klar = try AES.GCM.open(try kiste(u.n, u.c), using: k, authenticating: Data(basis.utf8))
        return (klar, k)
    }

    static func kiste(_ iv: String, _ c: String) throws -> AES.GCM.SealedBox {
        guard let iv = Data(b64u: iv), let c = Data(b64u: c), c.count >= 16 else { throw Fehler.unlesbar }
        return try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: c.dropLast(16), tag: c.suffix(16))
    }

    static func lesen(_ text: String, ich: Int) throws -> Umschlag {
        guard let u = try? JSONDecoder().decode(Umschlag.self, from: Data(text.utf8)) else { throw Fehler.unlesbar }
        guard u.k[String(ich)] != nil else { throw Fehler.nichtFuerMich }
        return u
    }

    // MARK: Nachrichten

    /// ziele: zu zweit [Empfänger: Schlüssel], in Gruppen alle anderen Mitglieder; der Absender kommt immer dazu.
    /// rid: Empfänger-Nummer oder "g<Gruppe>".
    public static func verschluesseln(text: String, anhaenge: [Anhang] = [], zitat: Zitat? = nil, sid: Int, rid: String,
                                      privat: P256.KeyAgreement.PrivateKey, pub: String, ziele: [Int: String], schluessel: SymmetricKey? = nil) throws -> String {
        let t = saeubern(text)
        let a = anhaenge.compactMap { $0.geprueft() }
        guard a.count == anhaenge.count, a.count <= hoechstensBilder else { throw Fehler.unlesbar }
        guard !t.isEmpty || !a.isEmpty else { throw Fehler.leer }
        if !a.isEmpty && schluessel == nil { throw Fehler.schluessel }
        var alle = Dictionary(uniqueKeysWithValues: ziele.map { (String($0.key), $0.value) })
        alle[String(sid)] = pub
        let mitJson = !a.isEmpty || zitat != nil
        let klar: Data
        if mitJson {
            struct Teil: Encodable { let t: String; let a: [Anhang]?; let q: Zitat? }
            klar = try JSONEncoder().encode(Teil(t: t, a: a.isEmpty ? nil : a, q: zitat))
        } else { klar = Data(t.utf8) }
        return try versiegeln(basis: kontext(sid: String(sid), rid: rid, s: pub), klar: auffuellen(klar, hoechstens: mitJson ? maxV2 : maxV1), privat: privat, pub: pub, ziele: alle,
                              v: mitJson ? 2 : 1, b: mitJson ? a.map(\.id) : nil, schluessel: schluessel)
    }

    /// Länge verstecken wie im Browser (dmcrypto.js, auffuellen): mit Leerzeichen auf die nächste Stufe (64, 128, 256 … Bytes).
    /// Ältere Fassungen lesen das unverändert: v1 schneidet Leerzeichen am Ende ab, v2 ist JSON mit Leerraum am Ende.
    static let maxV1 = hoechstens * 4, maxV2 = hoechstens * 4 + hoechstensBilder * (500 * 4 + 200) + 64 + 700
    static func auffuellen(_ d: Data, hoechstens: Int) -> Data {
        var stufe = 64
        while stufe < d.count { stufe *= 2 }
        stufe = min(stufe, hoechstens)
        guard stufe > d.count else { return d }
        return d + Data(repeating: 0x20, count: stufe - d.count)
    }

    public static func entschluesseln(_ umschlag: String, ich: Int, sid: Int, rid: String, privat: P256.KeyAgreement.PrivateKey) throws -> Inhalt {
        let u = try lesen(umschlag, ich: ich)
        guard u.v == 1 || u.v == 2 else { throw Fehler.unbekannteFassung }
        let (klar, k) = try oeffnen(u, basis: kontext(sid: String(sid), rid: rid, s: u.s), ich: ich, privat: privat)
        guard var text = String(data: klar, encoding: .utf8) else { throw Fehler.unlesbar }
        var anhaenge: [Anhang] = [], zitat: Zitat?
        if u.v == 2 {
            struct Teil: Decodable { let t: String?; let a: [Anhang]?; let q: Zitat? }
            guard let j = try? JSONDecoder().decode(Teil.self, from: klar) else { throw Fehler.unlesbar }
            text = j.t ?? ""
            let sichtbar = Set(u.b ?? [])
            anhaenge = Array((j.a ?? []).compactMap { $0.geprueft() }.filter { sichtbar.contains($0.id) }.prefix(hoechstensBilder))
            zitat = j.q.flatMap { $0.id > 0 && $0.von > 0 ? Zitat(id: $0.id, von: $0.von, t: String(saeubern($0.t).prefix(140)), bild: $0.bild) : nil }
        }
        return Inhalt(text: saeubern(text), absenderSchluessel: u.s, anhaenge: anhaenge, zitat: zitat, schluessel: k)
    }

    // MARK: Gruppennamen

    public static let hoechstensGruppenname = 50
    static func gruppenNameKontext(von: Int, s: String) -> String { "cs-dm-gname-v1|\(von)|\(s)" }

    /// Verschlüsselter Gruppenname (dmcrypto.js, gruppenNameEntschluesseln): derselbe Umschlag wie eine v1-Nachricht, Kontext
    /// aus der Kontonummer dessen, der versiegelt hat (`von`, beim Server name_von / name_by), und seinem Schlüssel im Umschlag.
    /// `absenderSchluessel` muss der Aufrufer gegen den bekannten Schlüssel von `von` halten; ohne das könnte der Server
    /// einen Namen unter fremder Kontonummer unterschieben.
    public static func gruppenNameEntschluesseln(_ umschlag: String, ich: Int, von: Int, privat: P256.KeyAgreement.PrivateKey) throws -> (name: String, absenderSchluessel: String) {
        let u = try lesen(umschlag, ich: ich)
        guard u.v == 1 else { throw Fehler.unbekannteFassung }
        let (klar, _) = try oeffnen(u, basis: gruppenNameKontext(von: von, s: u.s), ich: ich, privat: privat)
        guard let roh = String(data: klar, encoding: .utf8) else { throw Fehler.unlesbar }
        let name = String(String.UnicodeScalarView(saeubern(roh).unicodeScalars.prefix(hoechstensGruppenname))).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { throw Fehler.leer }
        return (name, u.s)
    }

    /// Gruppenname für die Anzeige, mit Schlüsselprüfung: nil (dann gilt der Ersatzname), wenn der Umschlag nicht für mich ist,
    /// nicht aufgeht oder der Schlüssel darin nicht der von `von` ist. `bekannt` ist der Schlüssel von `von`, den man aus
    /// dem Gruppendetail oder dem eigenen Konto kennt (oder nil), `pins` die gemerkten Schlüssel (SchluesselMerken).
    public static func gruppenNameLesen(_ umschlag: String, von: Int, ich: Int, privat: P256.KeyAgreement.PrivateKey,
                                        bekannt: String?, pins: [String: String]) -> (name: String, schluessel: String)? {
        guard let erwartet = SchluesselMerken.erwartet(pins, von: von, bekannt: bekannt),
              let r = try? gruppenNameEntschluesseln(umschlag, ich: ich, von: von, privat: privat), r.absenderSchluessel == erwartet else { return nil }
        return (r.name, erwartet)
    }

    // MARK: Bilder und Sprachnachrichten

    /// Liefert IV (base64url) und Chiffrat zum Hochladen an /dm/blobs
    public static func anhangVerschluesseln(_ daten: Data, schluessel: SymmetricKey, sid: Int, rid: String) throws -> (n: String, daten: Data) {
        let k = try AES.GCM.seal(daten, using: schluessel, nonce: AES.GCM.Nonce(), authenticating: bildKontext(sid: String(sid), rid: rid))
        return (Data(k.nonce).b64u, k.ciphertext + k.tag)
    }

    public static func anhangEntschluesseln(_ chiffrat: Data, anhang: Anhang, schluessel: SymmetricKey, sid: Int, rid: String) throws -> Data {
        guard let iv = Data(b64u: anhang.n), chiffrat.count >= 16 else { throw Fehler.unlesbar }
        let k = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: chiffrat.dropLast(16), tag: chiffrat.suffix(16))
        return try AES.GCM.open(k, using: schluessel, authenticating: bildKontext(sid: String(sid), rid: rid))
    }

    // MARK: Reaktionen

    public static func reaktionVerschluesseln(_ emoji: String, mid: Int, sid: Int, konv: String, privat: P256.KeyAgreement.PrivateKey, pub: String, ziele: [Int: String]) throws -> String {
        guard let e = emojiPruefen(emoji) else { throw Fehler.unlesbar }
        var alle = Dictionary(uniqueKeysWithValues: ziele.map { (String($0.key), $0.value) })
        alle[String(sid)] = pub
        return try versiegeln(basis: reaktionsKontext(mid: mid, sid: sid, konv: konv, s: pub), klar: Data(e.utf8), privat: privat, pub: pub, ziele: alle, v: 1, b: nil)
    }

    public static func reaktionEntschluesseln(_ umschlag: String, ich: Int, mid: Int, sid: Int, konv: String, privat: P256.KeyAgreement.PrivateKey) throws -> String {
        let u = try lesen(umschlag, ich: ich)
        guard u.v == 1 else { throw Fehler.unbekannteFassung }
        let (klar, _) = try oeffnen(u, basis: reaktionsKontext(mid: mid, sid: sid, konv: konv, s: u.s), ich: ich, privat: privat)
        guard let e = emojiPruefen(String(decoding: klar, as: UTF8.self)) else { throw Fehler.unlesbar }
        return e
    }

    /// Genau ein Emoji (ein Graphem mit Bildzeichen, Flagge oder Tastenkappe)
    public static func emojiPruefen(_ roh: String) -> String? {
        let e = roh.precomposedStringWithCanonicalMapping.trimmingCharacters(in: .whitespaces)
        guard !e.isEmpty, e.utf16.count <= 32, e.count == 1, e.rangeOfCharacter(from: .whitespacesAndNewlines.union(.controlCharacters)) == nil else { return nil }
        // wie im Browser: /\p{Extended_Pictographic}|\p{Regional_Indicator}{2}|\u20E3/u (ICU kennt dieselben Klassen)
        let bild = e.range(of: #"\p{Extended_Pictographic}|\p{Regional_Indicator}{2}|\u20E3"#, options: .regularExpression) != nil
        return bild ? e : nil
    }

    // MARK: Vergleichen

    /// Gemeinsame Sicherheitsnummer zweier Konten (beide sehen dieselbe Zahl): 8 Gruppen zu je 5 Ziffern
    public static func sicherheitsnummer(_ a: String, _ b: String) -> String? {
        guard let ra = Data(b64u: a), let rb = Data(b64u: b) else { return nil }
        let (erst, dann) = ra.lexicographicallyPrecedes(rb) || ra == rb ? (ra, rb) : (rb, ra)
        let h = Array(SHA256.hash(data: Data("cs-sicherheitsnummer-v1".utf8) + erst + dann))
        return (0..<8).map { j in
            let z = (UInt32(h[j * 4]) << 24) | (UInt32(h[j * 4 + 1]) << 16) | (UInt32(h[j * 4 + 2]) << 8) | UInt32(h[j * 4 + 3])
            return String(format: "%05d", z % 100000)
        }.joined(separator: " ")
    }

    // MARK: Bereinigen wie lib/text.js (der Server sieht den Text nicht mehr und kann ihn nicht prüfen)

    public static func saeubern(_ roh: String) -> String {
        var s = roh.precomposedStringWithCanonicalMapping.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n").replacingOccurrences(of: "\t", with: " ")
        s = s.replacingOccurrences(of: "[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F-\\u009F]", with: "", options: .regularExpression)
        s = s.replacingOccurrences(of: "[\\u061C\\u200E\\u200F\\u202A-\\u202E\\u2066-\\u2069]", with: "", options: .regularExpression)
        s = s.replacingOccurrences(of: "[\\u00AD\\u180E\\u200B\\u2060-\\u2064\\uFEFF]", with: "", options: .regularExpression)
        s = s.replacingOccurrences(of: "^\\p{M}+", with: "", options: .regularExpression)
        s = s.replacingOccurrences(of: "(\\P{M})(\\p{M}{3})\\p{M}+", with: "$1$2", options: .regularExpression)
        s = s.replacingOccurrences(of: "\\n{3,}", with: "\n\n", options: .regularExpression)
        s = s.replacingOccurrences(of: "[\\u0020\\u00A0\\u3000]{3,}", with: "  ", options: .regularExpression)
        s = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return String(String.UnicodeScalarView(s.unicodeScalars.prefix(hoechstens))).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
