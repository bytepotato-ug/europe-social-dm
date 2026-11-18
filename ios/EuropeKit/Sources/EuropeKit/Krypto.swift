import CryptoKit
import Foundation

/// Ende-zu-Ende-Verschlüsselung der Direktnachrichten, bitgenau wie public/javascripts/dmcrypto.js auf der Seite.
/// Bewiesen am 2026-11-10 (ios/PLAN.md, Abschnitt 0): ein im Browser eingepackter Schlüssel ließ sich hier auspacken.
public enum Krypto {
    /// Fester PRF-Eingabewert für alle Konten (dmcrypto.js, prfSalz). Das Geheimnis steckt im Passkey.
    public static let prfSalz = Data(SHA256.hash(data: Data("europe.social e2ee v1".utf8)))

    public enum Fehler: Error { case unlesbar, passtNicht }

    /// dmcrypto.js, hueller und auspacken: HKDF-SHA256 ohne Salz über die PRF-Ausgabe, AES-256-GCM, "iv.chiffrat"
    public static func auspacken(_ gepackt: String, prf: Data, uid: Int, credId: String) throws -> P256.KeyAgreement.PrivateKey {
        let teile = gepackt.split(separator: ".").map(String.init)
        guard teile.count == 2, let iv = Data(b64u: teile[0]), let ct = Data(b64u: teile[1]) else { throw Fehler.unlesbar }
        let schluessel = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: prf), salt: Data(),
                                                info: Data("cs-wrap-v1|\(uid)|\(credId)".utf8), outputByteCount: 32)
        let kiste = try AES.GCM.SealedBox(combined: iv + ct)
        let pkcs8 = try AES.GCM.open(kiste, using: schluessel, authenticating: Data("cs-wrap-v1|\(uid)".utf8))
        return try P256.KeyAgreement.PrivateKey(derRepresentation: pkcs8)
    }

    /// Gegenstück für neue Passkeys und neue Schlüssel (dmcrypto.js, einpacken)
    public static func einpacken(_ privat: P256.KeyAgreement.PrivateKey, prf: Data, uid: Int, credId: String) throws -> String {
        let schluessel = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: prf), salt: Data(),
                                                info: Data("cs-wrap-v1|\(uid)|\(credId)".utf8), outputByteCount: 32)
        let kiste = try AES.GCM.seal(privat.derRepresentation, using: schluessel, nonce: AES.GCM.Nonce(), authenticating: Data("cs-wrap-v1|\(uid)".utf8))
        return Data(kiste.nonce).b64u + "." + (kiste.ciphertext + kiste.tag).b64u
    }

    // MARK: Wiederherstellungscode (dmcrypto.js, codeNeu, codeLesen, codeEinpacken, codeAuspacken)

    /// Crockford-Base32 ohne I, L, O, U; 20 Byte (160 Bit) ergeben 32 Zeichen in acht Vierergruppen
    static let codeZeichen = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    public static let codeBytes = 20

    public static func codeText(_ roh: Data) -> String {
        var bits = 0, wert = 0, aus = ""
        for b in roh {
            wert = (wert << 8) | Int(b); bits += 8
            while bits >= 5 { aus.append(codeZeichen[(wert >> (bits - 5)) & 31]); bits -= 5 }
            wert &= (1 << bits) - 1
        }
        return stride(from: 0, to: aus.count, by: 4).map { i in
            String(aus[aus.index(aus.startIndex, offsetBy: i)..<aus.index(aus.startIndex, offsetBy: min(i + 4, aus.count))])
        }.joined(separator: "-")
    }

    public static func codeNeu() -> (roh: Data, code: String) {
        let roh = SymmetricKey(size: SymmetricKeySize(bitCount: codeBytes * 8)).withUnsafeBytes { Data($0) }
        return (roh, codeText(roh))
    }

    /// Anzeige beim Tippen und Einfügen: Großbuchstaben und Ziffern in Vierergruppen mit Bindestrich, höchstens 32 Zeichen
    /// (wie codeFormatieren in public/javascripts/app.js und Krypto.codeFormatieren in Android). Alles andere (Leerzeichen,
    /// alte Bindestriche, Sonderzeichen) fällt weg; codeLesen versteht das Ergebnis wie jede andere Schreibweise.
    public static func codeFormatieren(_ text: String) -> String {
        // Nur ASCII-Buchstaben und Ziffern: isLetter ließe auch ä oder ß durch, die JavaScript-Regex [^A-Z0-9] nicht
        let s = text.uppercased().unicodeScalars.filter { ("A"..."Z").contains($0) || ("0"..."9").contains($0) }.prefix(codeBytes * 8 / 5)
        let z = Array(s).map { Character($0) }
        return stride(from: 0, to: z.count, by: 4).map { String(z[$0..<min($0 + 4, z.count)]) }.joined(separator: "-")
    }

    public enum CodeFehler: Error { case unvollstaendig, zeichen, passtNicht }

    /// Groß- und Kleinschreibung, Leerzeichen und Striche egal; O als 0, I und L als 1
    public static func codeLesen(_ text: String) throws -> Data {
        var s = text.uppercased().filter { !" \t\n-–—_.".contains($0) }
        s = s.replacingOccurrences(of: "O", with: "0").replacingOccurrences(of: "I", with: "1").replacingOccurrences(of: "L", with: "1")
        guard s.count == codeBytes * 8 / 5 else { throw CodeFehler.unvollstaendig }
        var roh = Data(), bits = 0, wert = 0
        for c in s {
            guard let z = codeZeichen.firstIndex(of: c) else { throw CodeFehler.zeichen }
            wert = ((wert << 5) | z) & 0xffff; bits += 5
            if bits >= 8 { roh.append(UInt8((wert >> (bits - 8)) & 255)); bits -= 8 }
        }
        return roh
    }

    static func codeHuelle(_ roh: Data, uid: Int) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: roh), salt: Data(), info: Data("cs-code-v1|\(uid)".utf8), outputByteCount: 32)
    }

    public static func codeEinpacken(_ privat: P256.KeyAgreement.PrivateKey, roh: Data, uid: Int) throws -> String {
        let kiste = try AES.GCM.seal(privat.derRepresentation, using: codeHuelle(roh, uid: uid), nonce: AES.GCM.Nonce(), authenticating: Data("cs-code-v1|\(uid)".utf8))
        return Data(kiste.nonce).b64u + "." + (kiste.ciphertext + kiste.tag).b64u
    }

    public static func codeAuspacken(_ gepackt: String, roh: Data, uid: Int) throws -> P256.KeyAgreement.PrivateKey {
        let teile = gepackt.split(separator: ".").map(String.init)
        guard teile.count == 2, let iv = Data(b64u: teile[0]), let ct = Data(b64u: teile[1]) else { throw Fehler.unlesbar }
        guard roh.count == codeBytes else { throw CodeFehler.unvollstaendig }
        do {
            let pkcs8 = try AES.GCM.open(try AES.GCM.SealedBox(combined: iv + ct), using: codeHuelle(roh, uid: uid), authenticating: Data("cs-code-v1|\(uid)".utf8))
            return try P256.KeyAgreement.PrivateKey(derRepresentation: pkcs8)
        } catch { throw CodeFehler.passtNicht }
    }

    /// Öffentlicher Schlüssel wie auf dem Server gespeichert: roh unkomprimiert (65 Byte), base64url
    public static func oeffentlich(_ privat: P256.KeyAgreement.PrivateKey) -> String { privat.publicKey.x963Representation.b64u }
}

public extension Data {
    init?(b64u: String) {
        var s = b64u.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        s += String(repeating: "=", count: (4 - s.count % 4) % 4)
        self.init(base64Encoded: s)
    }
    var b64u: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

// MARK: Gerät koppeln (KOPPELN.md, dmcrypto.js: kopplungFp, kopplungNonce, kopplungCommit, kopplungZahl, kopplungEinpacken, kopplungAuspacken)

public extension Krypto {
    /// Fingerabdruck des Einmal-Schlüssels des neuen Geräts (steht im QR-Link): 16 Zeichen base64url
    static func kopplungFp(_ pubN: String) throws -> String {
        guard let roh = Data(b64u: pubN) else { throw Fehler.unlesbar }
        return Data(SHA256.hash(data: Data("cs-pair-v1|".utf8) + roh).prefix(12)).b64u
    }

    /// Zufällige Nonce für das Commitment, 16 Bytes, base64url (22 Zeichen)
    static func kopplungNonce() -> String {
        SymmetricKey(size: .bits128).withUnsafeBytes { Data($0) }.b64u
    }

    /// Commitment des neuen Geräts (seit 2026-11-16): SHA-256(„cs-pair-commit-v1|“ ‖ pubN ‖ nonce), base64url (43 Zeichen).
    /// Das neue Gerät schickt es vor seinem Einmal-Schlüssel; das andere Gerät prüft es nach dem Offenlegen selbst. So
    /// kann ein bösartiger Server die Prüfzahl nicht durch Probieren passend machen.
    static func kopplungCommit(_ pubN: String, _ nonce: String) throws -> String {
        guard let n = Data(b64u: pubN), let z = Data(b64u: nonce), z.count == 16 else { throw Fehler.unlesbar }
        return Data(SHA256.hash(data: Data("cs-pair-commit-v1|".utf8) + n + z)).b64u
    }

    /// Prüfzahl aus beiden Einmal-Schlüsseln (neues Gerät zuerst), sechs Ziffern mit führenden Nullen
    static func kopplungZahl(_ pubN: String, _ pubA: String) throws -> String {
        guard let n = Data(b64u: pubN), let a = Data(b64u: pubA) else { throw Fehler.unlesbar }
        let h = Array(SHA256.hash(data: Data("cs-pair-sas-v1|".utf8) + n + a).prefix(4))
        let zahl = h.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } % 1_000_000
        return String(format: "%06u", zahl)
    }

    private static func kopplungsSchluessel(_ eph: P256.KeyAgreement.PrivateKey, fremd: String, pubN: String, pubA: String, uid: Int, id: String) throws -> SymmetricKey {
        guard let n = Data(b64u: pubN), let a = Data(b64u: pubA), let f = Data(b64u: fremd), f.count == 65, f.first == 4 else { throw Fehler.unlesbar }
        let z = try eph.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: f))
        return z.hkdfDerivedSymmetricKey(using: SHA256.self, salt: n + a, sharedInfo: Data("cs-pair-v1|\(uid)|\(id)".utf8), outputByteCount: 32)
    }

    /// Entsperrtes Gerät (A): DM-Schlüssel für das neue Gerät verschlüsseln, "iv.chiffrat"
    static func kopplungEinpacken(_ dm: P256.KeyAgreement.PrivateKey, eigen eA: P256.KeyAgreement.PrivateKey, pubN: String, pubA: String, uid: Int, id: String) throws -> String {
        let k = try kopplungsSchluessel(eA, fremd: pubN, pubN: pubN, pubA: pubA, uid: uid, id: id)
        let kiste = try AES.GCM.seal(dm.derRepresentation, using: k, nonce: AES.GCM.Nonce(), authenticating: Data("cs-pair-v1|\(uid)|\(id)".utf8))
        return Data(kiste.nonce).b64u + "." + (kiste.ciphertext + kiste.tag).b64u
    }

    /// Neues Gerät (N): auspacken. Ob der Schlüssel zum Konto gehört, prüft der Aufrufer gegen /dm/keys/me.
    static func kopplungAuspacken(_ gepackt: String, eigen eN: P256.KeyAgreement.PrivateKey, pubN: String, pubA: String, uid: Int, id: String) throws -> P256.KeyAgreement.PrivateKey {
        let teile = gepackt.split(separator: ".").map(String.init)
        guard teile.count == 2, let iv = Data(b64u: teile[0]), let ct = Data(b64u: teile[1]) else { throw Fehler.unlesbar }
        let k = try kopplungsSchluessel(eN, fremd: pubA, pubN: pubN, pubA: pubA, uid: uid, id: id)
        do {
            let pkcs8 = try AES.GCM.open(try AES.GCM.SealedBox(combined: iv + ct), using: k, authenticating: Data("cs-pair-v1|\(uid)|\(id)".utf8))
            return try P256.KeyAgreement.PrivateKey(derRepresentation: pkcs8)
        } catch { throw Fehler.unlesbar }
    }
}
