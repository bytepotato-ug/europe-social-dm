import CryptoKit
import Foundation
import Testing
@testable import EuropeKit

/// Gegen Vektoren aus dem Browser-Code (ios/Werkzeuge/koppel-pruefvektoren.mjs, public/javascripts/dmcrypto.js)
@Suite struct KoppelnTests {
    struct Paar: Decodable { let privat: String; let oeffentlich: String
        var schluessel: P256.KeyAgreement.PrivateKey { try! P256.KeyAgreement.PrivateKey(derRepresentation: Data(b64u: privat)!) } }
    struct Vektoren: Decodable { let uid: Int; let id: String; let dm: Paar; let neu: Paar; let alt: Paar
        let fingerabdruck: String; let nonce: String; let commit: String; let pruefzahl: String; let wrapped: String }
    let v: Vektoren = try! JSONDecoder().decode(Vektoren.self, from: Data(contentsOf: Bundle.module.url(forResource: "koppeln", withExtension: "json", subdirectory: "Daten")!))

    @Test func fingerabdruckUndZahl() throws {
        #expect(try Krypto.kopplungFp(v.neu.oeffentlich) == v.fingerabdruck)
        #expect(try Krypto.kopplungZahl(v.neu.oeffentlich, v.alt.oeffentlich) == v.pruefzahl)
        // Reihenfolge zählt
        #expect(try Krypto.kopplungZahl(v.alt.oeffentlich, v.neu.oeffentlich) != v.pruefzahl)
    }

    @Test func commitment() throws {
        #expect(try Krypto.kopplungCommit(v.neu.oeffentlich, v.nonce) == v.commit)
        // Anderer Schlüssel oder andere Nonce: anderes Commitment
        #expect(try Krypto.kopplungCommit(v.alt.oeffentlich, v.nonce) != v.commit)
        #expect(try Krypto.kopplungCommit(v.neu.oeffentlich, Krypto.kopplungNonce()) != v.commit)
        #expect(Krypto.kopplungNonce().count == 22)
        #expect(throws: (any Error).self) { try Krypto.kopplungCommit(v.neu.oeffentlich, "kurz") }
    }

    @Test func browserChiffratAuspacken() throws {
        let k = try Krypto.kopplungAuspacken(v.wrapped, eigen: v.neu.schluessel, pubN: v.neu.oeffentlich, pubA: v.alt.oeffentlich, uid: v.uid, id: v.id)
        #expect(Krypto.oeffentlich(k) == v.dm.oeffentlich)
        // Falsche Anfrage-Nummer oder fremdes Konto fällt auf
        #expect(throws: (any Error).self) { try Krypto.kopplungAuspacken(v.wrapped, eigen: v.neu.schluessel, pubN: v.neu.oeffentlich, pubA: v.alt.oeffentlich, uid: v.uid + 1, id: v.id) }
        #expect(throws: (any Error).self) { try Krypto.kopplungAuspacken(v.wrapped, eigen: v.neu.schluessel, pubN: v.neu.oeffentlich, pubA: v.alt.oeffentlich, uid: v.uid, id: "x" + v.id) }
    }

    @Test func eigenesRund() throws {
        let gepackt = try Krypto.kopplungEinpacken(v.dm.schluessel, eigen: v.alt.schluessel, pubN: v.neu.oeffentlich, pubA: v.alt.oeffentlich, uid: v.uid, id: v.id)
        let k = try Krypto.kopplungAuspacken(gepackt, eigen: v.neu.schluessel, pubN: v.neu.oeffentlich, pubA: v.alt.oeffentlich, uid: v.uid, id: v.id)
        #expect(Krypto.oeffentlich(k) == v.dm.oeffentlich)
    }
}
