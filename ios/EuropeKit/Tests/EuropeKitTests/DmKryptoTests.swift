import CryptoKit
import Foundation
import Testing
@testable import EuropeKit

/// Gegen Vektoren aus dem Browser-Code (ios/Werkzeuge/dm-pruefvektoren.mjs, public/javascripts/dmcrypto.js)
@Suite struct DmKryptoTests {
    struct Person: Decodable { let id: Int; let privat: String; let oeffentlich: String
        var schluessel: P256.KeyAgreement.PrivateKey { try! P256.KeyAgreement.PrivateKey(derRepresentation: Data(b64u: privat)!) } }
    struct Vektoren: Decodable {
        struct Nachricht: Decodable { let umschlag: String; let text: String; let bildChiffrat: String?; let bildKlar: String?; let rid: String? }
        struct Reaktion: Decodable { let umschlag: String; let mid: Int; let sid: Int; let konv: String; let emoji: String }
        struct Gruppenname: Decodable { let umschlag: String; let von: Int; let name: String }
        struct Einpacken: Decodable { let prf: String; let uid: Int; let credId: String; let gepackt: String }
        let ada: Person, bob: Person, cleo: Person
        let v1: Nachricht, v2: Nachricht, gruppe: Nachricht
        let reaktion: Reaktion
        let gruppenname: Gruppenname
        let einpacken: Einpacken
        struct Code: Decodable { let roh: String; let code: String; let uid: Int; let gepackt: String }
        let code: Code
        struct Bindung: Decodable { let ohne: String; let gefaelscht: String; let gefaelschtOhne: String; let gefaelschtText: String }
        let bindung: Bindung
        let sicherheitsnummer: String
    }
    let v: Vektoren = try! JSONDecoder().decode(Vektoren.self, from: Data(contentsOf: Bundle.module.url(forResource: "dm", withExtension: "json", subdirectory: "Daten")!))

    @Test func browserNachrichtOeffnen() throws {
        let r = try DmKrypto.entschluesseln(v.v1.umschlag, ich: v.bob.id, sid: v.ada.id, rid: String(v.bob.id), privat: v.bob.schluessel)
        #expect(r.text == v.v1.text)
        #expect(r.absenderSchluessel == v.ada.oeffentlich)
        // Der Absender kann seine eigene Nachricht auch lesen
        #expect(try DmKrypto.entschluesseln(v.v1.umschlag, ich: v.ada.id, sid: v.ada.id, rid: String(v.bob.id), privat: v.ada.schluessel).text == v.v1.text)
        // Falscher Kontext (andere Unterhaltung) fällt auf
        #expect(throws: (any Error).self) { try DmKrypto.entschluesseln(v.v1.umschlag, ich: v.bob.id, sid: v.ada.id, rid: "4", privat: v.bob.schluessel) }
        // Cleo war nicht dabei
        #expect(throws: DmKrypto.Fehler.nichtFuerMich) { try DmKrypto.entschluesseln(v.v1.umschlag, ich: v.cleo.id, sid: v.ada.id, rid: String(v.bob.id), privat: v.cleo.schluessel) }
    }

    @Test func browserBildUndZitat() throws {
        let r = try DmKrypto.entschluesseln(v.v2.umschlag, ich: v.bob.id, sid: v.ada.id, rid: String(v.bob.id), privat: v.bob.schluessel)
        #expect(r.text == "Mit Bild")
        #expect(r.anhaenge.count == 1 && r.anhaenge[0].alt == "Ein Hafen" && r.anhaenge[0].b == 800)
        #expect(r.zitat == DmKrypto.Zitat(id: 7, von: v.bob.id, t: "Vorher", bild: false))
        let klar = try DmKrypto.anhangEntschluesseln(Data(b64u: v.v2.bildChiffrat!)!, anhang: r.anhaenge[0], schluessel: r.schluessel, sid: v.ada.id, rid: String(v.bob.id))
        #expect(klar == Data(b64u: v.v2.bildKlar!)!)
    }

    @Test func browserGruppeUndReaktion() throws {
        for p in [v.bob, v.cleo] {
            #expect(try DmKrypto.entschluesseln(v.gruppe.umschlag, ich: p.id, sid: v.ada.id, rid: "g9", privat: p.schluessel).text == "An alle")
        }
        let e = try DmKrypto.reaktionEntschluesseln(v.reaktion.umschlag, ich: v.ada.id, mid: v.reaktion.mid, sid: v.reaktion.sid, konv: v.reaktion.konv, privat: v.ada.schluessel)
        #expect(e == "❤️")
        #expect(throws: (any Error).self) { try DmKrypto.reaktionEntschluesseln(v.reaktion.umschlag, ich: v.ada.id, mid: 43, sid: v.reaktion.sid, konv: v.reaktion.konv, privat: v.ada.schluessel) }
    }

    /// Bindung der Hülle an den Inhalt (seit 2026-11-19): Wer als Empfänger den Inhaltsschlüssel kennt, kann keinen
    /// anderen Text unter die Hüllen des Absenders legen, und die sichtbaren Felder v und b sind mitgesichert.
    @Test func bindungAnDenInhalt() throws {
        let lesen = { (u: String) in try DmKrypto.entschluesseln(u, ich: v.bob.id, sid: v.ada.id, rid: String(v.bob.id), privat: v.bob.schluessel) }
        #expect(try lesen(v.v1.umschlag).gebunden)
        // Ältere Fassungen schicken keine Bindung: geht auf, gilt aber als nicht gebunden
        let alt = try lesen(v.bindung.ohne)
        #expect(alt.text == v.v1.text && !alt.gebunden)
        // Bob legt anderen Text unter Adas Hüllen: scheitert bei Cleo, auf Adas eigenem Gerät und bei ihm selbst
        for p in [v.cleo, v.ada, v.bob] {
            #expect(throws: DmKrypto.Fehler.unlesbar) { try DmKrypto.entschluesseln(v.bindung.gefaelscht, ich: p.id, sid: v.ada.id, rid: "g9", privat: p.schluessel) }
        }
        // Ohne Bindung (so sähe es aus, wenn jemand sie entfernt): lesbar, aber als nicht gebunden erkennbar
        let f = try DmKrypto.entschluesseln(v.bindung.gefaelschtOhne, ich: v.cleo.id, sid: v.ada.id, rid: "g9", privat: v.cleo.schluessel)
        #expect(f.text == v.bindung.gefaelschtText && !f.gebunden)
        // Sichtbare Felder: Anhangliste geleert, Fassung von 2 auf 1 gestellt
        var u = try #require(JSONSerialization.jsonObject(with: Data(v.v2.umschlag.utf8)) as? [String: Any])
        u["b"] = [String]()
        let ohneB = String(decoding: try JSONSerialization.data(withJSONObject: u), as: UTF8.self)
        #expect(throws: DmKrypto.Fehler.unlesbar) { try lesen(ohneB) }
        u["v"] = 1; u["b"] = nil
        let alsV1 = String(decoding: try JSONSerialization.data(withJSONObject: u), as: UTF8.self)
        #expect(throws: DmKrypto.Fehler.unlesbar) { try lesen(alsV1) }
        // Was Swift selbst verschlüsselt, ist gebunden
        let eigen = try DmKrypto.verschluesseln(text: "aus Swift", sid: v.ada.id, rid: String(v.bob.id), privat: v.ada.schluessel, pub: v.ada.oeffentlich, ziele: [v.bob.id: v.bob.oeffentlich])
        #expect(try lesen(eigen).gebunden)
    }

    /// Antworten aus Android: bis 2026-11-19 fehlte dort das Feld bild, wenn es false war, und die Nachricht war hier unlesbar
    @Test func zitatOhneBildFeld() throws {
        let z = try JSONDecoder().decode(DmKrypto.Zitat.self, from: Data(#"{"id":7,"von":3,"t":"Vorher"}"#.utf8))
        #expect(z == DmKrypto.Zitat(id: 7, von: 3, t: "Vorher", bild: false))
        #expect(try JSONDecoder().decode(DmKrypto.Zitat.self, from: Data(#"{"id":7,"von":3,"t":"x","bild":true}"#.utf8)).bild)
        // Beim Verschlüsseln geprüft wie im Browser: Auszug auf 140 Zeichen, ungültige Nummer abgelehnt
        let lang = DmKrypto.Zitat(id: 7, von: v.bob.id, t: String(repeating: "ä", count: 300), bild: false)
        let u = try DmKrypto.verschluesseln(text: "ja", zitat: lang, sid: v.ada.id, rid: String(v.bob.id), privat: v.ada.schluessel, pub: v.ada.oeffentlich, ziele: [v.bob.id: v.bob.oeffentlich])
        #expect(try DmKrypto.entschluesseln(u, ich: v.bob.id, sid: v.ada.id, rid: String(v.bob.id), privat: v.bob.schluessel).zitat?.t.unicodeScalars.count == 140)
        #expect(throws: DmKrypto.Fehler.unlesbar) {
            try DmKrypto.verschluesseln(text: "ja", zitat: DmKrypto.Zitat(id: 0, von: 3, t: "x", bild: false), sid: v.ada.id, rid: String(v.bob.id), privat: v.ada.schluessel, pub: v.ada.oeffentlich, ziele: [v.bob.id: v.bob.oeffentlich])
        }
    }

    /// Reaktionen: jedes Emoji ergibt dasselbe Maß (48 Bytes und 16 für GCM), sonst verriete die Länge die Gruppe des Emojis
    @Test func reaktionLaengeVersteckt() throws {
        struct Kopf: Decodable { let c: String }
        for emoji in ["👍", "❤️", "✅", "👍🏽", "🇪🇺", "👨‍👩‍👧"] {
            let rx = try DmKrypto.reaktionVerschluesseln(emoji, mid: 5, sid: v.ada.id, konv: "p2-3", privat: v.ada.schluessel, pub: v.ada.oeffentlich, ziele: [v.bob.id: v.bob.oeffentlich])
            #expect(Data(b64u: try JSONDecoder().decode(Kopf.self, from: Data(rx.utf8)).c)?.count == 64)
            #expect(try DmKrypto.reaktionEntschluesseln(rx, ich: v.bob.id, mid: 5, sid: v.ada.id, konv: "p2-3", privat: v.bob.schluessel) == emoji)
        }
    }

    @Test func gruppennameWieImBrowser() throws {
        let g = v.gruppenname
        for p in [v.bob, v.cleo, v.ada] {
            let r = try DmKrypto.gruppenNameEntschluesseln(g.umschlag, ich: p.id, von: g.von, privat: p.schluessel)
            #expect(r.name == g.name)
            #expect(r.absenderSchluessel == v.ada.oeffentlich)
        }
        // Falscher Absender (Kontext) darf nicht aufgehen
        #expect(throws: (any Error).self) { try DmKrypto.gruppenNameEntschluesseln(g.umschlag, ich: v.bob.id, von: v.cleo.id, privat: v.bob.schluessel) }
        // Eine Nachricht ist kein Gruppenname (anderer Kontext)
        #expect(throws: (any Error).self) { try DmKrypto.gruppenNameEntschluesseln(v.gruppe.umschlag, ich: v.bob.id, von: v.ada.id, privat: v.bob.schluessel) }
        // Mit Schlüsselprüfung: bekannter Schlüssel, gemerkter Schlüssel, abweichender, keiner
        #expect(DmKrypto.gruppenNameLesen(g.umschlag, von: g.von, ich: v.bob.id, privat: v.bob.schluessel, bekannt: v.ada.oeffentlich, pins: [:])?.name == g.name)
        #expect(DmKrypto.gruppenNameLesen(g.umschlag, von: g.von, ich: v.bob.id, privat: v.bob.schluessel, bekannt: nil, pins: [String(g.von): v.ada.oeffentlich])?.name == g.name)
        #expect(DmKrypto.gruppenNameLesen(g.umschlag, von: g.von, ich: v.bob.id, privat: v.bob.schluessel, bekannt: v.cleo.oeffentlich, pins: [:]) == nil)
        #expect(DmKrypto.gruppenNameLesen(g.umschlag, von: g.von, ich: v.bob.id, privat: v.bob.schluessel, bekannt: v.ada.oeffentlich, pins: [String(g.von): v.cleo.oeffentlich]) == nil)
        #expect(DmKrypto.gruppenNameLesen(g.umschlag, von: g.von, ich: v.bob.id, privat: v.bob.schluessel, bekannt: nil, pins: [:]) == nil)
    }

    @Test func einpackenWieImBrowser() throws {
        let e = v.einpacken
        let p = try Krypto.auspacken(e.gepackt, prf: Data(b64u: e.prf)!, uid: e.uid, credId: e.credId)
        #expect(Krypto.oeffentlich(p) == v.ada.oeffentlich)
        let neu = try Krypto.einpacken(p, prf: Data(b64u: e.prf)!, uid: e.uid, credId: e.credId)
        #expect(Krypto.oeffentlich(try Krypto.auspacken(neu, prf: Data(b64u: e.prf)!, uid: e.uid, credId: e.credId)) == v.ada.oeffentlich)
    }

    @Test func wiederherstellungscodeWieImBrowser() throws {
        let c = v.code
        let roh = Data(b64u: c.roh)!
        #expect(Krypto.codeText(roh) == c.code)
        #expect(try Krypto.codeLesen(c.code) == roh)
        // Kleinschreibung, Leerzeichen statt Strichen, O statt 0, l statt 1
        let schlampig = c.code.lowercased().replacingOccurrences(of: "-", with: " ").replacingOccurrences(of: "0", with: "o").replacingOccurrences(of: "1", with: "l")
        #expect(try Krypto.codeLesen(schlampig) == roh)
        #expect(throws: Krypto.CodeFehler.self) { try Krypto.codeLesen("ABCD-EFGH") }
        #expect(throws: Krypto.CodeFehler.self) { try Krypto.codeLesen(String(c.code.dropLast()) + "U") }
        let p = try Krypto.codeAuspacken(c.gepackt, roh: roh, uid: c.uid)
        #expect(Krypto.oeffentlich(p) == v.ada.oeffentlich)
        #expect(throws: Krypto.CodeFehler.self) { try Krypto.codeAuspacken(c.gepackt, roh: Krypto.codeNeu().roh, uid: c.uid) }
        #expect(throws: Krypto.CodeFehler.self) { try Krypto.codeAuspacken(c.gepackt, roh: roh, uid: c.uid + 1) }
        let neu = try Krypto.codeEinpacken(p, roh: roh, uid: c.uid)
        #expect(Krypto.oeffentlich(try Krypto.codeAuspacken(neu, roh: roh, uid: c.uid)) == v.ada.oeffentlich)
        let n = Krypto.codeNeu()
        #expect(n.code.count == 39)
        #expect(try Krypto.codeLesen(n.code) == n.roh)
    }

    @Test func sicherheitsnummerWieImBrowser() {
        #expect(DmKrypto.sicherheitsnummer(v.ada.oeffentlich, v.bob.oeffentlich) == v.sicherheitsnummer)
        #expect(DmKrypto.sicherheitsnummer(v.bob.oeffentlich, v.ada.oeffentlich) == v.sicherheitsnummer)
    }

    /// Gegenrichtung: schreibt, was Swift verschlüsselt hat; der Node-Teil öffnet es (dm-pruefvektoren.mjs --pruefen)
    @Test func swiftVerschluesselt() throws {
        let k = SymmetricKey(size: .bits256)
        let bild = Data("Bytes aus Swift".utf8)
        let (n, chiffrat) = try DmKrypto.anhangVerschluesseln(bild, schluessel: k, sid: v.ada.id, rid: String(v.bob.id))
        let a = DmKrypto.Anhang(id: "BBBBBBBBBBBBBBBBBBBBBB", n: n, typ: "image/jpeg", b: 10, h: 10, alt: "Test")
        let u = try DmKrypto.verschluesseln(text: "Grüße aus Swift ✨", anhaenge: [a], sid: v.ada.id, rid: String(v.bob.id), privat: v.ada.schluessel, pub: v.ada.oeffentlich, ziele: [v.bob.id: v.bob.oeffentlich], schluessel: k)
        let r = try DmKrypto.entschluesseln(u, ich: v.bob.id, sid: v.ada.id, rid: String(v.bob.id), privat: v.bob.schluessel)
        #expect(r.text == "Grüße aus Swift ✨")
        let rx = try DmKrypto.reaktionVerschluesseln("👍🏽", mid: 5, sid: v.ada.id, konv: "p2-3", privat: v.ada.schluessel, pub: v.ada.oeffentlich, ziele: [v.bob.id: v.bob.oeffentlich])
        struct Aus: Encodable { let umschlag: String; let text: String; let bild: [String: String]; let reaktion: [String: String] }
        let ziel = FileManager.default.temporaryDirectory.appending(path: "europe-dm-swift.json")
        try JSONEncoder().encode(Aus(umschlag: u, text: "Grüße aus Swift ✨", bild: ["chiffrat": chiffrat.b64u, "klar": bild.b64u],
                                     reaktion: ["umschlag": rx, "emoji": "👍🏽", "mid": "5", "konv": "p2-3"])).write(to: ziel)
        // mid und konv der Reaktion stehen fest im Node-Teil nicht drin, deshalb nur hier geprüft
        #expect(try DmKrypto.reaktionEntschluesseln(rx, ich: v.bob.id, mid: 5, sid: v.ada.id, konv: "p2-3", privat: v.bob.schluessel) == "👍🏽")
    }

    @Test func emojiUndBereinigen() {
        #expect(DmKrypto.emojiPruefen("❤️") == "❤️")
        #expect(DmKrypto.emojiPruefen("🇪🇺") == "🇪🇺")
        #expect(DmKrypto.emojiPruefen("👍🏽") == "👍🏽")
        // Zusammengesetzte Emojis (mit dem Verbinder U+200D) und Tastenkappen, wie Web und Android sie annehmen
        #expect(DmKrypto.emojiPruefen("👨‍👩‍👧") == "👨‍👩‍👧")
        #expect(DmKrypto.emojiPruefen("🏳️‍🌈") == "🏳️‍🌈")
        #expect(DmKrypto.emojiPruefen("1️⃣") == "1️⃣")
        #expect(DmKrypto.emojiPruefen("👍 ") == "👍")
        #expect(DmKrypto.emojiPruefen("👍\n👍") == nil)
        #expect(DmKrypto.emojiPruefen("\u{0007}") == nil)
        #expect(DmKrypto.emojiPruefen("a") == nil)
        #expect(DmKrypto.emojiPruefen("❤️❤️") == nil)
        #expect(DmKrypto.saeubern("  a\u{202E}b\u{200B}c\n\n\n\nd  ") == "abc\n\nd")
        #expect(DmKrypto.saeubern(String(repeating: "x", count: 1200)).count == 1000)
    }
}

@Suite struct LaengeTests {
    @Test func laengeVersteckt() throws {
        let v = DmKryptoTests().v
        func groesse(_ text: String) throws -> Int {
            let u = try DmKrypto.verschluesseln(text: text, sid: v.ada.id, rid: String(v.bob.id), privat: v.ada.schluessel, pub: v.ada.oeffentlich, ziele: [v.bob.id: v.bob.oeffentlich])
            #expect(try DmKrypto.entschluesseln(u, ich: v.bob.id, sid: v.ada.id, rid: String(v.bob.id), privat: v.bob.schluessel).text == text)
            let j = try JSONSerialization.jsonObject(with: Data(u.utf8)) as! [String: Any]
            return Data(b64u: j["c"] as! String)!.count
        }
        #expect(try groesse("ok") == 64 + 16)
        #expect(try groesse("Treffen wir uns morgen um acht am Bahnhof?") == 64 + 16)
        #expect(try groesse(String(repeating: "x", count: 65)) == 128 + 16)
        #expect(try groesse(String(repeating: "😀", count: DmKrypto.hoechstens)) <= DmKrypto.hoechstens * 4 + 16)
    }
}
