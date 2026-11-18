import Foundation

/// Schlüssel der Gegenüber merken (Trust on first use), genau wie `pin()` in public/javascripts/app.js:
/// Beim ersten Kontakt wird der öffentliche DM-Schlüssel je (eigenes Konto, Partner) gemerkt, danach nur noch verglichen.
/// Die reine Logik liegt hier, damit sie ohne Schlüsselbund testbar ist; `Konten` hält den Speicher.
public enum SchluesselMerken {
    /// Prüft den Schlüssel eines Partners. Unbekannt: merken, gilt. Gleich: gilt. Anders: gilt nicht, nichts wird geändert.
    public static func pruefen(_ pins: inout [String: String], partner: Int, schluessel: String) -> Bool {
        let k = String(partner)
        guard let alt = pins[k] else { pins[k] = schluessel; return true }
        return alt == schluessel
    }

    /// Welche der Schlüssel weichen vom gemerkten ab? Unbekannte werden gemerkt (erster Kontakt). Rückgabe: Partner-Nummern.
    public static func geaenderte(_ pins: inout [String: String], _ schluessel: [Int: String]) -> [Int] {
        schluessel.keys.sorted().filter { !pruefen(&pins, partner: $0, schluessel: schluessel[$0]!) }
    }

    /// Nach der Bestätigung: den neuen Schlüssel merken
    public static func uebernehmen(_ pins: inout [String: String], _ schluessel: [Int: String], fuer partner: [Int]) {
        for p in partner { if let k = schluessel[p] { pins[String(p)] = k } }
    }

    /// Welcher Schlüssel gilt für `von`, wenn etwas gegen ihn geprüft wird (Gruppennamen)? `bekannt` ist ein Schlüssel aus
    /// sicherer Quelle (Mitgliederliste, eigener Schlüssel). Gibt es zusätzlich einen gemerkten, müssen beide übereinstimmen
    /// (sonst nil: der Schlüssel hat sich geändert); gibt es nur einen, gilt er; gibt es keinen, nil. Ändert nichts.
    public static func erwartet(_ pins: [String: String], von: Int, bekannt: String?) -> String? {
        let gemerkt = pins[String(von)]
        if let bekannt, let gemerkt { return bekannt == gemerkt ? bekannt : nil }
        return bekannt ?? gemerkt
    }
}
