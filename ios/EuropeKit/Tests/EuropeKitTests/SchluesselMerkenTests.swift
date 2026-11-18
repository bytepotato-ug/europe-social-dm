import Testing
@testable import EuropeKit

@Suite struct SchluesselMerkenTests {
    @Test func ersterKontaktMerktUndGilt() {
        var pins: [String: String] = [:]
        #expect(SchluesselMerken.pruefen(&pins, partner: 7, schluessel: "A"))
        #expect(pins["7"] == "A")
    }
    @Test func gleicherSchluesselGilt() {
        var pins = ["7": "A"]
        #expect(SchluesselMerken.pruefen(&pins, partner: 7, schluessel: "A"))
    }
    @Test func geaenderterSchluesselGiltNichtUndBleibtUnveraendert() {
        var pins = ["7": "A"]
        #expect(!SchluesselMerken.pruefen(&pins, partner: 7, schluessel: "B"))
        #expect(pins["7"] == "A")
    }
    @Test func partnerSindGetrennt() {
        var pins = ["7": "A"]
        #expect(SchluesselMerken.pruefen(&pins, partner: 8, schluessel: "B"))
        #expect(pins == ["7": "A", "8": "B"])
    }
    @Test func gruppeMeldetNurAbweichende() {
        var pins = ["1": "A", "2": "B"]
        let g = SchluesselMerken.geaenderte(&pins, [1: "A", 2: "X", 3: "C"])
        #expect(g == [2])
        #expect(pins["3"] == "C") // neu gemerkt
        #expect(pins["2"] == "B") // bis zur Bestätigung unverändert
    }
    @Test func bestaetigungUebernimmtNeuenSchluessel() {
        var pins = ["2": "B"]
        SchluesselMerken.uebernehmen(&pins, [2: "X"], fuer: [2])
        #expect(pins["2"] == "X")
        #expect(SchluesselMerken.pruefen(&pins, partner: 2, schluessel: "X"))
    }
}
