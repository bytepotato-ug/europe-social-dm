package com.bytepotato.europesocial.kern

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/** Gegen Vektoren aus dem Browser-Code (ios/Werkzeuge/dm-pruefvektoren.mjs, public/javascripts/dmcrypto.js), dieselben wie in DmKryptoTests.swift */
class DmKryptoTest {
    private val ada = TestDaten.person("ada")
    private val bob = TestDaten.person("bob")
    private val cleo = TestDaten.person("cleo")

    private fun art(block: () -> Unit): KryptoFehler.Art = assertFailsWith<KryptoFehler> { block() }.art

    @Test fun browserNachrichtOeffnen() {
        val umschlag = TestDaten.feld("v1", "umschlag")
        val r = DmKrypto.entschluesseln(umschlag, bob.id, ada.id, bob.id.toString(), bob.schluessel)
        assertEquals(TestDaten.feld("v1", "text"), r.text)
        assertEquals(ada.oeffentlich, r.absenderSchluessel)
        // Der Absender kann seine eigene Nachricht auch lesen
        assertEquals(TestDaten.feld("v1", "text"), DmKrypto.entschluesseln(umschlag, ada.id, ada.id, bob.id.toString(), ada.schluessel).text)
        // Falscher Kontext (andere Unterhaltung) fällt auf
        assertFailsWith<KryptoFehler> { DmKrypto.entschluesseln(umschlag, bob.id, ada.id, "4", bob.schluessel) }
        // Cleo war nicht dabei
        assertEquals(KryptoFehler.Art.NICHT_FUER_MICH, art { DmKrypto.entschluesseln(umschlag, cleo.id, ada.id, bob.id.toString(), cleo.schluessel) })
    }

    @Test fun browserBildUndZitat() {
        val r = DmKrypto.entschluesseln(TestDaten.feld("v2", "umschlag"), bob.id, ada.id, bob.id.toString(), bob.schluessel)
        assertEquals("Mit Bild", r.text)
        assertEquals(1, r.anhaenge.size)
        assertEquals("Ein Hafen", r.anhaenge[0].alt)
        assertEquals(800, r.anhaenge[0].b)
        assertEquals(DmKrypto.Zitat(7, bob.id, "Vorher", false), r.zitat)
        val klar = DmKrypto.anhangEntschluesseln(TestDaten.feld("v2", "bildChiffrat").ausB64u()!!, r.anhaenge[0], r.schluessel, ada.id, bob.id.toString())
        assertContentEquals(TestDaten.feld("v2", "bildKlar").ausB64u()!!, klar)
    }

    @Test fun browserGruppeUndReaktion() {
        for (p in listOf(bob, cleo)) {
            assertEquals("An alle", DmKrypto.entschluesseln(TestDaten.feld("gruppe", "umschlag"), p.id, ada.id, "g9", p.schluessel).text)
        }
        val rx = TestDaten.feld("reaktion", "umschlag")
        val mid = TestDaten.zahl("reaktion", "mid")
        val sid = TestDaten.zahl("reaktion", "sid")
        val konv = TestDaten.feld("reaktion", "konv")
        assertEquals("❤️", DmKrypto.reaktionEntschluesseln(rx, ada.id, mid, sid, konv, ada.schluessel))
        assertFailsWith<KryptoFehler> { DmKrypto.reaktionEntschluesseln(rx, ada.id, 43, sid, konv, ada.schluessel) }
    }

    @Test fun gruppennameWieImBrowser() {
        val u = TestDaten.feld("gruppenname", "umschlag")
        val von = TestDaten.zahl("gruppenname", "von")
        val name = TestDaten.feld("gruppenname", "name")
        for (p in listOf(bob, cleo, ada)) {
            val r = DmKrypto.gruppenNameEntschluesseln(u, p.id, von, p.schluessel)
            assertEquals(name, r.name)
            assertEquals(ada.oeffentlich, r.absenderSchluessel)
        }
        // Falscher Absender (Kontext) darf nicht aufgehen; eine Nachricht ist kein Gruppenname
        assertFailsWith<KryptoFehler> { DmKrypto.gruppenNameEntschluesseln(u, bob.id, cleo.id, bob.schluessel) }
        assertFailsWith<KryptoFehler> { DmKrypto.gruppenNameEntschluesseln(TestDaten.feld("gruppe", "umschlag"), bob.id, ada.id, bob.schluessel) }
        // Mit Schlüsselprüfung: bekannter, gemerkter, abweichender, keiner
        fun lesen(bekannt: String?, pins: Map<String, String>) = DmKrypto.gruppenNameLesen(u, von, bob.id, bob.schluessel, bekannt, pins)?.name
        assertEquals(name, lesen(ada.oeffentlich, emptyMap()))
        assertEquals(name, lesen(null, mapOf(von.toString() to ada.oeffentlich)))
        assertNull(lesen(cleo.oeffentlich, emptyMap()))
        assertNull(lesen(ada.oeffentlich, mapOf(von.toString() to cleo.oeffentlich)))
        assertNull(lesen(null, emptyMap()))
    }

    @Test fun einpackenWieImBrowser() {
        val prf = TestDaten.feld("einpacken", "prf").ausB64u()!!
        val uid = TestDaten.zahl("einpacken", "uid")
        val credId = TestDaten.feld("einpacken", "credId")
        val p = Krypto.auspacken(TestDaten.feld("einpacken", "gepackt"), prf, uid, credId)
        assertEquals(ada.oeffentlich, Krypto.oeffentlich(p))
        val neu = Krypto.einpacken(p, prf, uid, credId)
        assertEquals(ada.oeffentlich, Krypto.oeffentlich(Krypto.auspacken(neu, prf, uid, credId)))
        // falsche Passkey-Kennung oder Kontonummer packt nichts aus
        assertFailsWith<KryptoFehler> { Krypto.auspacken(neu, prf, uid, "andere") }
        assertFailsWith<KryptoFehler> { Krypto.auspacken(neu, prf, uid + 1, credId) }
    }

    @Test fun codeFormatierenSetztBindestriche() {
        assertEquals("", Krypto.codeFormatieren(""))
        assertEquals("ABCD", Krypto.codeFormatieren("abcd"))
        assertEquals("ABCD-E", Krypto.codeFormatieren("abcde"))
        assertEquals("VJKK-VGHT-T3NH-M3K2-F21G-1S63-85N0-STTH", Krypto.codeFormatieren("vjkk vght-t3nh–m3k2.f21g_1s6385n0STTH"))
        assertEquals("VJKK-VGHT-T3NH-M3K2-F21G-1S63-85N0-STTH", Krypto.codeFormatieren("VJKKVGHTT3NHM3K2F21G1S6385N0STTHXYZ"))  // höchstens 32
        // Das formatierte Ergebnis bleibt lesbar wie jede andere Schreibweise
        val roh = ByteArray(20) { it.toByte() }
        val code = Krypto.codeText(roh)
        assertContentEquals(roh, Krypto.codeLesen(Krypto.codeFormatieren(code.lowercase().replace("-", ""))))
    }

    @Test fun wiederherstellungscodeWieImBrowser() {
        val roh = TestDaten.feld("code", "roh").ausB64u()!!
        val code = TestDaten.feld("code", "code")
        val uid = TestDaten.zahl("code", "uid")
        val gepackt = TestDaten.feld("code", "gepackt")
        assertEquals(code, Krypto.codeText(roh))
        assertContentEquals(roh, Krypto.codeLesen(code))
        val schlampig = code.lowercase().replace("-", " ").replace("0", "o").replace("1", "l")
        assertContentEquals(roh, Krypto.codeLesen(schlampig))
        assertFailsWith<Krypto.CodeFehler> { Krypto.codeLesen("ABCD-EFGH") }
        assertFailsWith<Krypto.CodeFehler> { Krypto.codeLesen(code.dropLast(1) + "U") }
        val p = Krypto.codeAuspacken(gepackt, roh, uid)
        assertEquals(ada.oeffentlich, Krypto.oeffentlich(p))
        assertFailsWith<Krypto.CodeFehler> { Krypto.codeAuspacken(gepackt, Krypto.codeNeu().first, uid) }
        assertFailsWith<Krypto.CodeFehler> { Krypto.codeAuspacken(gepackt, roh, uid + 1) }
        val neu = Krypto.codeEinpacken(p, roh, uid)
        assertEquals(ada.oeffentlich, Krypto.oeffentlich(Krypto.codeAuspacken(neu, roh, uid)))
        val (nRoh, nCode) = Krypto.codeNeu()
        assertEquals(39, nCode.length); assertContentEquals(nRoh, Krypto.codeLesen(nCode))
    }

    @Test fun sicherheitsnummerWieImBrowser() {
        val soll = TestDaten.feld("sicherheitsnummer")
        assertEquals(soll, DmKrypto.sicherheitsnummer(ada.oeffentlich, bob.oeffentlich))
        assertEquals(soll, DmKrypto.sicherheitsnummer(bob.oeffentlich, ada.oeffentlich))
        assertNull(DmKrypto.sicherheitsnummer("***", bob.oeffentlich))
    }

    @Test fun fingerabdruckWieImBrowser() {
        assertEquals(TestDaten.feld("fingerabdruck"), Krypto.fingerabdruck(ada.oeffentlich))
    }

    @Test fun schluesselUmrechnen() {
        val p = ada.schluessel
        // öffentlicher Schlüssel aus dem privaten gerechnet = der, den der Browser gespeichert hat
        assertEquals(ada.oeffentlich, Krypto.oeffentlich(p))
        // roh und zurück
        assertEquals(ada.oeffentlich, Krypto.oeffentlich(Krypto.privatAusRoh(Krypto.roh(p))))
        // PKCS#8 wie WebCrypto es schreibt: byteweise gleich
        assertContentEquals(ada.privatPkcs8.ausB64u()!!, Krypto.pkcs8(p))
        // ECDH ist symmetrisch
        val z1 = Krypto.ecdh(ada.schluessel, Krypto.oeffentlichAusB64u(bob.oeffentlich))
        val z2 = Krypto.ecdh(bob.schluessel, Krypto.oeffentlichAusB64u(ada.oeffentlich))
        assertContentEquals(z1, z2)
        assertEquals(32, z1.size)
        // neue Paare: öffentlicher Teil stimmt mit der Rechnung aus dem privaten überein
        repeat(5) {
            val k = Krypto.neuesPaar()
            assertEquals(Krypto.oeffentlich(k.public), Krypto.oeffentlich(k.private))
        }
    }

    @Test fun ungueltigeSchluesselAbgelehnt() {
        assertEquals(KryptoFehler.Art.SCHLUESSEL, art { Krypto.oeffentlichAusB64u("AAAA") })
        // Punkt nicht auf der Kurve
        val roh = ada.oeffentlich.ausB64u()!!.also { it[64] = (it[64] + 1).toByte() }
        assertEquals(KryptoFehler.Art.SCHLUESSEL, art { Krypto.oeffentlichAusRoh(roh) })
        assertEquals(KryptoFehler.Art.SCHLUESSEL, art { Krypto.privatAusRoh(ByteArray(5)) })
    }

    @Test fun hkdfNachRfc5869() {
        fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        val okm1 = Krypto.hkdf(ByteArray(22) { 0x0b }, hex("000102030405060708090a0b0c"), hex("f0f1f2f3f4f5f6f7f8f9"), 42)
        assertContentEquals(hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), okm1)
        val okm3 = Krypto.hkdf(ByteArray(22) { 0x0b }, ByteArray(0), ByteArray(0), 42)
        assertContentEquals(hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"), okm3)
    }

    /** Gegenrichtung: schreibt, was Kotlin verschlüsselt hat; der Node-Teil öffnet es (dm-pruefvektoren.mjs --pruefen) */
    @Test fun kotlinVerschluesselt() {
        val k = DmKrypto.neuerSchluessel()
        val bild = "Bytes aus Kotlin".toByteArray()
        val (n, chiffrat) = DmKrypto.anhangVerschluesseln(bild, k, ada.id, bob.id.toString())
        val a = DmKrypto.Anhang("BBBBBBBBBBBBBBBBBBBBBB", n, "image/jpeg", 10, 10, "Test")
        val u = DmKrypto.verschluesseln("Grüße aus Kotlin ✨", listOf(a), null, ada.id, bob.id.toString(), ada.schluessel, ada.oeffentlich, mapOf(bob.id to bob.oeffentlich), k)
        val r = DmKrypto.entschluesseln(u, bob.id, ada.id, bob.id.toString(), bob.schluessel)
        assertEquals("Grüße aus Kotlin ✨", r.text)
        assertEquals(listOf(a), r.anhaenge)
        assertContentEquals(bild, DmKrypto.anhangEntschluesseln(chiffrat, r.anhaenge[0], r.schluessel, ada.id, bob.id.toString()))
        val rx = DmKrypto.reaktionVerschluesseln("👍🏽", 5, ada.id, "p2-3", ada.schluessel, ada.oeffentlich, mapOf(bob.id to bob.oeffentlich))
        assertEquals("👍🏽", DmKrypto.reaktionEntschluesseln(rx, bob.id, 5, ada.id, "p2-3", bob.schluessel))

        // Form des Umschlags, die der Server prüft: v2 hat sechs Felder, je Ziel genau drei, nur Empfänger und Absender
        val j = kernJson.parseToJsonElement(u) as kotlinx.serialization.json.JsonObject
        assertEquals(setOf("v", "s", "n", "c", "k", "b"), j.keys)
        assertEquals(setOf(ada.id.toString(), bob.id.toString()), (j["k"] as kotlinx.serialization.json.JsonObject).keys)
        val ziel = (j["k"] as kotlinx.serialization.json.JsonObject)[bob.id.toString()] as kotlinx.serialization.json.JsonObject
        assertEquals(setOf("e", "n", "w", "t"), ziel.keys)
        val v1 = kernJson.parseToJsonElement(DmKrypto.verschluesseln("nur Text", sid = ada.id, rid = bob.id.toString(), privat = ada.schluessel, pub = ada.oeffentlich, ziele = mapOf(bob.id to bob.oeffentlich))) as kotlinx.serialization.json.JsonObject
        assertEquals(setOf("v", "s", "n", "c", "k"), v1.keys)

        assumeTrue(TestDaten.node != null, "node fehlt")
        val datei = File.createTempFile("europe-dm-kotlin", ".json")
        try {
            fun s(x: String) = kernJson.encodeToString(kotlinx.serialization.serializer<String>(), x)
            datei.writeText(
                """{"umschlag":${s(u)},"text":${s("Grüße aus Kotlin ✨")},"bild":{"chiffrat":${s(chiffrat.b64u)},"klar":${s(bild.b64u)}},
                |"reaktion":{"umschlag":${s(rx)},"emoji":${s("👍🏽")},"mid":5,"konv":"p2-3"}}""".trimMargin(),
            )
            val (code, aus) = TestDaten.nodeLaufen("ios/Werkzeuge/dm-pruefvektoren.mjs", "--pruefen", datei.absolutePath)
            assertEquals(0, code, aus)
            assertTrue("alles lesbar" in aus, aus)
        } finally { datei.delete() }
    }

    /**
     * Bindung der Hülle an den Inhalt (seit 2026-11-19): Wer als Empfänger den Inhaltsschlüssel kennt, kann keinen anderen
     * Text unter die Hüllen des Absenders legen, und die sichtbaren Felder v und b sind mitgesichert.
     */
    @Test fun bindungAnDenInhalt() {
        fun lesen(u: String) = DmKrypto.entschluesseln(u, bob.id, ada.id, bob.id.toString(), bob.schluessel)
        assertTrue(lesen(TestDaten.feld("v1", "umschlag")).gebunden)
        // Ältere Fassungen schicken keine Bindung: geht auf, gilt aber als nicht gebunden
        val alt = lesen(TestDaten.feld("bindung", "ohne"))
        assertEquals(TestDaten.feld("v1", "text"), alt.text)
        assertTrue(!alt.gebunden)
        // Bob legt anderen Text unter Adas Hüllen: scheitert bei Cleo, auf Adas eigenem Gerät und bei ihm selbst
        val gefaelscht = TestDaten.feld("bindung", "gefaelscht")
        for (p in listOf(cleo, ada, bob)) assertEquals(KryptoFehler.Art.UNLESBAR, art { DmKrypto.entschluesseln(gefaelscht, p.id, ada.id, "g9", p.schluessel) })
        // Ohne Bindung (so sähe es aus, wenn jemand sie entfernt): lesbar, aber als nicht gebunden erkennbar
        val f = DmKrypto.entschluesseln(TestDaten.feld("bindung", "gefaelschtOhne"), cleo.id, ada.id, "g9", cleo.schluessel)
        assertEquals(TestDaten.feld("bindung", "gefaelschtText"), f.text)
        assertTrue(!f.gebunden)
        // Sichtbare Felder: Anhangliste geleert, Fassung von 2 auf 1 gestellt
        val u = kernJson.parseToJsonElement(TestDaten.feld("v2", "umschlag")) as kotlinx.serialization.json.JsonObject
        val ohneB = kotlinx.serialization.json.JsonObject(u + ("b" to kotlinx.serialization.json.JsonArray(emptyList())))
        assertEquals(KryptoFehler.Art.UNLESBAR, art { lesen(ohneB.toString()) })
        val alsV1 = kotlinx.serialization.json.JsonObject((u - "b") + ("v" to kotlinx.serialization.json.JsonPrimitive(1)))
        assertEquals(KryptoFehler.Art.UNLESBAR, art { lesen(alsV1.toString()) })
        // Was Kotlin selbst verschlüsselt, ist gebunden
        assertTrue(lesen(DmKrypto.verschluesseln("aus Kotlin", sid = ada.id, rid = bob.id.toString(), privat = ada.schluessel, pub = ada.oeffentlich, ziele = mapOf(bob.id to bob.oeffentlich))).gebunden)
    }

    /** Antworten: das Feld bild steht immer im Zitat (Swift verlangte es bis 2026-11-19 und hielt die Antwort sonst für unlesbar) */
    @Test fun zitatImmerMitBildFeld() {
        assertEquals("""{"id":7,"von":3,"t":"Vorher","bild":false}""", kernJson.encodeToString(DmKrypto.Zitat.serializer(), DmKrypto.Zitat(7, 3, "Vorher")))
        assertEquals(DmKrypto.Zitat(7, 3, "Vorher", false), kernJson.decodeFromString(DmKrypto.Zitat.serializer(), """{"id":7,"von":3,"t":"Vorher"}"""))
        // Beim Verschlüsseln geprüft wie im Browser: Auszug auf 140 Zeichen, ungültige Nummer abgelehnt
        val u = DmKrypto.verschluesseln("ja", zitat = DmKrypto.Zitat(7, bob.id, "ä".repeat(300)), sid = ada.id, rid = bob.id.toString(), privat = ada.schluessel, pub = ada.oeffentlich, ziele = mapOf(bob.id to bob.oeffentlich))
        assertEquals(140, DmKrypto.entschluesseln(u, bob.id, ada.id, bob.id.toString(), bob.schluessel).zitat!!.t.length)
        assertEquals(KryptoFehler.Art.UNLESBAR, art { DmKrypto.verschluesseln("ja", zitat = DmKrypto.Zitat(0, 3, "x"), sid = ada.id, rid = bob.id.toString(), privat = ada.schluessel, pub = ada.oeffentlich, ziele = mapOf(bob.id to bob.oeffentlich)) })
    }

    /** Reaktionen: jedes Emoji ergibt dasselbe Maß (48 Bytes und 16 für GCM), sonst verriete die Länge die Gruppe des Emojis */
    @Test fun reaktionLaengeVersteckt() {
        for (emoji in listOf("👍", "❤️", "✅", "👍🏽", "🇪🇺", "👨‍👩‍👧")) {
            val rx = DmKrypto.reaktionVerschluesseln(emoji, 5, ada.id, "p2-3", ada.schluessel, ada.oeffentlich, mapOf(bob.id to bob.oeffentlich))
            val c = (kernJson.parseToJsonElement(rx) as kotlinx.serialization.json.JsonObject)["c"]!!.let { (it as kotlinx.serialization.json.JsonPrimitive).content }
            assertEquals(64, c.ausB64u()!!.size)
            assertEquals(emoji, DmKrypto.reaktionEntschluesseln(rx, bob.id, 5, ada.id, "p2-3", bob.schluessel))
        }
    }

    /** Gegenrichtung für den eingepackten Schlüssel: der Browser-Code packt aus, was Kotlin eingepackt hat */
    @Test fun eingepackterSchluesselImBrowser() {
        assumeTrue(TestDaten.node != null, "node fehlt")
        val prf = ByteArray(32) { (it * 7).toByte() }
        val gepackt = Krypto.einpacken(ada.schluessel, prf, 2, "cred-kotlin")
        val skript = File.createTempFile("europe-einpacken", ".mjs")
        try {
            skript.writeText(
                """
                import { createRequire } from 'node:module';
                const require = createRequire(import.meta.url);
                const dm = require(process.argv[2] + '/public/javascripts/dmcrypto.js');
                const k = await dm.auspacken(process.argv[3], dm.unb64u(process.argv[4]), 2, 'cred-kotlin');
                const pub = await dm.oeffentlichVon(k);
                if (pub !== process.argv[5]) throw new Error('Schlüssel weicht ab: ' + pub);
                console.log('Kotlin eingepackt, Browser ausgepackt');
                """.trimIndent(),
            )
            val (code, aus) = TestDaten.nodeLaufen(skript.absolutePath, TestDaten.wurzel.absolutePath, gepackt, prf.b64u, ada.oeffentlich)
            assertEquals(0, code, aus)
        } finally { skript.delete() }
    }

    @Test fun emojiUndBereinigen() {
        assertEquals("❤️", DmKrypto.emojiPruefen("❤️"))
        assertEquals("🇪🇺", DmKrypto.emojiPruefen("🇪🇺"))
        assertEquals("👍🏽", DmKrypto.emojiPruefen("👍🏽"))
        assertEquals("1️⃣", DmKrypto.emojiPruefen("1️⃣"))
        assertEquals("👨‍👩‍👧", DmKrypto.emojiPruefen("👨‍👩‍👧"))
        assertNull(DmKrypto.emojiPruefen("a"))
        assertNull(DmKrypto.emojiPruefen("❤️❤️"))
        assertNull(DmKrypto.emojiPruefen(""))
        assertNull(DmKrypto.emojiPruefen("🇪"))
        assertEquals("abc\n\nd", DmKrypto.saeubern("  a\u202Eb\u200Bc\n\n\n\nd  "))
        assertEquals(1000, DmKrypto.saeubern("x".repeat(1200)).length)
        // zählt Codepunkte, nicht Zeichen des Strings
        assertEquals(1000, DmKrypto.saeubern("😀".repeat(1200)).codePointCount(0, DmKrypto.saeubern("😀".repeat(1200)).length))
        // Zalgo: höchstens drei kombinierende Zeichen je Grundzeichen, keine am Anfang
        assertEquals("x\u0301\u0302\u0303", DmKrypto.saeubern("x\u0301\u0302\u0303\u0304\u0305"))
        assertEquals("a", DmKrypto.saeubern("\u0301a"))
        // CR, Tab, viele Leerzeichen, einzelnes Ersatzzeichen
        assertEquals("a\nb c", DmKrypto.saeubern("a\r\nb\tc"))
        assertEquals("a  b", DmKrypto.saeubern("a      b"))
        assertEquals("a�b", DmKrypto.saeubern("a\uD800b"))
        // NFC
        assertEquals("\u00E9", DmKrypto.saeubern("e\u0301"))
    }

    @Test fun nachrichtenRegeln() {
        val ziele = mapOf(bob.id to bob.oeffentlich)
        fun senden(text: String, anhaenge: List<DmKrypto.Anhang> = emptyList(), k: ByteArray? = null) =
            DmKrypto.verschluesseln(text, anhaenge, null, ada.id, "3", ada.schluessel, ada.oeffentlich, ziele, k)
        assertEquals(KryptoFehler.Art.LEER, art { senden("  \u200B ") })
        val bild = DmKrypto.Anhang("A".repeat(22), "B".repeat(16), "image/jpeg", 10, 10, "")
        assertEquals(KryptoFehler.Art.SCHLUESSEL, art { senden("x", listOf(bild)) })
        assertEquals(KryptoFehler.Art.UNLESBAR, art { senden("x", listOf(bild.copy(b = 9000)), DmKrypto.neuerSchluessel()) })
        assertEquals(KryptoFehler.Art.UNLESBAR, art { senden("x", List(5) { bild }, DmKrypto.neuerSchluessel()) })
        // Sprachnachricht
        val ton = DmKrypto.Anhang("C".repeat(22), "D".repeat(16), "audio/mp4", d = 12)
        val k = DmKrypto.neuerSchluessel()
        val r = DmKrypto.entschluesseln(senden("", listOf(ton), k), bob.id, ada.id, "3", bob.schluessel)
        assertEquals(listOf(ton), r.anhaenge)
        assertTrue(r.anhaenge[0].istTon)
        assertContentEquals(k, r.schluessel)
        // unlesbar, fremde Fassung
        assertEquals(KryptoFehler.Art.UNLESBAR, art { DmKrypto.entschluesseln("kein json", bob.id, ada.id, "3", bob.schluessel) })
        assertEquals(KryptoFehler.Art.NICHT_FUER_MICH, art { DmKrypto.entschluesseln(senden("hi"), cleo.id, ada.id, "3", cleo.schluessel) })
        val v9 = senden("hi").replaceFirst("\"v\":1", "\"v\":9")
        assertEquals(KryptoFehler.Art.UNBEKANNTE_FASSUNG, art { DmKrypto.entschluesseln(v9, bob.id, ada.id, "3", bob.schluessel) })
        // verändertes Chiffrat fällt auf (GCM)
        val u = senden("hi")
        val c = Regex("\"c\":\"([^\"]+)\"").find(u)!!.groupValues[1]
        val kaputt = c.ausB64u()!!.also { it[0] = (it[0] + 1).toByte() }.b64u
        assertEquals(KryptoFehler.Art.UNLESBAR, art { DmKrypto.entschluesseln(u.replace(c, kaputt), bob.id, ada.id, "3", bob.schluessel) })
        assertNotNull(DmKrypto.konv(3, 2)); assertEquals("p2-3", DmKrypto.konv(3, 2))
    }

    @Test fun gruppeMitDreiMitgliedern() {
        val u = DmKrypto.verschluesseln("Hallo Gruppe", sid = bob.id, rid = "g9", privat = bob.schluessel, pub = bob.oeffentlich,
            ziele = mapOf(ada.id to ada.oeffentlich, cleo.id to cleo.oeffentlich))
        for (p in listOf(ada, bob, cleo)) assertEquals("Hallo Gruppe", DmKrypto.entschluesseln(u, p.id, bob.id, "g9", p.schluessel).text)
    }

    @Test fun laengeVersteckt() {
        fun groesse(text: String): Int {
            val u = DmKrypto.verschluesseln(text, sid = ada.id, rid = bob.id.toString(), privat = ada.schluessel, pub = ada.oeffentlich, ziele = mapOf(bob.id to bob.oeffentlich))
            assertEquals(text, DmKrypto.entschluesseln(u, bob.id, ada.id, bob.id.toString(), bob.schluessel).text)
            val c = (kernJson.parseToJsonElement(u) as kotlinx.serialization.json.JsonObject)["c"].toString().trim('"')
            return java.util.Base64.getUrlDecoder().decode(c).size
        }
        assertEquals(64 + 16, groesse("ok"))
        assertEquals(64 + 16, groesse("Treffen wir uns morgen um acht am Bahnhof?"))
        assertEquals(128 + 16, groesse("x".repeat(65)))
        kotlin.test.assertTrue(groesse("😀".repeat(DmKrypto.HOECHSTENS)) <= DmKrypto.HOECHSTENS * 4 + 16)
    }
}
