package com.bytepotato.europesocial.kern

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Gegen Vektoren aus dem Browser-Code (ios/Werkzeuge/koppel-pruefvektoren.mjs, public/javascripts/dmcrypto.js), dieselben wie auf iOS */
class KoppelnTest {
    private val v: JsonObject = Json.parseToJsonElement(TestDaten.text("koppeln.json")).jsonObject
    private fun feld(vararg pfad: String): String {
        var o = v
        for (p in pfad.dropLast(1)) o = o[p]!!.jsonObject
        return o[pfad.last()]!!.jsonPrimitive.content
    }

    private val uid = v["uid"]!!.jsonPrimitive.int
    private val id = feld("id")
    private val pubN = feld("neu", "oeffentlich")
    private val pubA = feld("alt", "oeffentlich")

    @Test fun fingerabdruckUndPruefzahl() {
        assertEquals(feld("fingerabdruck"), Krypto.kopplungFp(pubN))
        assertEquals(16, Krypto.kopplungFp(pubN).length)
        assertEquals(feld("pruefzahl"), Krypto.kopplungZahl(pubN, pubA))
        assertEquals("951 722", Krypto.kopplungZahlText(Krypto.kopplungZahl(pubN, pubA)))
    }

    @Test fun commitment() {
        assertEquals(feld("commit"), Krypto.kopplungCommit(pubN, feld("nonce")))
        // Anderer Schlüssel oder andere Nonce: anderes Commitment; kaputte Nonce: Fehler
        assertTrue(Krypto.kopplungCommit(pubA, feld("nonce")) != feld("commit"))
        assertTrue(Krypto.kopplungCommit(pubN, Krypto.kopplungNonce()) != feld("commit"))
        assertEquals(22, Krypto.kopplungNonce().length)
        assertFailsWith<KryptoFehler> { Krypto.kopplungCommit(pubN, "kurz") }
    }

    @Test fun browserFassungAuspacken() {
        val eN = Krypto.privatAusPkcs8(feld("neu", "privat").ausB64u()!!)
        val dm = Krypto.kopplungAuspacken(feld("wrapped"), eN, pubN, pubA, uid, id)
        assertEquals(feld("dm", "oeffentlich"), Krypto.oeffentlich(dm))
        // Falsche Anfrage oder falsches Konto: unlesbar
        assertFailsWith<KryptoFehler> { Krypto.kopplungAuspacken(feld("wrapped"), eN, pubN, pubA, uid, "AbCdEfGhIjKlMnOpQrStUw") }
        assertFailsWith<KryptoFehler> { Krypto.kopplungAuspacken(feld("wrapped"), eN, pubN, pubA, uid + 1, id) }
    }

    @Test fun eigenesEinpackenRund() {
        val dm = Krypto.privatAusPkcs8(feld("dm", "privat").ausB64u()!!)
        val eN = Krypto.neuesPaar()
        val eA = Krypto.neuesPaar()
        val n = Krypto.oeffentlich(eN.public)
        val a = Krypto.oeffentlich(eA.public)
        val gepackt = Krypto.kopplungEinpacken(dm, eA.private, n, a, uid, id)
        assertEquals(Krypto.oeffentlich(dm), Krypto.oeffentlich(Krypto.kopplungAuspacken(gepackt, eN.private, n, a, uid, id)))
        // Ein dritter Einmal-Schlüssel kann es nicht öffnen
        assertFailsWith<KryptoFehler> { Krypto.kopplungAuspacken(gepackt, Krypto.neuesPaar().private, n, a, uid, id) }
        // Das Format ist "iv.chiffrat" wie bei einpacken
        assertEquals(2, gepackt.split(".").size)
        assertEquals(16, gepackt.substringBefore(".").length)
    }
}
