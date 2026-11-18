package com.bytepotato.europesocial.kern

import java.security.PrivateKey
import java.text.BreakIterator
import java.text.Normalizer
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Direktnachrichten, bitgenau wie public/javascripts/dmcrypto.js und DmKrypto.swift (dort steht das Verfahren
 * ausführlich): Inhaltsschlüssel K (AES-256-GCM, Zusatzdaten = Kontext), K je Ziel eingepackt mit
 * KEK = HKDF-SHA256(ECDH(E, P) ‖ ECDH(S, P), Salz = E roh, Info = Kontext|Ziel). Ziele sind Empfänger und Absender,
 * in Gruppen alle Mitglieder. Bilder mit demselben K und eigenem IV. Geprüft gegen Vektoren aus dem Browser-Code.
 * Seit 2026-11-19 trägt jede Hülle eine Bindung an den Inhalt (Feld t, HMAC über v, n, c, b mit einem Schlüssel aus
 * ECDH(S, P)): Ohne sie könnte ein Empfänger, der K kennt, anderen Text unter die Hüllen des Absenders legen.
 */
object DmKrypto {
    const val HOECHSTENS = 1000
    const val HOECHSTENS_BILDER = 4
    private const val HOECHSTENS_ALT = 500
    private const val HOECHSTENS_ZITAT = 140
    internal val bildArten = listOf("image/webp", "image/jpeg", "image/gif")
    internal val tonArten = listOf("audio/webm", "audio/mp4", "audio/ogg")

    /** Sichtbarer Teil auf dem Server: v, s (Absender), n (IV), c (Chiffrat), k (je Ziel), b (Anhänge, nur v2) */
    @Serializable
    internal class Umschlag(val v: Int, val s: String, val n: String, val c: String, val k: Map<String, Eingepackt>, val b: List<String>? = null)

    @Serializable
    internal class Eingepackt(val e: String, val n: String, val w: String, val t: String? = null)

    /** Anhang im verschlüsselten Teil: Bild (typ, b, h, alt) oder Sprachnachricht (typ, d) */
    @Serializable
    data class Anhang(
        val id: String,
        val n: String,
        val typ: String,
        val b: Int? = null,
        val h: Int? = null,
        val alt: String? = null,
        val d: Int? = null,
    ) {
        val istTon: Boolean get() = typ in tonArten

        /** dmcrypto.js, anhangPruefen: alles Unbekannte fällt weg */
        internal fun geprueft(): Anhang? {
            if (!ID.matches(id) || !IV.matches(n)) return null
            if (typ in tonArten) {
                val dauer = d ?: return null
                return if (dauer in 1..300) Anhang(id, n, typ, d = dauer) else null
            }
            if (typ !in bildArten) return null
            val breite = b ?: return null
            val hoehe = h ?: return null
            if (breite !in 1..8192 || hoehe !in 1..8192) return null
            return Anhang(id, n, typ, breite, hoehe, vorne(saeubern(alt ?: ""), HOECHSTENS_ALT))
        }

        private companion object {
            val ID = Regex("[A-Za-z0-9_-]{22}")
            val IV = Regex("[A-Za-z0-9_-]{16}")
        }
    }

    /**
     * Antwort auf eine bestimmte Nachricht: Nummer, Absender, kurzer Auszug. [bild] wird immer mitgeschrieben, auch wenn
     * es false ist: Swift verlangte das Feld bis 2026-11-19 und hielt eine Antwort ohne es für unlesbar (kernJson lässt
     * Vorgabewerte sonst weg).
     */
    @OptIn(ExperimentalSerializationApi::class)
    @Serializable
    data class Zitat(val id: Int, val von: Int, val t: String, @EncodeDefault val bild: Boolean = false) {
        /** dmcrypto.js, zitatPruefen: gültige Nummern, Auszug bereinigt und auf 140 Zeichen (Codepunkte) gekürzt */
        internal fun geprueft(): Zitat? = if (id > 0 && von > 0) Zitat(id, von, vorne(saeubern(t), HOECHSTENS_ZITAT), bild) else null
    }

    @Serializable
    private class Teil(val t: String? = null, val a: List<Anhang>? = null, val q: Zitat? = null)

    /**
     * Entschlüsselter Inhalt einer Nachricht; [schluessel] (32 Byte) öffnet die Anhänge und dient dem Bearbeiten mit gleichen
     * Bildern. [gebunden]: die Hülle trug eine gültige Bindung an genau diesen Inhalt (false bei Nachrichten älterer Fassungen).
     */
    class Inhalt(val text: String, val absenderSchluessel: String, val anhaenge: List<Anhang>, val zitat: Zitat?, val schluessel: ByteArray, val gebunden: Boolean = false)

    // ---------- Kontexte (Zusatzdaten und HKDF-Info) ----------

    internal fun kontext(sid: String, rid: String, s: String) = "cs-dm-v1|$sid|$rid|$s"
    internal fun reaktionsKontext(mid: Int, sid: Int, konv: String, s: String) = "cs-dm-reaktion-v1|$mid|$sid|$konv|$s"
    internal fun bildKontext(sid: String, rid: String) = "cs-dm-bild-v1|$sid|$rid".toByteArray()

    /** Unterhaltung zu zweit, gleich aus beiden Blickwinkeln */
    fun konv(a: Int, b: Int): String = "p${minOf(a, b)}-${maxOf(a, b)}"

    /** Neuer Inhaltsschlüssel für eine Nachricht mit Anhängen (vor dem Hochladen erzeugen, beim Senden übergeben) */
    fun neuerSchluessel(): ByteArray = Krypto.zufallsBytes(32)

    // ---------- Kern ----------

    private fun kek(z1: ByteArray, z2: ByteArray, eph: ByteArray, basis: String, fuer: String): ByteArray =
        Krypto.hkdf(z1 + z2, eph, "$basis|$fuer".toByteArray(), 32)

    // ---------- Bindung der Hülle an den Inhalt (dmcrypto.js, bindeText und bindeSchluessel) ----------

    internal fun bindeText(v: Int, n: String, c: String, b: List<String>?): ByteArray {
        val liste = if (v == 2) b ?: emptyList() else emptyList()
        if (liste.any { '|' in it || ',' in it }) throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        return "cs-dm-bind-v1|$v|$n|$c|${liste.joinToString(",")}".toByteArray()
    }

    /** Schlüssel nur aus z2 = ECDH(S, P): Absender und genau dieser Empfänger können ihn rechnen, sonst niemand */
    internal fun bindeSchluessel(z2: ByteArray, eph: ByteArray, basis: String, fuer: String): ByteArray =
        Krypto.hkdf(z2, eph, "$basis|$fuer|bind-v1".toByteArray(), 32)

    /** klar mit K verschlüsseln und K für jedes Ziel ({ Kontonummer: öffentlicher Schlüssel }, Absender eingeschlossen) einpacken */
    private fun versiegeln(
        basis: String, klar: ByteArray, privat: PrivateKey, pub: String, ziele: Map<String, String>,
        v: Int, b: List<String>?, schluessel: ByteArray?,
    ): String {
        val k = schluessel ?: neuerSchluessel()
        val iv = Krypto.zufallsBytes(12)
        val chiffrat = Krypto.gcmSiegeln(k, iv, klar, basis.toByteArray())
        val gebunden = bindeText(v, iv.b64u, chiffrat.b64u, b)
        val eingepackt = LinkedHashMap<String, Eingepackt>()
        for ((fuer, zielPub) in ziele) {
            val p = Krypto.oeffentlichAusB64u(zielPub)
            val eph = Krypto.neuesPaar()
            val ephRoh = Krypto.oeffentlichRoh(eph.public)
            val z2 = Krypto.ecdh(privat, p)
            val kk = kek(Krypto.ecdh(eph.private, p), z2, ephRoh, basis, fuer)
            val iv2 = Krypto.zufallsBytes(12)
            val w = Krypto.gcmSiegeln(kk, iv2, k)
            val t = Krypto.hmacSha256(bindeSchluessel(z2, ephRoh, basis, fuer), gebunden)
            eingepackt[fuer] = Eingepackt(ephRoh.b64u, iv2.b64u, w.b64u, t.b64u)
        }
        return kernJson.encodeToString(Umschlag(v, pub, iv.b64u, chiffrat.b64u, eingepackt, b))
    }

    private class Geoeffnet(val klar: ByteArray, val k: ByteArray, val gebunden: Boolean)

    /**
     * Liefert Klartext, Inhaltsschlüssel und ob die Hülle an genau diesen Inhalt gebunden war. Trägt die Hülle eine Bindung,
     * die nicht passt, wurde der Umschlag verändert: UNLESBAR.
     */
    private fun oeffnen(u: Umschlag, basis: String, ich: Int, privat: PrivateKey): Geoeffnet {
        val mein = u.k[ich.toString()] ?: throw KryptoFehler(KryptoFehler.Art.NICHT_FUER_MICH)
        val ephRoh = mein.e.ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.NICHT_FUER_MICH)
        val z2 = Krypto.ecdh(privat, Krypto.oeffentlichAusB64u(u.s))
        var gebunden = false
        if (mein.t != null) {
            val soll = Krypto.hmacSha256(bindeSchluessel(z2, ephRoh, basis, ich.toString()), bindeText(u.v, u.n, u.c, u.b))
            if (!java.security.MessageDigest.isEqual(soll, b64(mein.t))) throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
            gebunden = true
        }
        val kk = kek(Krypto.ecdh(privat, Krypto.oeffentlichAusB64u(mein.e)), z2, ephRoh, basis, ich.toString())
        val k = Krypto.gcmOeffnen(kk, b64(mein.n), b64(mein.w))
        val klar = Krypto.gcmOeffnen(k, b64(u.n), b64(u.c), basis.toByteArray())
        return Geoeffnet(klar, k, gebunden)
    }

    private fun b64(s: String): ByteArray = s.ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.UNLESBAR)

    private fun lesen(text: String, ich: Int): Umschlag {
        val u = try { kernJson.decodeFromString<Umschlag>(text) } catch (e: Exception) { throw KryptoFehler(KryptoFehler.Art.UNLESBAR, e) }
        if (u.k[ich.toString()] == null) throw KryptoFehler(KryptoFehler.Art.NICHT_FUER_MICH)
        return u
    }

    // ---------- Nachrichten ----------

    /**
     * ziele: zu zweit { Empfänger: Schlüssel }, in Gruppen alle anderen Mitglieder; der Absender kommt immer dazu.
     * rid: Empfänger-Nummer oder "g<Gruppe>". schluessel: Inhaltsschlüssel, Pflicht bei Anhängen (gleicher wie beim Verschlüsseln der Anhänge).
     */
    fun verschluesseln(
        text: String, anhaenge: List<Anhang> = emptyList(), zitat: Zitat? = null, sid: Int, rid: String,
        privat: PrivateKey, pub: String, ziele: Map<Int, String>, schluessel: ByteArray? = null,
    ): String {
        val t = saeubern(text)
        val a = anhaenge.mapNotNull { it.geprueft() }
        if (a.size != anhaenge.size || a.size > HOECHSTENS_BILDER) throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        if (t.isEmpty() && a.isEmpty()) throw KryptoFehler(KryptoFehler.Art.LEER)
        if (a.isNotEmpty() && schluessel == null) throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL)
        val q = zitat?.let { it.geprueft() ?: throw KryptoFehler(KryptoFehler.Art.UNLESBAR) }
        val alle = ziele.entries.associate { it.key.toString() to it.value }.toMutableMap()
        alle[sid.toString()] = pub
        val mitJson = a.isNotEmpty() || q != null
        val klar = if (mitJson) kernJson.encodeToString(Teil(t, a.ifEmpty { null }, q)).toByteArray() else t.toByteArray()
        return versiegeln(kontext(sid.toString(), rid, pub), auffuellen(klar, if (mitJson) MAX_V2 else MAX_V1), privat, pub, alle, if (mitJson) 2 else 1, if (mitJson) a.map { it.id } else null, schluessel)
    }

    // Länge verstecken wie im Browser (dmcrypto.js, auffuellen): mit Leerzeichen auf die nächste Stufe (64, 128, 256 … Bytes).
    // Ältere Fassungen lesen das unverändert: v1 schneidet Leerzeichen am Ende ab, v2 ist JSON mit Leerraum am Ende.
    private const val MAX_V1 = HOECHSTENS * 4
    private const val MAX_V2 = HOECHSTENS * 4 + HOECHSTENS_BILDER * (HOECHSTENS_ALT * 4 + 200) + 64 + 700
    internal fun auffuellen(d: ByteArray, hoechstens: Int): ByteArray {
        var stufe = 64
        while (stufe < d.size) stufe *= 2
        stufe = minOf(stufe, hoechstens)
        if (stufe <= d.size) return d
        return d + ByteArray(stufe - d.size) { 0x20 }
    }

    fun entschluesseln(umschlag: String, ich: Int, sid: Int, rid: String, privat: PrivateKey): Inhalt {
        val u = lesen(umschlag, ich)
        if (u.v != 1 && u.v != 2) throw KryptoFehler(KryptoFehler.Art.UNBEKANNTE_FASSUNG)
        val g = oeffnen(u, kontext(sid.toString(), rid, u.s), ich, privat)
        val klar = g.klar
        var text = try { klar.decodeToString(throwOnInvalidSequence = true) } catch (e: Exception) { throw KryptoFehler(KryptoFehler.Art.UNLESBAR, e) }
        var anhaenge = emptyList<Anhang>()
        var zitat: Zitat? = null
        if (u.v == 2) {
            val j = try { kernJson.decodeFromString<Teil>(text) } catch (e: Exception) { throw KryptoFehler(KryptoFehler.Art.UNLESBAR, e) }
            text = j.t ?: ""
            val sichtbar = (u.b ?: emptyList()).toSet()
            anhaenge = (j.a ?: emptyList()).mapNotNull { it.geprueft() }.filter { it.id in sichtbar }.take(HOECHSTENS_BILDER)
            zitat = j.q?.geprueft()
        }
        return Inhalt(saeubern(text), u.s, anhaenge, zitat, g.k, g.gebunden)
    }

    // ---------- Gruppennamen ----------

    const val HOECHSTENS_GRUPPENNAME = 50
    internal fun gruppenNameKontext(von: Int, s: String) = "cs-dm-gname-v1|$von|$s"

    class GruppenName(val name: String, val absenderSchluessel: String)

    /**
     * Verschlüsselter Gruppenname (dmcrypto.js, gruppenNameEntschluesseln): derselbe Umschlag wie eine v1-Nachricht, Kontext aus
     * der Kontonummer dessen, der versiegelt hat ([von], beim Server name_by), und seinem Schlüssel im Umschlag.
     * [GruppenName.absenderSchluessel] muss der Aufrufer gegen den bekannten Schlüssel von [von] halten, siehe [gruppenNameLesen].
     */
    fun gruppenNameEntschluesseln(umschlag: String, ich: Int, von: Int, privat: PrivateKey): GruppenName {
        val u = lesen(umschlag, ich)
        if (u.v != 1) throw KryptoFehler(KryptoFehler.Art.UNBEKANNTE_FASSUNG)
        val klar = oeffnen(u, gruppenNameKontext(von, u.s), ich, privat).klar
        val roh = try { klar.decodeToString(throwOnInvalidSequence = true) } catch (e: Exception) { throw KryptoFehler(KryptoFehler.Art.UNLESBAR, e) }
        val name = kappen(vorne(saeubern(roh), HOECHSTENS_GRUPPENNAME))
        if (name.isEmpty()) throw KryptoFehler(KryptoFehler.Art.LEER)
        return GruppenName(name, u.s)
    }

    /**
     * Gruppenname für die Anzeige, mit Schlüsselprüfung: null (dann gilt der Ersatzname), wenn der Umschlag nicht für mich ist,
     * nicht aufgeht oder der Schlüssel darin nicht der von [von] ist. [bekannt]: Schlüssel von [von] aus der Mitgliederliste
     * oder der eigene (oder null), [pins]: die gemerkten Schlüssel ([SchluesselMerken]).
     */
    fun gruppenNameLesen(umschlag: String, von: Int, ich: Int, privat: PrivateKey, bekannt: String?, pins: Map<String, String>): GruppenName? {
        val erwartet = SchluesselMerken.erwartet(pins, von, bekannt) ?: return null
        val r = try { gruppenNameEntschluesseln(umschlag, ich, von, privat) } catch (_: KryptoFehler) { return null }
        return if (r.absenderSchluessel == erwartet) r else null
    }

    // ---------- Bilder und Sprachnachrichten ----------

    /** Liefert IV (base64url) und Chiffrat zum Hochladen an /dm/blobs */
    fun anhangVerschluesseln(daten: ByteArray, schluessel: ByteArray, sid: Int, rid: String): Pair<String, ByteArray> {
        val iv = Krypto.zufallsBytes(12)
        return iv.b64u to Krypto.gcmSiegeln(schluessel, iv, daten, bildKontext(sid.toString(), rid))
    }

    fun anhangEntschluesseln(chiffrat: ByteArray, anhang: Anhang, schluessel: ByteArray, sid: Int, rid: String): ByteArray {
        val iv = anhang.n.ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        return Krypto.gcmOeffnen(schluessel, iv, chiffrat, bildKontext(sid.toString(), rid))
    }

    // ---------- Reaktionen ----------

    fun reaktionVerschluesseln(emoji: String, mid: Int, sid: Int, konv: String, privat: PrivateKey, pub: String, ziele: Map<Int, String>): String {
        val e = emojiPruefen(emoji) ?: throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        val alle = ziele.entries.associate { it.key.toString() to it.value }.toMutableMap()
        alle[sid.toString()] = pub
        return versiegeln(reaktionsKontext(mid, sid, konv, pub), reaktionAuffuellen(e.toByteArray()), privat, pub, alle, 1, null, null)
    }

    // Länge verstecken wie im Browser (dmcrypto.js, reaktionAuffuellen): mit Leerzeichen auf feste 48 Bytes, sonst verriete
    // die Größe des Chiffrats, aus welcher Gruppe das Emoji stammt. Alle Fassungen schneiden beim Lesen ab.
    private const val REAKTION_BYTES = 48
    internal fun reaktionAuffuellen(d: ByteArray): ByteArray = if (d.size >= REAKTION_BYTES) d else d + ByteArray(REAKTION_BYTES - d.size) { 0x20 }

    fun reaktionEntschluesseln(umschlag: String, ich: Int, mid: Int, sid: Int, konv: String, privat: PrivateKey): String {
        val u = lesen(umschlag, ich)
        if (u.v != 1) throw KryptoFehler(KryptoFehler.Art.UNBEKANNTE_FASSUNG)
        val klar = oeffnen(u, reaktionsKontext(mid, sid, konv, u.s), ich, privat).klar
        return emojiPruefen(klar.decodeToString()) ?: throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
    }

    /** Genau ein Emoji (ein Graphem mit Bildzeichen, Flagge oder Tastenkappe) */
    fun emojiPruefen(roh: String): String? {
        val e = Normalizer.normalize(roh, Normalizer.Form.NFC).trim { it == ' ' || it == '\t' }
        if (e.isEmpty() || e.length > 32 || e.any { it.isWhitespace() || it.isISOControl() || it == '\u0085' }) return null
        if (graphemAnzahl(e) != 1) return null
        // wie im Browser: Extended_Pictographic, zwei Regionalzeichen (Flagge) oder U+20E3 (Tastenkappe)
        return if (hatBildzeichen(e)) e else null
    }

    private fun graphemAnzahl(s: String): Int {
        val bi = BreakIterator.getCharacterInstance()
        bi.setText(s)
        var n = 0
        while (bi.next() != BreakIterator.DONE) n++
        return n
    }

    private fun hatBildzeichen(s: String): Boolean {
        var regional = 0
        var i = 0
        while (i < s.length) {
            val c = s.codePointAt(i)
            i += Character.charCount(c)
            if (c == 0x20E3 || istBildzeichen(c)) return true
            if (c in 0x1F1E6..0x1F1FF) { regional++; if (regional >= 2) return true } else regional = 0
        }
        return false
    }

    // Unicode Extended_Pictographic (emoji-data.txt), als Bereiche: java.util.regex und Androids ICU nennen die Eigenschaft verschieden
    private val bildBereiche = intArrayOf(
        0xA9, 0xA9, 0xAE, 0xAE, 0x203C, 0x203C, 0x2049, 0x2049, 0x2122, 0x2122, 0x2139, 0x2139, 0x2194, 0x2199, 0x21A9, 0x21AA,
        0x231A, 0x231B, 0x2328, 0x2328, 0x2388, 0x2388, 0x23CF, 0x23CF, 0x23E9, 0x23F3, 0x23F8, 0x23FA, 0x24C2, 0x24C2,
        0x25AA, 0x25AB, 0x25B6, 0x25B6, 0x25C0, 0x25C0, 0x25FB, 0x25FE, 0x2600, 0x2605, 0x2607, 0x2612, 0x2614, 0x2685,
        0x2690, 0x2705, 0x2708, 0x2712, 0x2714, 0x2714, 0x2716, 0x2716, 0x271D, 0x271D, 0x2721, 0x2721, 0x2728, 0x2728,
        0x2733, 0x2734, 0x2744, 0x2744, 0x2747, 0x2747, 0x274C, 0x274C, 0x274E, 0x274E, 0x2753, 0x2755, 0x2757, 0x2757,
        0x2763, 0x2767, 0x2795, 0x2797, 0x27A1, 0x27A1, 0x27B0, 0x27B0, 0x27BF, 0x27BF, 0x2934, 0x2935, 0x2B05, 0x2B07,
        0x2B1B, 0x2B1C, 0x2B50, 0x2B50, 0x2B55, 0x2B55, 0x3030, 0x3030, 0x303D, 0x303D, 0x3297, 0x3297, 0x3299, 0x3299,
        0x1F000, 0x1F0FF, 0x1F10D, 0x1F10F, 0x1F12F, 0x1F12F, 0x1F16C, 0x1F171, 0x1F17E, 0x1F17F, 0x1F18E, 0x1F18E,
        0x1F191, 0x1F19A, 0x1F1AD, 0x1F1E5, 0x1F201, 0x1F20F, 0x1F21A, 0x1F21A, 0x1F22F, 0x1F22F, 0x1F232, 0x1F23A,
        0x1F23C, 0x1F23F, 0x1F249, 0x1F3FA, 0x1F400, 0x1F53D, 0x1F546, 0x1F64F, 0x1F680, 0x1F6FF, 0x1F774, 0x1F77F,
        0x1F7D5, 0x1F7FF, 0x1F80C, 0x1F80F, 0x1F848, 0x1F84F, 0x1F85A, 0x1F85F, 0x1F888, 0x1F88F, 0x1F8AE, 0x1F8FF,
        0x1F90C, 0x1F93A, 0x1F93C, 0x1F945, 0x1F947, 0x1FAFF, 0x1FC00, 0x1FFFD,
    )

    private fun istBildzeichen(c: Int): Boolean {
        var i = 0
        while (i < bildBereiche.size) {
            if (c in bildBereiche[i]..bildBereiche[i + 1]) return true
            i += 2
        }
        return false
    }

    // ---------- Vergleichen ----------

    /** Gemeinsame Sicherheitsnummer zweier Konten (beide sehen dieselbe Zahl): 8 Gruppen zu je 5 Ziffern */
    fun sicherheitsnummer(a: String, b: String): String? {
        val ra = a.ausB64u() ?: return null
        val rb = b.ausB64u() ?: return null
        val aErst = vergleichen(ra, rb) <= 0
        val (erst, dann) = if (aErst) ra to rb else rb to ra
        val h = Krypto.sha256("cs-sicherheitsnummer-v1".toByteArray() + erst + dann)
        return (0 until 8).joinToString(" ") { j ->
            val z = ((h[j * 4].toLong() and 0xFF) shl 24) or ((h[j * 4 + 1].toLong() and 0xFF) shl 16) or
                ((h[j * 4 + 2].toLong() and 0xFF) shl 8) or (h[j * 4 + 3].toLong() and 0xFF)
            "%05d".format(z % 100000)
        }
    }

    /** Bytes als Zahlen ohne Vorzeichen vergleichen (lexikografisch, wie `lexicographicallyPrecedes` in Swift und der Vergleich im Browser) */
    private fun vergleichen(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    // ---------- Bereinigen wie lib/text.js (der Server sieht den Text nicht mehr und kann ihn nicht prüfen) ----------

    private val steuerzeichen = Regex("[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F-\\u009F]")
    private val richtung = Regex("[\\u061C\\u200E\\u200F\\u202A-\\u202E\\u2066-\\u2069]")
    private val unsichtbar = Regex("[\\u00AD\\u180E\\u200B\\u2060-\\u2064\\uFEFF]")
    private val zeichenAmAnfang = Regex("^\\p{M}+")
    private val zuvieleZeichen = Regex("(\\P{M})(\\p{M}{3})\\p{M}+")
    private val zuvieleZeilen = Regex("\\n{3,}")
    private val zuvieleLeerzeichen = Regex("[\\u0020\\u00A0\\u3000]{3,}")

    private fun kappen(s: String) = s.trim { it.isWhitespace() }

    fun saeubern(roh: String): String {
        var s = Normalizer.normalize(wohlgeformt(roh), Normalizer.Form.NFC).replace("\r\n", "\n").replace("\r", "\n").replace("\t", " ")
        s = steuerzeichen.replace(s, "")
        s = richtung.replace(s, "")
        s = unsichtbar.replace(s, "")
        s = zeichenAmAnfang.replace(s, "")
        s = zuvieleZeichen.replace(s, "$1$2")
        s = zuvieleZeilen.replace(s, "\n\n")
        s = zuvieleLeerzeichen.replace(s, "  ")
        s = kappen(s)
        return kappen(vorne(s, HOECHSTENS))
    }

    /** Einzelne Ersatzzeichen (kein gültiges Unicode) werden zu U+FFFD, wie toWellFormed() im Browser */
    private fun wohlgeformt(s: String): String {
        var sb: StringBuilder? = null
        for (i in s.indices) {
            val c = s[i]
            val kaputt = when {
                Character.isHighSurrogate(c) -> i + 1 >= s.length || !Character.isLowSurrogate(s[i + 1])
                Character.isLowSurrogate(c) -> i == 0 || !Character.isHighSurrogate(s[i - 1])
                else -> false
            }
            if (kaputt) { if (sb == null) sb = StringBuilder(s); sb.setCharAt(i, '�') }
        }
        return sb?.toString() ?: s
    }

    /** Die ersten [n] Unicode-Zeichen (Codepunkte), wie `Array.from(s).slice(0, n)` im Browser */
    internal fun vorne(s: String, n: Int): String =
        if (s.codePointCount(0, s.length) <= n) s else s.substring(0, s.offsetByCodePoints(0, n))
}
