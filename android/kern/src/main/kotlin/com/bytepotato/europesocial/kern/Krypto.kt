package com.bytepotato.europesocial.kern

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Fehler der Verschlüsselung, so geschnitten wie Krypto.Fehler und DmKrypto.Fehler in Swift */
class KryptoFehler(val art: Art, ursache: Throwable? = null) : Exception(art.name, ursache) {
    enum class Art {
        NICHT_FUER_MICH, UNBEKANNTE_FASSUNG, UNLESBAR, LEER, SCHLUESSEL, PASST_NICHT,
        /** Der Passkey liefert keine PRF und kann die Nachrichten deshalb nicht entsperren */
        KEIN_PRF,
        /** Dieser Passkey hat die Nachrichten des Kontos noch nicht entsperrt (oder gehört nicht zum Konto) */
        ANDERER_PASSKEY,
    }
}

/** base64url ohne Auffüllung, wie überall auf Server und Seite */
val ByteArray.b64u: String get() = Base64.getUrlEncoder().withoutPadding().encodeToString(this)

/** Gegenstück zu [b64u]; null bei ungültigen Zeichen */
fun String.ausB64u(): ByteArray? = try { Base64.getUrlDecoder().decode(this) } catch (_: IllegalArgumentException) { null }

/**
 * Die Bausteine der Ende-zu-Ende-Verschlüsselung (Krypto.swift und die Hilfen aus CryptoKit): nur JCA, keine Fremdbibliothek.
 * Schlüssel sind P-256 (EC), ECDH, HKDF-SHA256 (selbst über HmacSHA256), AES-256-GCM.
 * Private Schlüssel sind `java.security.PrivateKey`: ein Software-Schlüssel oder ein Schlüssel aus dem Android-Keystore
 * (ECDH läuft über `KeyAgreement`, die Schlüsselbytes selbst brauchen nur die Funktionen mit „Roh“ im Namen).
 */
object Krypto {
    /** Fester PRF-Eingabewert für alle Konten (dmcrypto.js, prfSalz). Das Geheimnis steckt im Passkey. */
    val prfSalz: ByteArray = MessageDigest.getInstance("SHA-256").digest("europe.social e2ee v1".toByteArray())

    private val zufall = SecureRandom()

    fun zufallsBytes(n: Int): ByteArray = ByteArray(n).also { zufall.nextBytes(it) }

    // ---------- Kurve ----------

    private val kurve: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
    }
    private val feldP: BigInteger by lazy { (kurve.curve.field as ECFieldFp).p }

    fun neuesPaar(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun zu32(x: BigInteger): ByteArray {
        val b = x.toByteArray()
        return when {
            b.size == 32 -> b
            b.size > 32 -> b.copyOfRange(b.size - 32, b.size) // führendes Vorzeichenbyte
            else -> ByteArray(32 - b.size) + b
        }
    }

    /** Öffentlicher Schlüssel roh unkomprimiert (65 Byte: 04 ‖ X ‖ Y), wie der Server ihn speichert */
    fun oeffentlichRoh(pub: PublicKey): ByteArray {
        val p = (pub as? ECPublicKey ?: throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL)).w
        return byteArrayOf(4) + zu32(p.affineX) + zu32(p.affineY)
    }

    /** Öffentlicher Schlüssel wie auf dem Server gespeichert: roh unkomprimiert, base64url */
    fun oeffentlich(pub: PublicKey): String = oeffentlichRoh(pub).b64u

    /** Öffentlicher Schlüssel zu einem privaten (nur für Schlüssel, deren Zahl sich lesen lässt, nicht für Keystore-Schlüssel) */
    fun oeffentlich(privat: PrivateKey): String = oeffentlichRohAus(privat).b64u

    fun oeffentlichRohAus(privat: PrivateKey): ByteArray {
        val s = (privat as? ECPrivateKey ?: throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL)).s
        val p = malPunkt(s, kurve.generator) ?: throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL)
        return byteArrayOf(4) + zu32(p.affineX) + zu32(p.affineY)
    }

    /** Öffentlichen Schlüssel aus 65 Rohbytes lesen und prüfen (Länge, Kennbyte 4, Punkt liegt auf der Kurve) */
    fun oeffentlichAusRoh(roh: ByteArray): PublicKey {
        if (roh.size != 65 || roh[0] != 4.toByte()) throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL)
        val x = BigInteger(1, roh.copyOfRange(1, 33))
        val y = BigInteger(1, roh.copyOfRange(33, 65))
        val p = feldP
        val links = y.multiply(y).mod(p)
        val rechts = x.pow(3).add(kurve.curve.a.multiply(x)).add(kurve.curve.b).mod(p)
        if (x >= p || y >= p || links != rechts) throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL)
        return try {
            KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), kurve))
        } catch (e: Exception) { throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL, e) }
    }

    fun oeffentlichAusB64u(b64: String): PublicKey =
        oeffentlichAusRoh(b64.ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL))

    /** Privater Schlüssel aus den 32 Rohbytes der Zahl (so legt die App ihn in der Ablage ab, wie rawRepresentation in Swift) */
    fun privatAusRoh(roh: ByteArray): PrivateKey {
        if (roh.size != 32) throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL)
        return try { KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, roh), kurve)) }
        catch (e: Exception) { throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL, e) }
    }

    /** Privater Schlüssel aus PKCS#8 (so exportiert ihn WebCrypto und packt ihn der Browser ein) */
    fun privatAusPkcs8(der: ByteArray): PrivateKey =
        try { KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der)) }
        catch (e: Exception) { throw KryptoFehler(KryptoFehler.Art.UNLESBAR, e) }

    /** Die 32 Rohbytes der Zahl eines Software-Schlüssels (zum Ablegen) */
    fun roh(privat: PrivateKey): ByteArray = zu32((privat as? ECPrivateKey ?: throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL)).s)

    /**
     * PKCS#8 wie WebCrypto und CryptoKit es schreiben (mit eingebettetem öffentlichem Schlüssel), damit der Browser es
     * sicher wieder einliest. Die Länge ist bei P-256 immer gleich: 138 Byte.
     */
    fun pkcs8(privat: PrivateKey): ByteArray {
        val d = roh(privat)
        val pub = oeffentlichRohAus(privat)
        val kopf = hex("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420")
        val mitte = hex("a144034200")
        return kopf + d + mitte + pub
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    // Punkt mal Zahl auf P-256, nur um aus einem privaten Schlüssel den öffentlichen zu gewinnen (Verdoppeln und Addieren, affin)
    private fun malPunkt(k: BigInteger, g: ECPoint): ECPoint? {
        var ergebnis: ECPoint? = null
        var zusatz: ECPoint? = g
        var z = k
        while (z.signum() > 0) {
            if (z.testBit(0)) ergebnis = addieren(ergebnis, zusatz)
            zusatz = addieren(zusatz, zusatz)
            z = z.shiftRight(1)
        }
        return ergebnis
    }

    private fun addieren(a: ECPoint?, b: ECPoint?): ECPoint? {
        if (a == null || a == ECPoint.POINT_INFINITY) return b
        if (b == null || b == ECPoint.POINT_INFINITY) return a
        val p = feldP
        val lambda = if (a.affineX == b.affineX) {
            if (a.affineY.add(b.affineY).mod(p).signum() == 0) return null
            a.affineX.pow(2).multiply(BigInteger.valueOf(3)).add(kurve.curve.a)
                .multiply(a.affineY.shiftLeft(1).modInverse(p)).mod(p)
        } else {
            b.affineY.subtract(a.affineY).multiply(b.affineX.subtract(a.affineX).mod(p).modInverse(p)).mod(p)
        }
        val x = lambda.pow(2).subtract(a.affineX).subtract(b.affineX).mod(p)
        val y = lambda.multiply(a.affineX.subtract(x)).subtract(a.affineY).mod(p)
        return ECPoint(x, y)
    }

    // ---------- Verfahren ----------

    /** Gemeinsames Geheimnis (32 Byte) aus ECDH; läuft auch mit einem Keystore-Schlüssel */
    fun ecdh(privat: PrivateKey, oeff: PublicKey): ByteArray {
        try {
            val ka = KeyAgreement.getInstance("ECDH")
            ka.init(privat)
            ka.doPhase(oeff, true)
            return ka.generateSecret()
        } catch (e: KryptoFehler) { throw e } catch (e: Exception) { throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL, e) }
    }

    private fun hmac(schluessel: ByteArray, daten: ByteArray): ByteArray {
        val m = Mac.getInstance("HmacSHA256")
        m.init(SecretKeySpec(schluessel, "HmacSHA256"))
        return m.doFinal(daten)
    }

    /** HMAC-SHA256, für die Bindung der Hülle an den Inhalt ([DmKrypto]) */
    fun hmacSha256(schluessel: ByteArray, daten: ByteArray): ByteArray = hmac(schluessel, daten)

    /** HKDF-SHA256 (RFC 5869); ohne Salz gilt ein Salz aus 32 Nullbytes, wie bei CryptoKit und WebCrypto */
    fun hkdf(ikm: ByteArray, salz: ByteArray, info: ByteArray, laenge: Int = 32): ByteArray {
        val prk = hmac(if (salz.isEmpty()) ByteArray(32) else salz, ikm)
        val aus = ByteArrayOutputStream()
        var t = ByteArray(0)
        var i = 1
        while (aus.size() < laenge) {
            t = hmac(prk, t + info + byteArrayOf(i.toByte()))
            aus.write(t)
            i++
        }
        return aus.toByteArray().copyOf(laenge)
    }

    /** AES-256-GCM: liefert Chiffrat ‖ Tag (16 Byte), wie die Seite und Swift es verschicken */
    fun gcmSiegeln(schluessel: ByteArray, iv: ByteArray, klar: ByteArray, zusatz: ByteArray? = null): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(schluessel, "AES"), GCMParameterSpec(128, iv))
        if (zusatz != null) c.updateAAD(zusatz)
        return c.doFinal(klar)
    }

    /** Gegenstück zu [gcmSiegeln]; wirft UNLESBAR bei falschem Schlüssel, falschen Zusatzdaten oder verändertem Chiffrat */
    fun gcmOeffnen(schluessel: ByteArray, iv: ByteArray, chiffratMitTag: ByteArray, zusatz: ByteArray? = null): ByteArray {
        if (iv.size != 12 || chiffratMitTag.size < 16) throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(schluessel, "AES"), GCMParameterSpec(128, iv))
            if (zusatz != null) c.updateAAD(zusatz)
            return c.doFinal(chiffratMitTag)
        } catch (e: Exception) { throw KryptoFehler(KryptoFehler.Art.UNLESBAR, e) }
    }

    fun sha256(daten: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(daten)

    // ---------- Schlüssel am Passkey (dmcrypto.js, hueller, einpacken, auspacken) ----------

    private fun huelle(prf: ByteArray, uid: Int, credId: String): ByteArray =
        hkdf(prf, ByteArray(0), "cs-wrap-v1|$uid|$credId".toByteArray(), 32)

    /** HKDF-SHA256 ohne Salz über die PRF-Ausgabe, AES-256-GCM, "iv.chiffrat" */
    fun auspacken(gepackt: String, prf: ByteArray, uid: Int, credId: String): PrivateKey {
        val teile = gepackt.split(".")
        if (teile.size != 2) throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        val iv = teile[0].ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        val ct = teile[1].ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        val pkcs8 = gcmOeffnen(huelle(prf, uid, credId), iv, ct, "cs-wrap-v1|$uid".toByteArray())
        return privatAusPkcs8(pkcs8)
    }

    /** Gegenstück für neue Passkeys und neue Schlüssel (dmcrypto.js, einpacken) */
    fun einpacken(privat: PrivateKey, prf: ByteArray, uid: Int, credId: String): String {
        val iv = zufallsBytes(12)
        val ct = gcmSiegeln(huelle(prf, uid, credId), iv, pkcs8(privat), "cs-wrap-v1|$uid".toByteArray())
        return iv.b64u + "." + ct.b64u
    }

    // ---------- Gerät koppeln (KOPPELN.md, dmcrypto.js: kopplungFp, kopplungNonce, kopplungCommit, kopplungZahl, kopplungEinpacken, kopplungAuspacken) ----------

    private const val KOPPEL = "cs-pair-v1"

    private fun verbinden(vararg teile: ByteArray): ByteArray = ByteArrayOutputStream().also { o -> teile.forEach { o.write(it) } }.toByteArray()

    /** Fingerabdruck des Einmal-Schlüssels des neuen Geräts (N) für den QR-Code: 12 Byte SHA-256, base64url (16 Zeichen) */
    fun kopplungFp(pubN: String): String {
        val roh = pubN.ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL)
        return sha256(verbinden("$KOPPEL|".toByteArray(), roh)).copyOf(12).b64u
    }

    /** Zufällige Nonce für das Commitment: 16 Byte, base64url (22 Zeichen) */
    fun kopplungNonce(): String = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }.b64u

    /**
     * Commitment des neuen Geräts (seit 2026-11-16): SHA-256("cs-pair-commit-v1|" ‖ pubN ‖ nonce), base64url (43 Zeichen).
     * Das neue Gerät schickt es vor seinem Einmal-Schlüssel, das andere Gerät prüft es nach dem Offenlegen selbst. So kann
     * ein bösartiger Server die Prüfzahl nicht durch Probieren passend machen (KOPPELN.md).
     */
    fun kopplungCommit(pubN: String, nonce: String): String {
        val n = pubN.ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL)
        val z = nonce.ausB64u()?.takeIf { it.size == 16 } ?: throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL)
        return sha256(verbinden("cs-pair-commit-v1|".toByteArray(), n, z)).b64u
    }

    /** Prüfzahl aus beiden Einmal-Schlüsseln (neues Gerät zuerst): sechs Ziffern mit führenden Nullen, zum Beispiel "951722" */
    fun kopplungZahl(pubN: String, pubA: String): String {
        val n = pubN.ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL)
        val a = pubA.ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL)
        val h = sha256(verbinden("cs-pair-sas-v1|".toByteArray(), n, a))
        val wert = ((h[0].toLong() and 255) shl 24) or ((h[1].toLong() and 255) shl 16) or ((h[2].toLong() and 255) shl 8) or (h[3].toLong() and 255)
        return String.format(java.util.Locale.ROOT, "%06d", wert % 1_000_000)
    }

    /** Anzeige der Prüfzahl in zwei Dreiergruppen: "951 722" */
    fun kopplungZahlText(zahl: String): String = if (zahl.length == 6) zahl.substring(0, 3) + " " + zahl.substring(3) else zahl

    private fun kopplungsSchluessel(eigen: PrivateKey, fremdPub: String, pubN: String, pubA: String, uid: Int, id: String): ByteArray {
        val z = ecdh(eigen, oeffentlichAusB64u(fremdPub))
        val salz = verbinden(pubN.ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL), pubA.ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.SCHLUESSEL))
        return hkdf(z, salz, "$KOPPEL|$uid|$id".toByteArray(), 32)
    }

    /** Entsperrtes Gerät (A): den DM-Schlüssel (pkcs8, wie [einpacken]) für das neue Gerät verschlüsseln, "iv.chiffrat" */
    fun kopplungEinpacken(dmPrivat: PrivateKey, eigen: PrivateKey, pubN: String, pubA: String, uid: Int, id: String): String {
        val k = kopplungsSchluessel(eigen, pubN, pubN, pubA, uid, id)
        val iv = zufallsBytes(12)
        return iv.b64u + "." + gcmSiegeln(k, iv, pkcs8(dmPrivat), "$KOPPEL|$uid|$id".toByteArray()).b64u
    }

    /** Neues Gerät (N): auspacken. Ob der Schlüssel zum Konto gehört, prüft der Aufrufer (öffentlicher Schlüssel gegen /dm/keys/me). */
    fun kopplungAuspacken(gepackt: String, eigen: PrivateKey, pubN: String, pubA: String, uid: Int, id: String): PrivateKey {
        val teile = gepackt.split(".")
        if (teile.size != 2) throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        val iv = teile[0].ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        val ct = teile[1].ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        val k = kopplungsSchluessel(eigen, pubA, pubN, pubA, uid, id)
        return privatAusPkcs8(gcmOeffnen(k, iv, ct, "$KOPPEL|$uid|$id".toByteArray()))
    }

    // ---------- Wiederherstellungscode (dmcrypto.js, codeNeu, codeLesen, codeEinpacken, codeAuspacken) ----------

    private const val CODE_ZEICHEN = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    const val CODE_BYTES = 20

    /** Crockford-Base32, 20 Byte ergeben 32 Zeichen in acht Vierergruppen */
    fun codeText(roh: ByteArray): String {
        var bits = 0; var wert = 0; val aus = StringBuilder()
        for (b in roh) {
            wert = (wert shl 8) or (b.toInt() and 255); bits += 8
            while (bits >= 5) { aus.append(CODE_ZEICHEN[(wert ushr (bits - 5)) and 31]); bits -= 5 }
            wert = wert and ((1 shl bits) - 1)
        }
        return aus.chunked(4).joinToString("-")
    }

    fun codeNeu(): Pair<ByteArray, String> { val roh = zufallsBytes(CODE_BYTES); return roh to codeText(roh) }

    class CodeFehler(val art: Art) : Exception(art.name) { enum class Art { UNVOLLSTAENDIG, ZEICHEN, PASST_NICHT } }

    /** Groß- und Kleinschreibung, Leerzeichen und Striche egal; O als 0, I und L als 1 */
    /**
     * Anzeige beim Tippen und Einfügen: Großbuchstaben und Ziffern in Vierergruppen mit Bindestrich, höchstens 32 Zeichen
     * (wie im Web, public/javascripts/app.js codeFormatieren). Alles andere (Leerzeichen, alte Bindestriche) fällt weg;
     * codeLesen versteht das Ergebnis wie jede andere Schreibweise.
     */
    fun codeFormatieren(text: String): String =
        text.uppercase().filter { it in 'A'..'Z' || it in '0'..'9' }.take(CODE_BYTES * 8 / 5).chunked(4).joinToString("-")

    fun codeLesen(text: String): ByteArray {
        val s = text.uppercase().filterNot { it in " \t\n-–—_." }.replace('O', '0').replace('I', '1').replace('L', '1')
        if (s.length != CODE_BYTES * 8 / 5) throw CodeFehler(CodeFehler.Art.UNVOLLSTAENDIG)
        val roh = ByteArray(CODE_BYTES); var bits = 0; var wert = 0; var n = 0
        for (c in s) {
            val z = CODE_ZEICHEN.indexOf(c)
            if (z < 0) throw CodeFehler(CodeFehler.Art.ZEICHEN)
            wert = ((wert shl 5) or z) and 0xffff; bits += 5
            if (bits >= 8) { roh[n++] = ((wert ushr (bits - 8)) and 255).toByte(); bits -= 8 }
        }
        return roh
    }

    private fun codeHuelle(roh: ByteArray, uid: Int): ByteArray = hkdf(roh, ByteArray(0), "cs-code-v1|$uid".toByteArray(), 32)

    fun codeEinpacken(privat: PrivateKey, roh: ByteArray, uid: Int): String {
        val iv = zufallsBytes(12)
        return iv.b64u + "." + gcmSiegeln(codeHuelle(roh, uid), iv, pkcs8(privat), "cs-code-v1|$uid".toByteArray()).b64u
    }

    fun codeAuspacken(gepackt: String, roh: ByteArray, uid: Int): PrivateKey {
        val teile = gepackt.split(".")
        if (teile.size != 2) throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        val iv = teile[0].ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        val ct = teile[1].ausB64u() ?: throw KryptoFehler(KryptoFehler.Art.UNLESBAR)
        if (roh.size != CODE_BYTES) throw CodeFehler(CodeFehler.Art.UNVOLLSTAENDIG)
        val pkcs8 = try { gcmOeffnen(codeHuelle(roh, uid), iv, ct, "cs-code-v1|$uid".toByteArray()) } catch (e: KryptoFehler) { throw CodeFehler(CodeFehler.Art.PASST_NICHT) }
        return privatAusPkcs8(pkcs8)
    }

    /** Kurzer Fingerabdruck zum Vergleichen: 20 Hex-Zeichen in Fünfergruppen (dmcrypto.js, fingerabdruck) */
    fun fingerabdruck(pub: String): String? {
        val roh = pub.ausB64u() ?: return null
        val h = sha256(roh).copyOf(10).joinToString("") { "%02x".format(it) }
        return h.chunked(5).joinToString(" ")
    }
}
