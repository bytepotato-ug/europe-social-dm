package com.bytepotato.europesocial.kern

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Prüfvektoren und Beispielantworten liegen nur einmal im Repo (ios/EuropeKit/Tests/EuropeKitTests/Daten), nicht kopiert */
object TestDaten {
    val wurzel = File(System.getProperty("europe.repoRoot") ?: error("europe.repoRoot fehlt"))
    fun ios(name: String): File = File(wurzel, "ios/EuropeKit/Tests/EuropeKitTests/Daten/$name").also { check(it.isFile) { "fehlt: $it" } }
    fun text(name: String): String = ios(name).readText()

    val dm: JsonObject by lazy { Json.parseToJsonElement(text("dm.json")).jsonObject }

    class Konto(val id: Int, val privatPkcs8: String, val oeffentlich: String) {
        val schluessel get() = Krypto.privatAusPkcs8(privatPkcs8.ausB64u()!!)
    }

    fun person(name: String): Konto {
        val o = dm[name]!!.jsonObject
        return Konto(o["id"]!!.jsonPrimitive.int, o["privat"]!!.jsonPrimitive.content, o["oeffentlich"]!!.jsonPrimitive.content)
    }

    fun feld(vararg pfad: String): String {
        var o: JsonObject = dm
        for (p in pfad.dropLast(1)) o = o[p]!!.jsonObject
        return (o[pfad.last()] as JsonPrimitive).content
    }

    fun zahl(vararg pfad: String): Int = feld(*pfad).toInt()

    /** node, falls vorhanden (für die Gegenrichtung gegen den Browser-Code); sonst null */
    val node: String? by lazy {
        listOf("node", "/opt/homebrew/bin/node", "/usr/local/bin/node").firstOrNull {
            try { ProcessBuilder(it, "--version").redirectErrorStream(true).start().waitFor() == 0 } catch (_: Exception) { false }
        }
    }

    fun nodeLaufen(vararg args: String): Pair<Int, String> {
        val p = ProcessBuilder(listOf(node!!) + args).directory(wurzel).redirectErrorStream(true).start()
        val aus = p.inputStream.readBytes().decodeToString()
        return p.waitFor() to aus
    }
}
