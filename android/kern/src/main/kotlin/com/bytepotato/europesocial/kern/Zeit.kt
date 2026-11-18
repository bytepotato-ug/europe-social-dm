package com.bytepotato.europesocial.kern

import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json

/** JSON-Einstellungen für alles, was der Kern liest oder schreibt: unbekannte Felder egal, fehlende optionale Felder egal */
val kernJson: Json = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
    coerceInputValues = true
    encodeDefaults = false
}

/** Zeitangaben des Servers (toISOString: 2026-11-10T18:00:00.000Z), mit und ohne Bruchteil */
object Zeit {
    private val ausgabe = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC)

    fun lesen(s: String): Instant =
        try { Instant.parse(s) } catch (_: Exception) { OffsetDateTime.parse(s).toInstant() }

    /** Wie der Server schreibt, mit drei Stellen Bruchteil (so legt auch iOS den Zwischenspeicher an) */
    fun text(t: Instant): String = ausgabe.format(t)
}

object ZeitSerializer : KSerializer<Instant> {
    override val descriptor = PrimitiveSerialDescriptor("Zeit", PrimitiveKind.STRING)
    override fun deserialize(decoder: Decoder): Instant = Zeit.lesen(decoder.decodeString())
    override fun serialize(encoder: Encoder, value: Instant) = encoder.encodeString(Zeit.text(value))
}
