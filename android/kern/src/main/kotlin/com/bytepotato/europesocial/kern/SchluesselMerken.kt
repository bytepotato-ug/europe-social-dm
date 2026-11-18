package com.bytepotato.europesocial.kern

/**
 * Schlüssel der Gegenüber merken (Trust on first use), genau wie `pin()` in public/javascripts/app.js und
 * SchluesselMerken.swift: Beim ersten Kontakt wird der öffentliche DM-Schlüssel je (eigenes Konto, Partner) gemerkt,
 * danach nur noch verglichen. Reine Logik, der Speicher liegt in [Konten].
 */
object SchluesselMerken {
    /** Unbekannt: merken, gilt. Gleich: gilt. Anders: gilt nicht, nichts wird geändert. */
    fun pruefen(pins: MutableMap<String, String>, partner: Int, schluessel: String): Boolean {
        val alt = pins[partner.toString()]
        if (alt == null) { pins[partner.toString()] = schluessel; return true }
        return alt == schluessel
    }

    /** Welche Schlüssel weichen vom gemerkten ab? Unbekannte werden gemerkt (erster Kontakt). Rückgabe: Partner-Nummern. */
    fun geaenderte(pins: MutableMap<String, String>, schluessel: Map<Int, String>): List<Int> =
        schluessel.keys.sorted().filter { !pruefen(pins, it, schluessel.getValue(it)) }

    /** Nach der Bestätigung: den neuen Schlüssel merken */
    fun uebernehmen(pins: MutableMap<String, String>, schluessel: Map<Int, String>, partner: List<Int>) {
        for (p in partner) schluessel[p]?.let { pins[p.toString()] = it }
    }

    /**
     * Welcher Schlüssel gilt für [von], wenn etwas gegen ihn geprüft wird (Gruppennamen)? [bekannt] ist ein Schlüssel aus sicherer
     * Quelle (Mitgliederliste, eigener Schlüssel). Gibt es zusätzlich einen gemerkten, müssen beide übereinstimmen (sonst null:
     * der Schlüssel hat sich geändert); gibt es nur einen, gilt er; gibt es keinen, null. Ändert nichts.
     */
    fun erwartet(pins: Map<String, String>, von: Int, bekannt: String?): String? {
        val gemerkt = pins[von.toString()]
        if (bekannt != null && gemerkt != null) return if (bekannt == gemerkt) bekannt else null
        return bekannt ?: gemerkt
    }
}
