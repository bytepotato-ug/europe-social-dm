package com.bytepotato.europesocial.kern

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SchluesselMerkenTest {
    @Test fun ersterKontaktMerktUndGilt() {
        val pins = mutableMapOf<String, String>()
        assertTrue(SchluesselMerken.pruefen(pins, 7, "A"))
        assertEquals("A", pins["7"])
    }

    @Test fun gleicherGiltGeaenderterNichtUndBleibtUnveraendert() {
        val pins = mutableMapOf("7" to "A")
        assertTrue(SchluesselMerken.pruefen(pins, 7, "A"))
        assertFalse(SchluesselMerken.pruefen(pins, 7, "B"))
        assertEquals("A", pins["7"])
    }

    @Test fun gruppeMeldetNurAbweichendeUndMerktNeue() {
        val pins = mutableMapOf("1" to "A", "2" to "B")
        assertEquals(listOf(2), SchluesselMerken.geaenderte(pins, mapOf(1 to "A", 2 to "X", 3 to "C")))
        assertEquals("C", pins["3"])
        assertEquals("B", pins["2"])
    }

    @Test fun bestaetigungUebernimmtNeuenSchluessel() {
        val pins = mutableMapOf("2" to "B")
        SchluesselMerken.uebernehmen(pins, mapOf(2 to "X"), listOf(2))
        assertTrue(SchluesselMerken.pruefen(pins, 2, "X"))
    }
}
