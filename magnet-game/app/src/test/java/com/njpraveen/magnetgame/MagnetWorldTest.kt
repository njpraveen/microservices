package com.njpraveen.magnetgame

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

class MagnetWorldTest {

    @Test
    fun farApartMagnetsStayPut() {
        val w = MagnetWorld()
        w.place(-0.5f, 0f); w.settle()
        w.place(0.5f, 0f); w.settle()
        assertTrue(w.takeClashed().isEmpty())
        assertEquals(-0.5f, w.magnets[0].x, 1e-6f)
        assertEquals(0.5f, w.magnets[1].x, 1e-6f)
    }

    @Test
    fun closeMagnetsSnapTogether() {
        val w = MagnetWorld()
        var clacks = 0
        w.onClack = { _, _ -> clacks++ }
        w.place(0f, 0f); w.settle()
        w.place(0.25f, 0f); w.settle()
        assertEquals(1, clacks)
        assertEquals(2, w.takeClashed().size)
        assertTrue(w.magnets.isEmpty())
    }

    @Test
    fun chainReactionPullsInNeighbour() {
        val w = MagnetWorld()
        w.place(-0.28f, 0f); w.settle()
        w.place(0.28f, 0f); w.settle()
        assertTrue(w.takeClashed().isEmpty())
        // Dropping one in the middle drags both neighbours in.
        w.place(0f, 0f); w.settle()
        assertEquals(3, w.takeClashed().size)
    }

    @Test
    fun placingOnTopOfAnotherSnapsImmediately() {
        val w = MagnetWorld()
        w.place(0f, 0f); w.settle()
        w.place(0.05f, 0f)
        w.settle()
        assertEquals(2, w.takeClashed().size)
    }

    @Test
    fun riskPredictsSnap() {
        val w = MagnetWorld()
        w.place(0f, 0f); w.settle()
        assertTrue(w.risk(0.2f, 0f) > 1f)
        assertTrue(w.risk(0.5f, 0f) < 1f)
        assertFalse(w.isInsideRing(0.99f, 0f))
    }

    @Test
    fun gameEndsWithAWinner() {
        val random = Random(42)
        val game = Game(listOf("A", "B"), listOf(true, true))
        assertEquals(12, game.players[0].hand)
        var turns = 0
        while (!game.isOver && turns < 2000) {
            val (x, y) = game.world.chooseAiMove(random, 0.6f)
            val cx = x.coerceIn(-0.9f, 0.9f)
            if (game.place(cx, y)) {
                game.world.settle()
                game.endTurn()
            }
            turns++
        }
        assertTrue("game should finish", game.isOver)
        assertEquals(0, game.winner!!.hand)
    }
}
