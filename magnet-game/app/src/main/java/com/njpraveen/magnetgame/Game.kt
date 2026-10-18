package com.njpraveen.magnetgame

class Player(val name: String, val isComputer: Boolean, var hand: Int)

/**
 * The rules from the box:
 *  1. The magnets are divided evenly among the players.
 *  2. Players take turns placing one magnet inside the ring. If two or more magnets snap together,
 *     the player who just placed takes all the snapped magnets back into their hand.
 *  3. The first player to place their last magnet without causing a snap wins.
 */
class Game(playerNames: List<String>, computerFlags: List<Boolean>, totalMagnets: Int = 24) {
    val world = MagnetWorld()
    val players: List<Player>
    var current = 0
        private set
    var winner: Player? = null
        private set

    init {
        require(playerNames.size in 2..4)
        val each = totalMagnets / playerNames.size
        players = playerNames.mapIndexed { i, name -> Player(name, computerFlags[i], each) }
    }

    val currentPlayer get() = players[current]
    val isOver get() = winner != null

    /** Places the current player's magnet. Returns false if the move isn't allowed. */
    fun place(x: Float, y: Float): Boolean {
        if (isOver || world.simulating || currentPlayer.hand <= 0) return false
        if (!world.isInsideRing(x, y)) return false
        currentPlayer.hand--
        world.place(x, y)
        return true
    }

    /**
     * Must be called once the world has settled after [place]. Hands any snapped magnets to the
     * current player, checks for a win and moves on to the next player.
     * Returns the magnets the player had to take.
     */
    fun endTurn(): List<Magnet> {
        val taken = world.takeClashed()
        val p = currentPlayer
        p.hand += taken.size
        if (p.hand == 0) {
            winner = p
        } else {
            current = (current + 1) % players.size
        }
        return taken
    }
}
