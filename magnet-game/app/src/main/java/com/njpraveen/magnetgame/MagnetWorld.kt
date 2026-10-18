package com.njpraveen.magnetgame

import kotlin.math.cos
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.sin
import kotlin.math.sqrt
import kotlin.random.Random

/** A single magnet stone. Coordinates are in world units: the rope ring has radius 1 centred at (0, 0). */
class Magnet(var x: Float, var y: Float) {
    var vx = 0f
    var vy = 0f
    var moving = false

    /** True once this magnet has snapped onto another one ("clack"). Stuck magnets no longer move. */
    var stuck = false
}

/**
 * Physics of the magnets inside the rope ring.
 *
 * Every pair of magnets attracts with a force STRENGTH / d². A resting magnet only starts to slide
 * when the net pull on it beats static friction, so a lone pair begins to move once they are closer
 * than [PULL_RANGE]. When two magnets touch they snap together and stay put.
 */
class MagnetWorld {
    companion object {
        const val ARENA_RADIUS = 1f
        const val MAGNET_RADIUS = 0.065f
        const val CONTACT = MAGNET_RADIUS * 2

        /** Separation at which two lone magnets start sliding towards each other. */
        const val PULL_RANGE = 0.30f
        const val STRENGTH = 3f
        const val STATIC_FRICTION = STRENGTH / (PULL_RANGE * PULL_RANGE)
        const val KINETIC_FRICTION = STATIC_FRICTION * 0.5f

        /** Magnets farther apart than this are treated as not interacting at all. */
        const val MAX_INFLUENCE = 0.8f

        private const val STOP_SPEED = 0.02f
        private const val SETTLE_QUIET_TIME = 0.25f
        private const val MAX_SIM_TIME = 5f
        private const val SUB_STEP = 1f / 240f
    }

    val magnets = mutableListOf<Magnet>()

    /** True while a placement is being resolved. */
    var simulating = false
        private set

    private var simTime = 0f
    private var quietTime = 0f
    private var accumulator = 0f

    /** Called with the two magnets each time a pair snaps together. */
    var onClack: ((Magnet, Magnet) -> Unit)? = null

    fun reset() {
        magnets.clear()
        simulating = false
    }

    /** True if a magnet centred at (x, y) lies fully inside the rope. */
    fun isInsideRing(x: Float, y: Float): Boolean =
        hypot(x, y) <= ARENA_RADIUS - MAGNET_RADIUS

    /** Drops a new magnet at (x, y) and starts resolving the physics. */
    fun place(x: Float, y: Float): Magnet {
        val m = Magnet(x, y)
        for (o in magnets) {
            if (dist(m, o) < CONTACT) snap(m, o)
        }
        magnets.add(m)
        simulating = true
        simTime = 0f
        quietTime = 0f
        accumulator = 0f
        return m
    }

    /** Advances the simulation by [dt] seconds. Returns true once everything has come to rest. */
    fun update(dt: Float): Boolean {
        if (!simulating) return true
        accumulator += dt.coerceAtMost(0.1f)
        while (accumulator >= SUB_STEP && simulating) {
            accumulator -= SUB_STEP
            subStep(SUB_STEP)
        }
        return !simulating
    }

    /** Runs the simulation to completion without rendering. */
    fun settle() {
        while (simulating) subStep(SUB_STEP)
    }

    /** Removes and returns every magnet that clacked during this turn. */
    fun takeClashed(): List<Magnet> {
        val clashed = magnets.filter { it.stuck }
        magnets.removeAll(clashed)
        return clashed
    }

    private fun subStep(dt: Float) {
        simTime += dt
        val n = magnets.size
        val fx = FloatArray(n)
        val fy = FloatArray(n)
        for (i in 0 until n) {
            for (j in i + 1 until n) {
                val a = magnets[i]
                val b = magnets[j]
                val dx = b.x - a.x
                val dy = b.y - a.y
                val d = hypot(dx, dy)
                if (d > MAX_INFLUENCE || d < 1e-6f) continue
                val r = max(d, CONTACT)
                val f = STRENGTH / (r * r)
                val ux = dx / d
                val uy = dy / d
                fx[i] += f * ux; fy[i] += f * uy
                fx[j] -= f * ux; fy[j] -= f * uy
            }
        }

        var anyMoving = false
        for (i in 0 until n) {
            val m = magnets[i]
            if (m.stuck) continue
            val fMag = hypot(fx[i], fy[i])
            if (!m.moving) {
                if (fMag <= STATIC_FRICTION) continue
                m.moving = true
            }
            val speed = hypot(m.vx, m.vy)
            val (dirX, dirY) = when {
                speed > 1e-5f -> Pair(m.vx / speed, m.vy / speed)
                fMag > 1e-5f -> Pair(fx[i] / fMag, fy[i] / fMag)
                else -> Pair(0f, 0f)
            }
            m.vx += (fx[i] - KINETIC_FRICTION * dirX) * dt
            m.vy += (fy[i] - KINETIC_FRICTION * dirY) * dt
            if (fMag < STATIC_FRICTION && hypot(m.vx, m.vy) < STOP_SPEED) {
                m.vx = 0f; m.vy = 0f; m.moving = false
                continue
            }
            m.x += m.vx * dt
            m.y += m.vy * dt
            keepInsideRing(m)
            anyMoving = true
        }

        for (i in 0 until n) {
            for (j in i + 1 until n) {
                val a = magnets[i]
                val b = magnets[j]
                if (dist(a, b) < CONTACT && !(a.stuck && b.stuck)) snap(a, b)
            }
        }

        quietTime = if (anyMoving) 0f else quietTime + dt
        if (quietTime >= SETTLE_QUIET_TIME || simTime >= MAX_SIM_TIME) {
            for (m in magnets) { m.vx = 0f; m.vy = 0f; m.moving = false }
            simulating = false
        }
    }

    private fun snap(a: Magnet, b: Magnet) {
        val wasNew = !(a.stuck && b.stuck)
        // Push the pair apart so they rest exactly touching; a stuck magnet stays where it is.
        val dx = b.x - a.x
        val dy = b.y - a.y
        val d = hypot(dx, dy)
        if (d > 1e-6f) {
            val overlap = CONTACT - d
            val ux = dx / d
            val uy = dy / d
            when {
                a.stuck && !b.stuck -> { b.x += ux * overlap; b.y += uy * overlap }
                b.stuck && !a.stuck -> { a.x -= ux * overlap; a.y -= uy * overlap }
                else -> {
                    a.x -= ux * overlap / 2; a.y -= uy * overlap / 2
                    b.x += ux * overlap / 2; b.y += uy * overlap / 2
                }
            }
        }
        for (m in arrayOf(a, b)) {
            m.stuck = true; m.moving = false; m.vx = 0f; m.vy = 0f
        }
        if (wasNew) onClack?.invoke(a, b)
    }

    private fun keepInsideRing(m: Magnet) {
        val limit = ARENA_RADIUS - MAGNET_RADIUS
        val d = hypot(m.x, m.y)
        if (d > limit) {
            val ux = m.x / d
            val uy = m.y / d
            m.x = ux * limit; m.y = uy * limit
            val radial = m.vx * ux + m.vy * uy
            if (radial > 0) { m.vx -= radial * ux; m.vy -= radial * uy }
        }
    }

    private fun dist(a: Magnet, b: Magnet) = hypot(b.x - a.x, b.y - a.y)

    // ---------------------------------------------------------------- Computer opponent

    /**
     * How dangerous dropping a magnet at (x, y) would be: the largest net force on any magnet
     * afterwards, relative to static friction. Values below 1 mean nothing should move.
     */
    fun risk(x: Float, y: Float): Float {
        if (!isInsideRing(x, y)) return Float.MAX_VALUE
        var newFx = 0f
        var newFy = 0f
        var worst = 0f
        for (m in magnets) {
            val dx = m.x - x
            val dy = m.y - y
            val d = hypot(dx, dy)
            if (d < CONTACT) return Float.MAX_VALUE
            if (d > MAX_INFLUENCE) continue
            val f = STRENGTH / (d * d)
            newFx += f * dx / d
            newFy += f * dy / d
            val (ex, ey) = netForceOn(m)
            worst = max(worst, hypot(ex - f * dx / d, ey - f * dy / d) / STATIC_FRICTION)
        }
        return max(worst, hypot(newFx, newFy) / STATIC_FRICTION)
    }

    /** Picks a spot for the computer. Lower [skill] (0..1) makes it sloppier. */
    fun chooseAiMove(random: Random, skill: Float = 0.85f): Pair<Float, Float> {
        val limit = ARENA_RADIUS - MAGNET_RADIUS
        val candidates = ArrayList<Triple<Float, Float, Float>>(500)
        repeat(500) {
            val r = limit * sqrt(random.nextFloat())
            val a = random.nextFloat() * 2f * Math.PI.toFloat()
            val x = r * cos(a)
            val y = r * sin(a)
            candidates.add(Triple(x, y, risk(x, y)))
        }
        candidates.sortBy { it.third }
        // A perfect player always takes the safest spot; a sloppier one picks among the safe-looking ones.
        val tolerance = 0.05f + (1f - skill) * 0.9f
        val best = candidates.first().third
        val pool = candidates.filter { it.third <= max(best + 0.05f, tolerance) }
        val pick = pool[random.nextInt(pool.size)]
        // A little hand wobble.
        val wobble = (1f - skill) * 0.04f
        val x = pick.first + (random.nextFloat() - 0.5f) * wobble
        val y = pick.second + (random.nextFloat() - 0.5f) * wobble
        return Pair(x, y)
    }

    private fun netForceOn(m: Magnet): Pair<Float, Float> {
        var fx = 0f
        var fy = 0f
        for (o in magnets) {
            if (o === m) continue
            val dx = o.x - m.x
            val dy = o.y - m.y
            val d = hypot(dx, dy)
            if (d > MAX_INFLUENCE || d < 1e-6f) continue
            val r = max(d, CONTACT)
            val f = STRENGTH / (r * r)
            fx += f * dx / d
            fy += f * dy / d
        }
        return Pair(fx, fy)
    }
}
