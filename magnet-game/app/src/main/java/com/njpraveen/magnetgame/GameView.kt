package com.njpraveen.magnetgame

import android.content.Context
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.Typeface
import android.media.AudioManager
import android.media.ToneGenerator
import android.view.HapticFeedbackConstants
import android.view.MotionEvent
import android.view.View
import kotlin.math.PI
import kotlin.math.min
import kotlin.math.sin
import kotlin.random.Random

/** Draws the table, flower ring and magnets, and runs the turn loop. */
class GameView(
    context: Context,
    private val playerNames: List<String>,
    private val computerFlags: List<Boolean>,
    private val onExit: () -> Unit,
) : View(context) {

    private enum class State { WAITING_INPUT, AI_THINKING, SIMULATING, COLLECTING, GAME_OVER }

    private class Flying(val fromX: Float, val fromY: Float, val toX: Float, val toY: Float)

    private val density = resources.displayMetrics.density
    private fun dp(v: Float) = v * density

    private val playerColors = intArrayOf(
        Color.rgb(229, 57, 53), Color.rgb(30, 136, 229),
        Color.rgb(67, 160, 71), Color.rgb(251, 140, 0),
    )

    private val random = Random(System.nanoTime())
    private lateinit var game: Game
    private var state = State.WAITING_INPUT
    private var stateTime = 0f
    private var message = ""
    private var notice = ""
    private var flying = listOf<Flying>()
    private var shake = 0f

    // Ghost magnet that follows the finger; drawn above the finger so it isn't hidden.
    private var ghostX = 0f
    private var ghostY = 0f
    private var ghostVisible = false

    private var lastFrameNanos = 0L
    private var insetTop = 0
    private var insetBottom = 0

    // World -> screen transform.
    private var cx = 0f
    private var cy = 0f
    private var scale = 1f

    private var tone: ToneGenerator? = try {
        ToneGenerator(AudioManager.STREAM_MUSIC, 70)
    } catch (e: RuntimeException) {
        null
    }

    // The flower wreath that marks the play area, and where its inner wire sits in the bitmap.
    private val ringBitmap = BitmapFactory.decodeResource(resources, R.drawable.flower_ring)
    private val ringCenterX = 592f * ringBitmap.width / 1200f
    private val ringCenterY = 600f * ringBitmap.width / 1200f
    private val ringRadius = 443f * ringBitmap.width / 1200f
    private val ringPaint = Paint(Paint.FILTER_BITMAP_FLAG or Paint.ANTI_ALIAS_FLAG)
    private val ringDst = RectF()
    private val tableColor = Color.rgb(89, 153, 152)
    private val shadowPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.argb(70, 0, 0, 0) }
    private val magnetPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val highlightPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.argb(150, 255, 255, 255) }
    private val ghostPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { alpha = 130 }
    private val warnPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE; color = Color.rgb(229, 57, 53)
    }
    private val panelPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.rgb(33, 33, 33); textAlign = Paint.Align.CENTER
    }
    private val overlayPaint = Paint().apply { color = Color.argb(170, 0, 0, 0) }
    private val buttonPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val rect = RectF()
    private var magnetShaderRadius = -1f

    private val playAgainRect = RectF()
    private val menuRect = RectF()

    init {
        isHapticFeedbackEnabled = true
        setOnApplyWindowInsetsListener { _, insets ->
            @Suppress("DEPRECATION")
            insetTop = insets.systemWindowInsetTop
            @Suppress("DEPRECATION")
            insetBottom = insets.systemWindowInsetBottom
            requestLayout()
            insets
        }
        newGame()
    }

    private fun newGame() {
        notice = ""
        game = Game(playerNames, computerFlags)
        game.world.onClack = { _, _ -> onClack() }
        flying = emptyList()
        beginTurn()
    }

    private fun beginTurn() {
        val p = game.currentPlayer
        stateTime = 0f
        if (p.isComputer) {
            state = State.AI_THINKING
            message = "${p.name} is thinking…"
        } else {
            state = State.WAITING_INPUT
            message = "${p.name}: drag inside the ring and let go"
        }
        invalidate()
    }

    private fun onClack() {
        shake = 1f
        performHapticFeedback(HapticFeedbackConstants.LONG_PRESS)
        tone?.startTone(ToneGenerator.TONE_PROP_BEEP, 35)
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        tone?.release()
        tone = null
    }

    // ------------------------------------------------------------------ layout

    private val hudHeight get() = dp(84f)
    private val footerHeight get() = dp(72f)

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        relayout()
    }

    override fun onLayout(changed: Boolean, left: Int, top: Int, right: Int, bottom: Int) {
        super.onLayout(changed, left, top, right, bottom)
        relayout()
    }

    private fun relayout() {
        val top = insetTop + hudHeight
        val bottom = height - insetBottom - footerHeight
        cx = width / 2f
        cy = (top + bottom) / 2f
        // Fit the whole wreath across the screen; it may run under the score panels vertically.
        val fitWidth = width * ringRadius / ringBitmap.width
        val fitHeight = (bottom - top) / 2f / 1.02f
        scale = min(fitWidth, fitHeight).coerceAtLeast(1f) / MagnetWorld.ARENA_RADIUS
        val k = scale * MagnetWorld.ARENA_RADIUS / ringRadius
        ringDst.set(
            cx - ringCenterX * k, cy - ringCenterY * k,
            cx + (ringBitmap.width - ringCenterX) * k, cy + (ringBitmap.height - ringCenterY) * k,
        )
        val r = MagnetWorld.MAGNET_RADIUS * scale
        if (r != magnetShaderRadius && r > 0) {
            magnetShaderRadius = r
            magnetPaint.shader = RadialGradient(
                -r * 0.35f, -r * 0.4f, r * 1.4f,
                intArrayOf(Color.rgb(120, 120, 125), Color.rgb(45, 45, 50), Color.rgb(12, 12, 14)),
                floatArrayOf(0f, 0.45f, 1f), Shader.TileMode.CLAMP,
            )
            ghostPaint.shader = magnetPaint.shader
        }
        warnPaint.strokeWidth = dp(3f)
    }

    private fun toScreenX(x: Float) = cx + x * scale
    private fun toScreenY(y: Float) = cy + y * scale
    private fun toWorldX(sx: Float) = (sx - cx) / scale
    private fun toWorldY(sy: Float) = (sy - cy) / scale

    private fun panelRect(index: Int, out: RectF) {
        val n = game.players.size
        val pad = dp(8f)
        val w = (width - pad * (n + 1)) / n
        val left = pad + index * (w + pad)
        val top = insetTop + pad
        out.set(left, top, left + w, top + hudHeight - pad)
    }

    // ------------------------------------------------------------------ loop

    private fun tick(dt: Float) {
        stateTime += dt
        shake = (shake - dt * 4f).coerceAtLeast(0f)
        when (state) {
            State.AI_THINKING -> if (stateTime > 0.9f) {
                val (x, y) = game.world.chooseAiMove(random)
                if (game.place(x, y)) startSimulation() else beginTurn()
            }
            State.SIMULATING -> if (game.world.update(dt)) finishTurn()
            State.COLLECTING -> if (stateTime > 0.8f) {
                flying = emptyList()
                afterCollect()
            }
            State.WAITING_INPUT, State.GAME_OVER -> Unit
        }
    }

    private fun startSimulation() {
        state = State.SIMULATING
        stateTime = 0f
        message = ""
        notice = ""
    }

    private fun finishTurn() {
        val player = game.currentPlayer
        val playerIndex = game.current
        val taken = game.endTurn()
        if (taken.isEmpty()) {
            afterCollect()
            return
        }
        panelRect(playerIndex, rect)
        flying = taken.map {
            Flying(toScreenX(it.x), toScreenY(it.y), rect.centerX(), rect.bottom - dp(10f))
        }
        notice = "Clack! ${player.name} takes ${taken.size} magnets back"
        message = ""
        state = State.COLLECTING
        stateTime = 0f
    }

    private fun afterCollect() {
        val winner = game.winner
        if (winner != null) {
            state = State.GAME_OVER
            message = "${winner.name} wins!"
            performHapticFeedback(HapticFeedbackConstants.LONG_PRESS)
        } else {
            beginTurn()
        }
    }

    // ------------------------------------------------------------------ input

    override fun onTouchEvent(event: MotionEvent): Boolean {
        if (state == State.GAME_OVER) {
            if (event.actionMasked == MotionEvent.ACTION_UP) {
                when {
                    playAgainRect.contains(event.x, event.y) -> newGame()
                    menuRect.contains(event.x, event.y) -> onExit()
                }
            }
            return true
        }
        if (state != State.WAITING_INPUT) return true
        val lift = dp(56f)
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN, MotionEvent.ACTION_MOVE -> {
                ghostX = event.x
                ghostY = event.y - lift
                ghostVisible = true
                invalidate()
            }
            MotionEvent.ACTION_UP -> {
                ghostVisible = false
                val wx = toWorldX(event.x)
                val wy = toWorldY(event.y - lift)
                if (game.place(wx, wy)) {
                    performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY)
                    startSimulation()
                } else {
                    message = "Place the magnet fully inside the ring"
                }
                invalidate()
            }
            MotionEvent.ACTION_CANCEL -> {
                ghostVisible = false
                invalidate()
            }
        }
        return true
    }

    // ------------------------------------------------------------------ drawing

    override fun onDraw(canvas: Canvas) {
        val now = System.nanoTime()
        val dt = if (lastFrameNanos == 0L) 0f else (now - lastFrameNanos) / 1e9f
        lastFrameNanos = now
        if (magnetShaderRadius <= 0f) return
        tick(dt)

        canvas.drawColor(tableColor)

        canvas.save()
        if (shake > 0f) {
            val s = dp(6f) * shake
            canvas.translate(sin(stateTime * 90f) * s, sin(stateTime * 70f + 1f) * s * 0.6f)
        }
        drawRing(canvas)
        val r = MagnetWorld.MAGNET_RADIUS * scale
        for (m in game.world.magnets) drawMagnet(canvas, toScreenX(m.x), toScreenY(m.y), r, m.stuck)
        canvas.restore()

        if (state == State.COLLECTING) {
            val t = (stateTime / 0.7f).coerceIn(0f, 1f)
            val ease = t * t * (3 - 2 * t)
            for (f in flying) {
                val x = f.fromX + (f.toX - f.fromX) * ease
                val y = f.fromY + (f.toY - f.fromY) * ease - sin(t * PI.toFloat()) * dp(60f)
                drawMagnet(canvas, x, y, r * (1f - 0.5f * ease), stuck = true)
            }
        }

        if (ghostVisible) {
            val inside = game.world.isInsideRing(toWorldX(ghostX), toWorldY(ghostY))
            canvas.save()
            canvas.translate(ghostX, ghostY)
            canvas.drawCircle(0f, 0f, r, ghostPaint)
            canvas.restore()
            if (!inside) canvas.drawCircle(ghostX, ghostY, r * 1.25f, warnPaint)
        }

        drawHud(canvas)
        drawFooter(canvas)
        if (state == State.GAME_OVER) drawGameOver(canvas)

        if (state == State.WAITING_INPUT && shake == 0f) {
            lastFrameNanos = 0L // idle: restart the clock on the next touch
        } else {
            postInvalidateOnAnimation()
        }
    }

    private fun drawRing(canvas: Canvas) {
        canvas.drawBitmap(ringBitmap, null, ringDst, ringPaint)
    }

    private fun drawMagnet(canvas: Canvas, x: Float, y: Float, r: Float, stuck: Boolean) {
        canvas.save()
        canvas.translate(x, y)
        rect.set(-r * 1.02f, -r * 0.8f + dp(3f), r * 1.02f, r * 0.95f + dp(3f))
        canvas.drawOval(rect, shadowPaint)
        if (r != magnetShaderRadius) canvas.scale(r / magnetShaderRadius, r / magnetShaderRadius)
        val rr = magnetShaderRadius
        canvas.drawCircle(0f, 0f, rr, magnetPaint)
        rect.set(-rr * 0.6f, -rr * 0.7f, rr * 0.05f, -rr * 0.35f)
        canvas.drawOval(rect, highlightPaint)
        if (stuck) {
            canvas.drawCircle(0f, 0f, rr * 1.15f, warnPaint)
        }
        canvas.restore()
    }

    private fun drawHud(canvas: Canvas) {
        val small = magnetShaderRadius.coerceAtMost(dp(6f))
        for ((i, p) in game.players.withIndex()) {
            panelRect(i, rect)
            val active = i == game.current && state != State.GAME_OVER
            panelPaint.style = Paint.Style.FILL
            panelPaint.color = if (active) playerColors[i] else Color.argb(235, 255, 255, 255)
            canvas.drawRoundRect(rect, dp(12f), dp(12f), panelPaint)
            panelPaint.style = Paint.Style.STROKE
            panelPaint.strokeWidth = dp(2f)
            panelPaint.color = playerColors[i]
            canvas.drawRoundRect(rect, dp(12f), dp(12f), panelPaint)

            textPaint.color = if (active) Color.WHITE else Color.rgb(33, 33, 33)
            textPaint.typeface = Typeface.DEFAULT_BOLD
            textPaint.textSize = dp(14f)
            canvas.drawText(p.name, rect.centerX(), rect.top + dp(20f), textPaint)
            textPaint.typeface = Typeface.DEFAULT
            textPaint.textSize = dp(22f)
            canvas.drawText("${p.hand}", rect.centerX(), rect.top + dp(46f), textPaint)

            // A little row of stones for the hand.
            val shown = min(p.hand, 12)
            val spacing = min(small * 2.2f, (rect.width() - dp(12f)) / 12f)
            val startX = rect.centerX() - (shown - 1) * spacing / 2
            for (k in 0 until shown) {
                val sx = startX + k * spacing
                val sy = rect.bottom - dp(12f)
                canvas.save()
                canvas.translate(sx, sy)
                val s = small / magnetShaderRadius
                canvas.scale(s, s)
                canvas.drawCircle(0f, 0f, magnetShaderRadius, magnetPaint)
                canvas.restore()
            }
        }
    }

    private fun drawFooter(canvas: Canvas) {
        textPaint.color = Color.WHITE
        textPaint.typeface = Typeface.DEFAULT
        textPaint.textSize = dp(16f)
        val y = height - insetBottom - dp(18f)
        canvas.drawText(fit(message, width - dp(24f)), width / 2f, y, textPaint)
        if (notice.isNotEmpty()) {
            textPaint.color = Color.rgb(255, 224, 130)
            textPaint.typeface = Typeface.DEFAULT_BOLD
            canvas.drawText(fit(notice, width - dp(24f)), width / 2f, y - dp(26f), textPaint)
        }
    }

    private fun fit(text: String, maxWidth: Float): String {
        if (textPaint.measureText(text) <= maxWidth) return text
        var end = text.length
        while (end > 0 && textPaint.measureText(text, 0, end) + textPaint.measureText("…") > maxWidth) end--
        return text.substring(0, end) + "…"
    }

    private fun drawGameOver(canvas: Canvas) {
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), overlayPaint)
        val winnerIndex = game.players.indexOf(game.winner)
        textPaint.color = Color.WHITE
        textPaint.typeface = Typeface.DEFAULT_BOLD
        textPaint.textSize = dp(34f)
        canvas.drawText(message, width / 2f, height / 2f - dp(60f), textPaint)

        val bw = min(width * 0.7f, dp(280f))
        val bh = dp(52f)
        playAgainRect.set(width / 2f - bw / 2, height / 2f, width / 2f + bw / 2, height / 2f + bh)
        menuRect.set(playAgainRect.left, playAgainRect.bottom + dp(16f), playAgainRect.right, playAgainRect.bottom + dp(16f) + bh)
        buttonPaint.color = if (winnerIndex >= 0) playerColors[winnerIndex] else Color.DKGRAY
        canvas.drawRoundRect(playAgainRect, bh / 2, bh / 2, buttonPaint)
        buttonPaint.color = Color.rgb(97, 97, 97)
        canvas.drawRoundRect(menuRect, bh / 2, bh / 2, buttonPaint)
        textPaint.textSize = dp(18f)
        canvas.drawText("Play again", playAgainRect.centerX(), playAgainRect.centerY() + dp(6f), textPaint)
        canvas.drawText("Main menu", menuRect.centerX(), menuRect.centerY() + dp(6f), textPaint)
    }
}
