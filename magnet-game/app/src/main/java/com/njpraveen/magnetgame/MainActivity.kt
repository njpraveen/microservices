package com.njpraveen.magnetgame

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {

    private var inGame = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showMenu()
    }

    private fun dp(v: Float) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, resources.displayMetrics).toInt()

    private fun showMenu() {
        inGame = false
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            fitsSystemWindows = true
            setBackgroundColor(Color.rgb(245, 243, 238))
            setPadding(dp(32f), dp(32f), dp(32f), dp(32f))
        }
        root.addView(TextView(this).apply {
            text = getString(R.string.app_name)
            textSize = 40f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.rgb(33, 33, 33))
            gravity = Gravity.CENTER
        })
        root.addView(TextView(this).apply {
            text = getString(R.string.tagline)
            textSize = 16f
            setTextColor(Color.rgb(97, 97, 97))
            gravity = Gravity.CENTER
            setPadding(0, dp(8f), 0, dp(32f))
        })

        root.addView(menuButton("1 Player  vs  Computer", Color.rgb(229, 57, 53)) {
            startGame(listOf("You", "Computer"), listOf(false, true))
        })
        for (n in 2..4) {
            root.addView(menuButton("$n Players  (pass & play)", Color.rgb(30, 136, 229)) {
                startGame((1..n).map { "Player $it" }, List(n) { false })
            })
        }
        root.addView(menuButton("How to play", Color.rgb(97, 97, 97)) { showRules() })
        setContentView(root)
    }

    private fun menuButton(label: String, color: Int, onClick: () -> Unit) = Button(this).apply {
        text = label
        isAllCaps = false
        textSize = 18f
        setTextColor(Color.WHITE)
        background = GradientDrawable().apply {
            cornerRadius = dp(28f).toFloat()
            setColor(color)
        }
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(56f)).apply {
            topMargin = dp(12f)
        }
        setOnClickListener { onClick() }
    }

    private fun showRules() {
        AlertDialog.Builder(this)
            .setTitle(R.string.how_to_play)
            .setMessage(R.string.rules)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun startGame(names: List<String>, computer: List<Boolean>) {
        inGame = true
        val view = GameView(this, names, computer, onExit = { showMenu() })
        view.fitsSystemWindows = false
        setContentView(view)
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (inGame) {
            showMenu()
        } else {
            @Suppress("DEPRECATION")
            super.onBackPressed()
        }
    }
}
