package com.vaultspace.app

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.text.InputFilter
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.Switch
import android.widget.TextView
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// A tiny layout DSL over plain Android views, so each screen reads top-to-bottom like the design.

const val MATCH = ViewGroup.LayoutParams.MATCH_PARENT
const val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT

/** Colours from the Phase 1 design: black and white with soft greys. */
object C {
    const val BG = 0xFFF4F4F4.toInt()
    const val CARD = 0xFFFFFFFF.toInt()
    const val INK = 0xFF111111.toInt()
    const val MUTED = 0xFF6B6B6B.toInt()
    const val LINE = 0xFFE2E2E2.toInt()
    const val CHIP = 0xFFEBEBEB.toInt()
    const val DANGER = 0xFFC62828.toInt()
    const val GOOD = 0xFF2E7D32.toInt()
    const val WARN = 0xFFB45309.toInt()
}

fun View.dp(v: Int): Int = (v * resources.displayMetrics.density + 0.5f).toInt()
fun View.dpf(v: Float): Float = v * resources.displayMetrics.density

fun shape(color: Int, radius: Float, stroke: Int = 0, strokeWidth: Int = 0, oval: Boolean = false) = GradientDrawable().apply {
    if (oval) shape = GradientDrawable.OVAL else cornerRadius = radius
    setColor(color)
    if (strokeWidth > 0) setStroke(strokeWidth, stroke)
}

fun View.pressable(bg: GradientDrawable, ripple: Int = 0x22000000) {
    background = RippleDrawable(ColorStateList.valueOf(ripple), bg, null)
    isClickable = true
    isFocusable = true
}

/** Adds a child with layout params that suit the parent, then runs its setup block. */
fun <T : View> ViewGroup.add(v: T, w: Int = MATCH, h: Int = WRAP, weight: Float = 0f, block: T.() -> Unit = {}): T {
    v.layoutParams = if (this is LinearLayout) LinearLayout.LayoutParams(w, h, weight) else FrameLayout.LayoutParams(w, h)
    v.block()
    addView(v)
    return v
}

/** Even spacing between the children of a LinearLayout. */
fun LinearLayout.gap(px: Int) {
    if (px <= 0) return
    dividerDrawable = GradientDrawable().apply { setSize(px, px) }
    showDividers = LinearLayout.SHOW_DIVIDER_MIDDLE
}

fun ViewGroup.column(gap: Int = 0, pad: Int = 0, w: Int = MATCH, weight: Float = 0f, block: LinearLayout.() -> Unit = {}) =
    add(LinearLayout(context), w, WRAP, weight) {
        orientation = LinearLayout.VERTICAL
        gap(dp(gap))
        setPadding(dp(pad), dp(pad), dp(pad), dp(pad))
        block()
    }

fun ViewGroup.row(gap: Int = 0, w: Int = MATCH, block: LinearLayout.() -> Unit = {}) =
    add(LinearLayout(context), w) {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        gap(dp(gap))
        block()
    }

fun ViewGroup.text(s: CharSequence, size: Float = 15f, color: Int = C.INK, bold: Boolean = false, w: Int = MATCH, weight: Float = 0f, block: TextView.() -> Unit = {}) =
    add(TextView(context), w, WRAP, weight) {
        text = s
        textSize = size
        setTextColor(color)
        if (bold) setTypeface(Typeface.DEFAULT, Typeface.BOLD)
        block()
    }

fun ViewGroup.heading(s: String) = text(s, 26f, bold = true) { isFocusable = true }
fun ViewGroup.caption(s: CharSequence, color: Int = C.MUTED) = text(s, 13f, color)
fun ViewGroup.space(h: Int) = add(View(context), MATCH, dp(h))
fun ViewGroup.flex() = add(View(context), 0, 1, 1f)

enum class Btn { PRIMARY, SECONDARY, DANGER, OUTLINE }

fun ViewGroup.button(label: String, style: Btn = Btn.PRIMARY, w: Int = MATCH, weight: Float = 0f, onClick: (Button) -> Unit): Button =
    add(Button(context), w, dp(52), weight) {
        text = label
        isAllCaps = false
        textSize = 16f
        setTypeface(Typeface.DEFAULT, Typeface.BOLD)
        stateListAnimator = null
        minHeight = 0
        minimumHeight = 0
        setPadding(dp(16), 0, dp(16), 0)
        val (bg, fg, line) = when (style) {
            Btn.PRIMARY -> Triple(C.INK, Color.WHITE, 0)
            Btn.SECONDARY -> Triple(C.CHIP, C.INK, 0)
            Btn.DANGER -> Triple(C.CARD, C.DANGER, C.DANGER)
            Btn.OUTLINE -> Triple(C.CARD, C.INK, C.LINE)
        }
        setTextColor(fg)
        pressable(shape(bg, dpf(14f), line, if (line != 0) dp(1) else 0), if (style == Btn.PRIMARY) 0x33FFFFFF else 0x22000000)
        setOnClickListener { onClick(this) }
    }

/** Small pill-shaped action, like "Revoke" or "Restore". */
fun ViewGroup.pillButton(label: String, dark: Boolean = false, color: Int = C.INK, onClick: () -> Unit) =
    add(TextView(context), WRAP, dp(34)) {
        text = label
        textSize = 13f
        gravity = Gravity.CENTER
        setTypeface(Typeface.DEFAULT, Typeface.BOLD)
        setPadding(dp(14), 0, dp(14), 0)
        setTextColor(if (dark) Color.WHITE else color)
        pressable(shape(if (dark) C.INK else C.CHIP, dpf(17f)))
        setOnClickListener { onClick() }
    }

fun ViewGroup.link(label: String, onClick: () -> Unit) =
    text(label, 14f, C.INK, bold = true, w = WRAP) {
        setPadding(dp(4), dp(12), dp(4), dp(12))
        paintFlags = paintFlags or Paint.UNDERLINE_TEXT_FLAG
        setOnClickListener { onClick() }
    }

enum class Field { TEXT, NAME, EMAIL, PASSWORD, NEW_PASSWORD, CODE, SECRET, NUMBER }

fun ViewGroup.input(hint: String, kind: Field = Field.TEXT): EditText =
    add(EditText(context), MATCH, dp(52)) {
        this.hint = hint
        textSize = 15f
        setTextColor(C.INK)
        setHintTextColor(0xFF9A9A9A.toInt())
        setSingleLine()
        background = shape(C.CARD, dpf(14f), C.LINE, dp(1))
        setPadding(dp(16), 0, dp(16), 0)
        val t = InputType.TYPE_CLASS_TEXT
        inputType = when (kind) {
            Field.TEXT -> t or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            Field.NAME -> t or InputType.TYPE_TEXT_FLAG_CAP_WORDS or InputType.TYPE_TEXT_VARIATION_PERSON_NAME
            Field.EMAIL -> t or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
            Field.PASSWORD, Field.NEW_PASSWORD -> t or InputType.TYPE_TEXT_VARIATION_PASSWORD
            Field.SECRET -> t or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            Field.CODE, Field.NUMBER -> InputType.TYPE_CLASS_NUMBER
        }
        // Secrets: no autocorrect, no keyboard learning (incognito keyboard), no autofill of recovery keys.
        typeface = Typeface.DEFAULT   // password fields would otherwise switch to a monospace font
        if (kind in listOf(Field.PASSWORD, Field.NEW_PASSWORD, Field.CODE, Field.SECRET)) {
            imeOptions = imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        }
        when (kind) {
            Field.EMAIL -> setAutofillHints(View.AUTOFILL_HINT_EMAIL_ADDRESS)
            Field.PASSWORD -> setAutofillHints(View.AUTOFILL_HINT_PASSWORD)
            Field.NEW_PASSWORD -> setAutofillHints("newPassword")
            Field.CODE -> { setAutofillHints("smsOTPCode"); filters = arrayOf(InputFilter.LengthFilter(6)) }
            Field.SECRET -> importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            else -> {}
        }
    }

fun ViewGroup.field(label: String, hint: String, kind: Field = Field.TEXT): EditText {
    lateinit var e: EditText
    column(6) {
        caption(label)
        e = input(hint, kind)
    }
    return e
}

val EditText.value: String get() = text.toString().trim()

/** Password as a char array, so it can be wiped from memory after use (a String cannot). */
fun EditText.chars(): CharArray = CharArray(text.length).also { text.getChars(0, text.length, it, 0) }

/** Single-choice chips, e.g. "24 hours / 7 days / 30 days / Custom". */
fun ViewGroup.chips(options: List<String>, selected: Int, onPick: (Int) -> Unit): List<TextView> {
    val scroll = add(HorizontalScrollView(context)) { isHorizontalScrollBarEnabled = false }
    val bar = scroll.add(LinearLayout(context), WRAP, WRAP) {
        orientation = LinearLayout.HORIZONTAL
        gap(dp(8))
    }
    val views = options.map { o ->
        bar.add(TextView(context), WRAP, dp(40)) {
            text = o
            textSize = 14f
            gravity = Gravity.CENTER
            setPadding(dp(16), 0, dp(16), 0)
        }
    }
    fun paint(sel: Int) = views.forEachIndexed { i, v ->
        val on = i == sel
        v.setTextColor(if (on) Color.WHITE else C.INK)
        v.setTypeface(Typeface.DEFAULT, if (on) Typeface.BOLD else Typeface.NORMAL)
        v.background = shape(if (on) C.INK else C.CHIP, v.dpf(20f))
        v.isSelected = on
    }
    views.forEachIndexed { i, v -> v.setOnClickListener { paint(i); onPick(i) } }
    paint(selected)
    return views
}

fun ViewGroup.card(gap: Int = 8, pad: Int = 16, dark: Boolean = false, block: LinearLayout.() -> Unit) =
    column(gap, pad) {
        background = shape(if (dark) C.INK else C.CARD, dpf(18f), C.LINE, if (dark) 0 else dp(1))
        block()
    }

fun ViewGroup.pill(label: String, dark: Boolean = true, color: Int = C.INK) =
    add(TextView(context), WRAP, WRAP) {
        text = label
        textSize = 12f
        setTypeface(Typeface.DEFAULT, Typeface.BOLD)
        setPadding(dp(10), dp(4), dp(10), dp(4))
        setTextColor(if (dark) Color.WHITE else color)
        background = shape(if (dark) color else C.CHIP, dpf(12f))
    }

fun ViewGroup.icon(res: Int, size: Int = 24, tint: Int = C.INK) =
    add(ImageView(context), dp(size), dp(size)) {
        setImageResource(res)
        imageTintList = ColorStateList.valueOf(tint)
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }

fun ViewGroup.iconBox(res: Int, box: Int = C.CHIP, tint: Int = C.INK, size: Int = 44) =
    add(FrameLayout(context), dp(size), dp(size)) {
        background = shape(box, dpf(12f))
        icon(res, size / 2, tint).apply { (layoutParams as FrameLayout.LayoutParams).gravity = Gravity.CENTER }
    }

/** Round icon button (back, bell...). Always has a text description for screen readers. */
fun ViewGroup.roundButton(res: Int, description: String, dark: Boolean = true, badge: Int = 0, onClick: () -> Unit) =
    add(FrameLayout(context), dp(44), dp(44)) {
        contentDescription = if (badge > 0) "$description, $badge new" else description
        pressable(shape(if (dark) C.INK else C.CHIP, 0f, oval = true))
        icon(res, 22, if (dark) Color.WHITE else C.INK).apply { (layoutParams as FrameLayout.LayoutParams).gravity = Gravity.CENTER }
        if (badge > 0) add(TextView(context), dp(18), dp(18)) {
            (layoutParams as FrameLayout.LayoutParams).gravity = Gravity.TOP or Gravity.END
            text = if (badge > 9) "9+" else "$badge"
            textSize = 10f
            gravity = Gravity.CENTER
            setTextColor(Color.WHITE)
            background = shape(C.DANGER, 0f, oval = true)
        }
        setOnClickListener { onClick() }
    }

fun ViewGroup.avatar(name: String, size: Int = 40, dark: Boolean = true) =
    add(TextView(context), dp(size), dp(size)) {
        text = name.trim().firstOrNull()?.uppercase() ?: "?"
        gravity = Gravity.CENTER
        textSize = size / 2.6f
        setTypeface(Typeface.DEFAULT, Typeface.BOLD)
        setTextColor(if (dark) Color.WHITE else C.INK)
        background = shape(if (dark) C.INK else C.CHIP, 0f, oval = true)
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    }

fun ViewGroup.header(title: String, sub: String? = null, onBack: (() -> Unit)? = null, actions: LinearLayout.() -> Unit = {}) =
    row(12) {
        if (onBack != null) roundButton(R.drawable.ic_back, "Back") { onBack() }
        column(0, w = 0, weight = 1f) {
            heading(title)
            if (sub != null) caption(sub)
        }
        actions()
    }

fun ViewGroup.kv(k: String, v: String, color: Int = C.INK) =
    row(8) {
        text(k, 14f, C.MUTED, w = 0, weight = 1f)
        text(v, 14f, color, bold = true, w = WRAP)
    }

fun ViewGroup.navRow(label: String, sub: String? = null, color: Int = C.INK, onClick: () -> Unit) =
    add(LinearLayout(context)) {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(14), dp(16), dp(14))
        pressable(shape(C.CARD, dpf(14f), C.LINE, dp(1)))
        text(label, 15f, color, bold = true)
        if (sub != null) caption(sub)
        setOnClickListener { onClick() }
    }

fun ViewGroup.toggle(label: String, sub: String?, on: Boolean, onChange: (android.widget.CompoundButton, Boolean) -> Unit) =
    row(12) {
        column(2, w = 0, weight = 1f) {
            text(label, 15f, bold = true)
            if (sub != null) caption(sub)
        }
        add(Switch(context), WRAP, WRAP) {
            isChecked = on
            contentDescription = label
            setOnCheckedChangeListener { s, b -> onChange(s, b) }
        }
    }

/** Notice box, e.g. "Revoking stops future access...". */
fun ViewGroup.notice(title: String, body: String, dark: Boolean = true) =
    card(4, 16, dark) {
        text(title, 15f, if (dark) Color.WHITE else C.INK, bold = true)
        text(body, 13f, if (dark) 0xFFCFCFCF.toInt() else C.MUTED)
    }

/** Diagonal, repeated "who and when" text drawn over viewed files, so a photo of the screen shows who leaked it. */
class Watermark(ctx: Context, private val label: String) : View(ctx) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0x40808080
        textSize = dpf(13f)
        typeface = Typeface.DEFAULT_BOLD
    }

    init { importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO }

    override fun onDraw(c: Canvas) {
        c.save()
        c.rotate(-28f, width / 2f, height / 2f)
        val stepX = paint.measureText(label) + dpf(48f)
        val stepY = dpf(84f)
        var y = -height.toFloat()
        var line = 0
        while (y < height * 2f) {
            var x = -width.toFloat() + (line % 2) * stepX / 2
            while (x < width * 2f) {
                c.drawText(label, x, y, paint)
                x += stepX
            }
            y += stepY
            line++
        }
        c.restore()
    }
}

object Fmt {
    private fun now() = System.currentTimeMillis() / 1000

    fun size(b: Long): String = when {
        b < 1024 -> "$b B"
        b < 1024 * 1024 -> "%.1f KB".format(b / 1024.0)
        else -> "%.1f MB".format(b / 1048576.0)
    }

    fun ago(t: Long): String {
        val d = now() - t
        return when {
            d < 60 -> "just now"
            d < 3600 -> "${d / 60} min ago"
            d < 86400 -> "${d / 3600} h ago"
            d < 172800 -> "yesterday"
            else -> SimpleDateFormat("d MMM", Locale.getDefault()).format(Date(t * 1000))
        }
    }

    fun left(t: Long): String {
        val d = t - now()
        return when {
            d <= 0 -> "expired"
            d < 3600 -> "${maxOf(1, d / 60)} min"
            d < 172800 -> "${d / 3600}h ${(d % 3600) / 60}m"
            else -> "${d / 86400} days"
        }
    }

    fun date(t: Long): String = SimpleDateFormat("EEE d MMM, h:mm a", Locale.getDefault()).format(Date(t * 1000))
    fun time(t: Long): String = SimpleDateFormat("d MMM, h:mm a", Locale.getDefault()).format(Date(t * 1000))

    fun plural(n: Int, word: String) = "$n $word${if (n == 1) "" else "s"}"

    fun perm(p: String) = when (p) {
        "view" -> "View only"
        "download" -> "View & download"
        "edit" -> "Can update"
        else -> p
    }

    fun status(s: String) = when (s) {
        "active" -> "Active"
        "expired" -> "Expired"
        "revoked" -> "Access removed"
        "used_up" -> "All opens used"
        "locked" -> "Locked"
        else -> s
    }
}
