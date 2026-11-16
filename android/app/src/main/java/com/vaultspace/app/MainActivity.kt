package com.vaultspace.app

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.view.WindowManager
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import java.util.concurrent.Executors

/** One screen of the app. Screens build their views with the DSL in Ui.kt. */
abstract class Screen(val app: MainActivity) {
    open val tab = -1            // which bottom-bar tab is highlighted; -1 hides the bar
    open val scrolls = true
    var alive = true             // false once the screen is closed: late results are ignored

    abstract fun LinearLayout.build()
    open fun onShow() {}         // every time the screen becomes visible (refresh data here)
    open fun onClose() {}        // when removed: wipe decrypted data here

    fun rerender() = app.render(this, keepScroll = true)

    fun <T> task(busy: String? = "Please wait…", onError: ((Throwable) -> Boolean)? = null, work: ((String) -> Unit) -> T, done: (T) -> Unit) =
        app.task(this, busy, onError, work, done)
}

class MainActivity : Activity() {
    private val pool = Executors.newCachedThreadPool()
    private val handler = Handler(Looper.getMainLooper())
    private val stack = ArrayList<Screen>()
    private lateinit var content: FrameLayout
    private lateinit var nav: LinearLayout
    private lateinit var busyBox: FrameLayout
    private lateinit var busyText: TextView
    private lateinit var snackView: TextView
    private var busyCount = 0
    private var pendingShare: String? = null

    // ---- lifecycle -------------------------------------------------------------------
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        Prefs.init(this)
        // Blocks screenshots, screen recording and the preview in the recent-apps list.
        if (BuildConfig.SECURE_SCREEN) window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(buildShell())
        styleSystemBars()
        handleLink(intent)
        reset(LoginScreen(this))
        handler.postDelayed(idleCheck, 15_000)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleLink(intent)
    }

    // Back navigation. Android 13+ uses OnBackInvokedCallback: we only register it while there is a
    // screen to go back to, so the keyboard closes first and, on the first screen, the system's own
    // "back to home" gesture works. Older versions still call onBackPressed.
    @Deprecated("Deprecated in Java")
    override fun onBackPressed() = back()

    private var backCallback: Any? = null

    private fun syncBack() {
        if (Build.VERSION.SDK_INT < 33) return
        val cb = (backCallback ?: android.window.OnBackInvokedCallback { back() }.also { backCallback = it }) as android.window.OnBackInvokedCallback
        onBackInvokedDispatcher.unregisterOnBackInvokedCallback(cb)
        if (stack.size > 1) onBackInvokedDispatcher.registerOnBackInvokedCallback(android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT, cb)
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    // ---- auto-lock -----------------------------------------------------------------------
    // The vault locks (keys wiped from memory) after 5 minutes without a touch, or when the app
    // has been in the background for more than a minute.
    private var lastTouch = SystemClock.elapsedRealtime()
    private var hiddenAt = 0L
    private var externalOpen = false   // our own file picker / save dialog is in front

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        lastTouch = SystemClock.elapsedRealtime()
        return super.dispatchTouchEvent(ev)
    }

    private val idleCheck: Runnable = object : Runnable {
        override fun run() {
            if (Session.isOpen && !externalOpen && SystemClock.elapsedRealtime() - lastTouch > 5 * 60_000) {
                lock("VaultSpace locked after 5 minutes without activity.")
            }
            handler.postDelayed(this, 15_000)
        }
    }

    override fun onStop() {
        super.onStop()
        hiddenAt = SystemClock.elapsedRealtime()
    }

    override fun onStart() {
        super.onStart()
        if (Session.isOpen && !externalOpen && hiddenAt > 0 && SystemClock.elapsedRealtime() - hiddenAt > 60_000) {
            lock("VaultSpace locked while it was in the background.")
        }
        hiddenAt = 0
    }

    // ---- layout shell --------------------------------------------------------------------
    private fun dp(v: Int) = (v * resources.displayMetrics.density + 0.5f).toInt()

    private fun buildShell(): View {
        val root = FrameLayout(this)
        root.setBackgroundColor(C.BG)
        root.filterTouchesWhenObscured = true   // ignore taps while another app draws over us (tapjacking)
        val main = root.add(LinearLayout(this), MATCH, MATCH) { orientation = LinearLayout.VERTICAL }
        content = main.add(FrameLayout(this), MATCH, 0, 1f)
        nav = main.add(LinearLayout(this), MATCH, dp(72)) {
            orientation = LinearLayout.HORIZONTAL
            background = shape(C.INK, dpf(26f))
            (layoutParams as LinearLayout.LayoutParams).setMargins(dp(10), 0, dp(10), dp(8))
        }
        listOf(
            Triple("Home", R.drawable.ic_home) { HomeScreen(this) },
            Triple("Shared By Me", R.drawable.ic_shared_out) { SharedByMeScreen(this) },
            Triple("Shared With Me", R.drawable.ic_shared_in) { SharedWithMeScreen(this) },
            Triple("Profile", R.drawable.ic_person) { ProfileScreen(this) as Screen },
        ).forEachIndexed { i, (label, res, make) ->
            nav.add(LinearLayout(this), 0, MATCH, 1f) {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                contentDescription = label
                setOnClickListener { if (stack.lastOrNull()?.tab != i) reset(make()) }
                icon(res, 24, Color.WHITE)
                text(label, 11f, Color.WHITE, w = WRAP) { gravity = Gravity.CENTER; setPadding(0, dp(4), 0, 0) }
            }
        }
        snackView = root.add(TextView(this), MATCH, WRAP) {
            (layoutParams as FrameLayout.LayoutParams).apply { gravity = Gravity.BOTTOM; setMargins(dp(16), 0, dp(16), dp(96)) }
            setPadding(dp(16), dp(14), dp(16), dp(14))
            setTextColor(Color.WHITE)
            textSize = 14f
            background = shape(0xEE222222.toInt(), dpf(14f))
            visibility = View.GONE
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        busyBox = root.add(FrameLayout(this), MATCH, MATCH) {
            setBackgroundColor(0x99F4F4F4.toInt())
            isClickable = true      // swallows taps, so nothing can be pressed twice while working
            visibility = View.GONE
            val box = add(LinearLayout(this@MainActivity), dp(260), WRAP) {
                (layoutParams as FrameLayout.LayoutParams).gravity = Gravity.CENTER
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER_HORIZONTAL
                setPadding(dp(24), dp(24), dp(24), dp(24))
                background = shape(C.CARD, dpf(20f), C.LINE, dp(1))
                elevation = dpf(6f)
            }
            box.add(ProgressBar(this@MainActivity), dp(40), dp(40))
            busyText = box.text("", 15f, w = MATCH) {
                gravity = Gravity.CENTER
                setPadding(0, dp(14), 0, 0)
                accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
            }
        }
        // Android 15 draws apps edge-to-edge: keep our content clear of the status bar, nav bar and keyboard.
        if (Build.VERSION.SDK_INT >= 35) root.setOnApplyWindowInsetsListener { v, insets ->
            val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        return root
    }

    private fun styleSystemBars() {
        if (Build.VERSION.SDK_INT < 35) {
            @Suppress("DEPRECATION")
            window.statusBarColor = C.BG
            @Suppress("DEPRECATION")
            window.navigationBarColor = C.BG
        }
        if (Build.VERSION.SDK_INT >= 30) {
            val light = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
            window.insetsController?.setSystemBarsAppearance(light, light)
        } else {
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
        }
    }

    private fun paintNav(tab: Int) {
        nav.visibility = if (tab >= 0) View.VISIBLE else View.GONE
        for (i in 0 until nav.childCount) {
            val item = nav.getChildAt(i) as LinearLayout
            item.alpha = if (i == tab) 1f else 0.55f
            item.isSelected = i == tab
        }
    }

    // ---- navigation ----------------------------------------------------------------------
    fun render(s: Screen, keepScroll: Boolean = false) {
        if (stack.lastOrNull() !== s) return
        val oldY = (content.getChildAt(0) as? ScrollView)?.scrollY ?: 0
        content.removeAllViews()
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gap(dp(14))
            setPadding(dp(20), dp(16), dp(20), dp(28))
        }
        with(s) { col.build() }
        if (s.scrolls) {
            val sv = ScrollView(this).apply { isFillViewport = true; addView(col) }
            content.addView(sv)
            if (keepScroll) sv.post { sv.scrollTo(0, oldY) }
        } else {
            content.addView(col, FrameLayout.LayoutParams(MATCH, MATCH))
        }
        paintNav(s.tab)
    }

    private fun show(s: Screen) {
        render(s)
        syncBack()
        s.onShow()
    }

    fun push(s: Screen) {
        stack.add(s)
        show(s)
    }

    /** Replaces the top `count` screens (multi-step flows), so Back skips the finished steps. */
    fun replace(s: Screen, count: Int = 1) {
        repeat(minOf(count, stack.size)) { close(stack.removeAt(stack.lastIndex)) }
        push(s)
    }

    fun reset(s: Screen) {
        stack.forEach { close(it) }
        stack.clear()
        push(s)
    }

    fun back() {
        if (stack.size <= 1) {
            moveTaskToBack(true)
            return
        }
        close(stack.removeAt(stack.lastIndex))
        show(stack.last())
    }

    private fun close(s: Screen) {
        s.alive = false
        s.onClose()
    }

    // ---- background work -------------------------------------------------------------------
    // Network and crypto never run on the UI thread. Results are delivered only if the screen is still open.
    fun <T> task(owner: Screen?, busy: String?, onError: ((Throwable) -> Boolean)?, work: ((String) -> Unit) -> T, done: (T) -> Unit) {
        if (busy != null) showBusy(busy)
        pool.execute {
            val result = try {
                Result.success(work { msg -> runOnUiThread { if (busy != null) busyText.text = msg } })
            } catch (e: Throwable) {
                Result.failure<T>(e)
            }
            runOnUiThread {
                if (busy != null) hideBusy()
                if (owner != null && !owner.alive) return@runOnUiThread
                result.fold(done) { e -> if (onError?.invoke(e) != true) handleError(e) }
            }
        }
    }

    private fun showBusy(msg: String) {
        busyCount++
        busyText.text = msg
        busyBox.visibility = View.VISIBLE
    }

    private fun hideBusy() {
        busyCount = maxOf(0, busyCount - 1)
        if (busyCount == 0) busyBox.visibility = View.GONE
    }

    fun handleError(e: Throwable) {
        if (e is ApiError && e.status == 401 && Session.isOpen) return lock("Your session ended. Please unlock again.")
        snack(friendly(e))
    }

    fun friendly(e: Throwable): String = when (e) {
        is ApiError, is TamperedException -> e.message ?: "Something went wrong."
        // Only a certificate problem gets the certificate message; a connection dropped mid-TLS is a network error.
        is java.io.IOException -> if (e is javax.net.ssl.SSLException && generateSequence<Throwable>(e) { it.cause }
                .any { it is java.security.cert.CertificateException || it is java.security.cert.CertPathValidatorException })
            "Secure connection failed: the server's certificate is not the one VaultSpace trusts."
        else "Can't reach VaultSpace. The server is on the IIIT-Delhi campus network: connect to campus Wi-Fi (mobile data won't work) and try again."
        is IllegalArgumentException -> e.message ?: "That doesn't look right."
        is OutOfMemoryError -> "This file is too large to open on this phone."
        else -> "Something went wrong. Please try again."
    }

    fun snack(msg: String) {
        snackView.text = msg
        snackView.visibility = View.VISIBLE
        snackView.bringToFront()
        handler.removeCallbacks(hideSnack)
        handler.postDelayed(hideSnack, 4500)
    }

    private val hideSnack = Runnable { snackView.visibility = View.GONE }

    // ---- dialogs (also FLAG_SECURE: dialogs are separate windows and would otherwise be capturable) ----
    private fun secure(b: AlertDialog.Builder): AlertDialog = b.create().apply {
        if (BuildConfig.SECURE_SCREEN) window?.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        show()
    }

    fun confirm(title: String, message: String, action: String, onYes: () -> Unit) {
        secure(AlertDialog.Builder(this).setTitle(title).setMessage(message)
            .setPositiveButton(action) { _, _ -> onYes() }.setNegativeButton("Cancel", null))
    }

    fun info(title: String, message: String) {
        secure(AlertDialog.Builder(this).setTitle(title).setMessage(message).setPositiveButton("OK", null))
    }

    fun ask(title: String, message: String?, hint: String, kind: Field, action: String, onValue: (EditText) -> Unit) {
        val box = FrameLayout(this).apply { setPadding(dp(20), dp(8), dp(20), 0) }
        val input = box.input(hint, kind)
        secure(AlertDialog.Builder(this).setTitle(title).setMessage(message).setView(box)
            .setPositiveButton(action) { _, _ -> onValue(input) }.setNegativeButton("Cancel", null))
        input.requestFocus()
    }

    /** Re-authentication for sensitive actions: derives the password keys again (the server checks authKey). */
    fun withPassword(reason: String, then: (Crypto.KeyPairOfSecrets) -> Unit) {
        ask("Confirm it's you", reason, "Your password", Field.PASSWORD, "Continue") { input ->
            val pw = input.chars()
            input.setText("")
            task(stack.lastOrNull(), "Checking…", null, {
                val pre = Api.post("/auth/prelogin", JSONObject().put("email", Session.email))
                Crypto.passwordKeys(pw, Crypto.unb64(pre.getString("salt")), pre.getInt("iters")).also { pw.fill(' ') }
            }, then)
        }
    }

    // ---- system file picker / save dialog (Storage Access Framework: no storage permission needed) ----
    private var onPicked: ((Uri) -> Unit)? = null

    fun pickFile(cb: (Uri) -> Unit) {
        onPicked = cb
        externalOpen = true
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), 1)
    }

    fun saveFile(name: String, cb: (Uri) -> Unit) {
        onPicked = cb
        externalOpen = true
        startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
            .setType("application/octet-stream").putExtra(Intent.EXTRA_TITLE, name), 2)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(request: Int, result: Int, data: Intent?) {
        super.onActivityResult(request, result, data)
        externalOpen = false
        lastTouch = SystemClock.elapsedRealtime()
        val cb = onPicked
        onPicked = null
        val uri = data?.data
        if (result == RESULT_OK && uri != null && Session.isOpen) cb?.invoke(uri)
    }

    /** Copies a secret, marked sensitive so Android hides it in clipboard previews, and clears it after 60 s. */
    fun copySecret(label: String, text: String) {
        val cm = getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText(label, text)
        if (Build.VERSION.SDK_INT >= 33) clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        cm.setPrimaryClip(clip)
        snack("Copied. It will be cleared from the clipboard in 60 seconds.")
        handler.postDelayed({ runCatching { if (cm.primaryClip?.getItemAt(0)?.text == text) cm.clearPrimaryClip() } }, 60_000)
    }

    // ---- sessions ---------------------------------------------------------------------------
    /** After any successful login: start the session and go to the vault (or to `first`, e.g. a recovery key). */
    fun signedIn(payload: JSONObject, vault: ByteArray, authKey: ByteArray?, first: Screen? = null) {
        Session.start(payload, vault)
        Prefs.email = Session.email
        val share = pendingShare
        pendingShare = null
        reset(first ?: if (share != null) SharedWithMeScreen(this, share) else HomeScreen(this))
        if (first == null && authKey != null) offerBiometric(authKey)
    }

    fun offerBiometric(authKey: ByteArray) {
        if (DeviceUnlock.available(this) && !DeviceUnlock.isSetUpFor(Session.email)) {
            confirm("Unlock with your fingerprint?",
                "Next time, open VaultSpace with your fingerprint instead of typing your password. Your password is still needed on a new phone.",
                "Turn on") { enableBiometric(authKey) }
        }
    }

    fun enableBiometric(authKey: ByteArray, after: (Boolean) -> Unit = {}) {
        task(stack.lastOrNull(), "Setting up…", null, { Api.post("/auth/devices", JSONObject().put("authKey", Crypto.b64(authKey))) }) { r ->
            authKey.fill(0)
            val deviceId = r.getString("deviceId")
            val secret = JSONObject().put("id", deviceId).put("token", r.getString("deviceToken"))
                .put("vault", Crypto.b64(Session.vault)).toString().toByteArray()
            DeviceUnlock.enroll(this, secret) { ok, err ->
                secret.fill(0)
                if (ok) {
                    Prefs.deviceId = deviceId
                    Prefs.deviceEmail = Session.email
                    snack("Fingerprint unlock is on for this phone.")
                } else {
                    pool.execute { runCatching { Api.delete("/devices/$deviceId") } }
                    err?.let { snack(it) }
                }
                after(ok)
            }
        }
    }

    fun biometricLogin() {
        DeviceUnlock.unlock(this) { secret, err ->
            if (secret == null) {
                err?.let { snack(it) }
                return@unlock
            }
            val j = JSONObject(String(secret))
            secret.fill(0)
            task(stack.lastOrNull(), "Unlocking your vault…", { e ->
                if (e is ApiError && e.status == 401) {
                    DeviceUnlock.forget()
                    snack(e.message ?: "")
                    rerenderTop()
                    true
                } else false
            }, {
                Api.post("/auth/device-login", JSONObject().put("deviceId", j.getString("id")).put("deviceToken", j.getString("token")))
            }) { r -> signedIn(r, Crypto.unb64(j.getString("vault")), null) }
        }
    }

    private fun rerenderTop() = stack.lastOrNull()?.let { render(it) }

    /** Wipes keys from memory, ends the server session, and shows the unlock screen. */
    fun lock(reason: String?) {
        val token = Session.token
        Session.end()
        if (token != null) pool.execute { runCatching { Api.logout(token) } }
        reset(LoginScreen(this, reason))
    }

    // ---- deep links: vaultspace://share/<id> ---------------------------------------------------
    private fun handleLink(i: Intent?) {
        val u = i?.data ?: return
        if (u.scheme != "vaultspace" || u.host != "share") return
        val id = u.lastPathSegment ?: return
        if (!Regex("^[A-Za-z0-9_-]{22}$").matches(id)) return
        if (Session.isOpen) push(SharedWithMeScreen(this, id)) else {
            pendingShare = id
            snack("Log in to open the file shared with you.")
        }
    }

    fun shareText(text: String) =
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text), "Send a heads-up"))
}
