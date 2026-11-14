package com.vaultspace.app

import android.graphics.Typeface
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import org.json.JSONObject

fun EditText.onChange(block: (String) -> Unit) = addTextChangedListener(object : TextWatcher {
    override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
    override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
    override fun afterTextChanged(s: Editable?) = block(s?.toString() ?: "")
})

private val EMAIL = Regex("^[^@\\s]{1,64}@[^@\\s]+\\.[a-zA-Z]{2,24}$")

fun LinearLayout.logo() = column(4) {
    gravity = Gravity.CENTER_HORIZONTAL
    icon(R.drawable.ic_lock, 44)
    text("VaultSpace", 30f, bold = true, w = WRAP)
    text("Private storage. Controlled sharing.", 13f, C.MUTED, w = WRAP)
}

/** Live strength bar and the first rule the password breaks (or "Looks good"). */
fun LinearLayout.strengthMeter(pw: EditText, email: () -> String) {
    val bars = ArrayList<View>()
    row(6) { repeat(4) { bars += add(View(context), 0, dp(6), 1f) { background = shape(C.LINE, dpf(3f)) } } }
    val hint = caption("At least 12 characters. 3 or 4 random words work well.")
    pw.onChange { t ->
        val score = if (t.isEmpty()) 0 else maxOf(1, PasswordCheck.score(t))
        val problem = if (t.isEmpty()) null else PasswordCheck.problem(t, email())
        val color = when {
            problem != null -> C.DANGER
            score >= 3 -> C.GOOD
            else -> C.WARN
        }
        bars.forEachIndexed { i, v -> v.background = shape(if (i < score) color else C.LINE, v.dpf(3f)) }
        hint.text = if (t.isEmpty()) "At least 12 characters. 3 or 4 random words work well." else problem ?: "Looks good."
        hint.setTextColor(if (problem != null) C.DANGER else C.MUTED)
    }
}

/** Login, and also the "unlock" screen after auto-lock. */
class LoginScreen(app: MainActivity, private val notice: String? = null) : Screen(app) {
    override fun LinearLayout.build() {
        space(28)
        logo()
        space(8)
        if (notice != null) notice("VaultSpace", notice, dark = false)
        val email = field("Email", "you@example.com", Field.EMAIL).apply { setText(Prefs.email) }
        val pw = field("Password", "Your password", Field.PASSWORD)
        button("Log in") { login(email.value.lowercase(), pw) }
        val fingerprintFor = Prefs.deviceEmail
        if (DeviceUnlock.isSetUp() && fingerprintFor != null) {
            button("Unlock with fingerprint", Btn.OUTLINE) { app.biometricLogin() }
            caption("Fingerprint unlock opens $fingerprintFor.")
        }
        row {
            link("Create an account") { app.push(SignupScreen(app)) }
            flex()
            link("Forgot password?") { app.push(ForgotScreen(app)) }
        }
        caption("Your files are encrypted on your phone before they are uploaded. VaultSpace's servers can't read them.")
    }

    private fun login(email: String, pwField: EditText, totp: String? = null, known: Crypto.KeyPairOfSecrets? = null) {
        if (!EMAIL.matches(email) || pwField.text.isEmpty()) return app.snack("Enter your email and password.")
        val pw = pwField.chars()
        var keys = known
        task("Unlocking your vault…", onError = { e ->
            if (e is ApiError && e.body.optBoolean("need2fa") && keys != null) {
                val k = keys!!
                app.ask("Two-factor code", e.message, "6-digit code", Field.CODE, "Continue") { c -> login(email, pwField, c.value, k) }
                true
            } else false
        }, work = {
            val k = keys ?: run {
                val pre = Api.post("/auth/prelogin", JSONObject().put("email", email))
                Crypto.passwordKeys(pw, Crypto.unb64(pre.getString("salt")), pre.getInt("iters"))
            }
            keys = k
            pw.fill(' ')
            val body = JSONObject().put("email", email).put("authKey", Crypto.b64(k.auth))
            if (totp != null) body.put("totp", totp)
            val r = Api.post("/auth/login", body)
            r to Crypto.open(k.kek, Crypto.unb64(r.getJSONObject("keys").getString("vaultByPw")), "vs-vault")
        }) { (r, vault) ->
            pwField.setText("")
            app.signedIn(r, vault, keys!!.auth)
        }
    }
}

class SignupScreen(app: MainActivity) : Screen(app) {
    private var step = 0
    private var name = ""
    private var email = ""
    private var password = CharArray(0)

    override fun LinearLayout.build() {
        header("Create account", if (step == 0) "Step 1 of 3 · Your details" else "Step 2 of 3 · Check your email",
            onBack = { if (step == 1) { step = 0; rerender() } else app.back() })
        if (step == 0) details() else verify()
    }

    private fun LinearLayout.details() {
        val n = field("Your name", "e.g. Riya Sharma", Field.NAME).apply { setText(name) }
        val e = field("Email", "you@example.com", Field.EMAIL).apply { setText(email) }
        val p = field("Password", "At least 12 characters", Field.NEW_PASSWORD)
        strengthMeter(p) { e.value }
        val c = field("Confirm password", "Type it again", Field.NEW_PASSWORD)
        notice("Your password protects your keys",
            "It never leaves this phone, so we can't reset it for you. You'll also get a recovery key in case you forget it.", dark = false)
        button("Send verification code") {
            val mail = e.value.lowercase()
            val problem = when {
                n.value.isEmpty() -> "Please enter your name."
                !EMAIL.matches(mail) -> "Please enter a valid email."
                else -> PasswordCheck.problem(p.text.toString(), mail) ?: if (p.text.toString() != c.text.toString()) "The passwords don't match." else null
            }
            if (problem != null) return@button app.snack(problem)
            name = n.value
            email = mail
            password.fill(' ')
            password = p.chars()
            p.setText("")
            c.setText("")
            task("Sending code…", work = { Api.post("/auth/signup/start", JSONObject().put("email", email)) }) {
                step = 1
                rerender()
            }
        }
    }

    private fun LinearLayout.verify() {
        text("We sent a 6-digit code to $email. It expires in 10 minutes.")
        val code = field("Verification code", "123456", Field.CODE)
        button("Create my account") { create(code.value) }
        link("Send a new code") {
            task("Sending code…", work = { Api.post("/auth/signup/start", JSONObject().put("email", email)) }) { app.snack("A new code is on its way.") }
        }
    }

    // Every key is created here, on the phone. The server only receives wrapped (encrypted) keys.
    private fun create(code: String) {
        if (!Regex("^\\d{6}$").matches(code)) return app.snack("Enter the 6-digit code from the email.")
        task("Creating your keys…", work = { progress ->
            val salt = Crypto.random(16)
            val k = Crypto.passwordKeys(password, salt)
            val vault = Crypto.random(32)
            val rk = RecoveryKey.generate()
            val rkKeys = Crypto.recoveryKeys(rk)
            val pair = Crypto.newKeyPair()
            val body = JSONObject().put("email", email).put("code", code).put("name", name)
                .put("kdfSalt", Crypto.b64(salt)).put("authKey", Crypto.b64(k.auth))
                .put("vaultByPw", Crypto.b64(Crypto.seal(k.kek, vault, "vs-vault")))
                .put("vaultByRk", Crypto.b64(Crypto.seal(rkKeys.kek, vault, "vs-vault")))
                .put("rkAuth", Crypto.b64(rkKeys.auth))
                .put("rkByVault", Crypto.b64(Crypto.seal(vault, rk, "vs-rk")))
                .put("pubKey", Crypto.b64(pair.public.encoded))
                .put("privByVault", Crypto.b64(Crypto.seal(vault, pair.private.encoded, "vs-priv")))
            progress("Creating your account…")
            Triple(Api.post("/auth/signup/finish", body), vault, rk) to k.auth
        }) { (t, auth) ->
            password.fill(' ')
            val (r, vault, rk) = t
            app.signedIn(r, vault, null, RecoveryKeyScreen(app, rk, firstTime = true, authKey = auth))
        }
    }

    override fun onClose() = password.fill(' ')
}

/** Shows the recovery key. The first time, the user must confirm they saved it. */
class RecoveryKeyScreen(
    app: MainActivity, private val key: ByteArray, private val firstTime: Boolean,
    private val authKey: ByteArray? = null, private val title: String = "Save your recovery key",
) : Screen(app) {
    override fun LinearLayout.build() {
        val formatted = RecoveryKey.format(key)
        header(title, if (firstTime) "Last step" else "Keep it private", onBack = if (firstTime) null else ({ app.back() }))
        text("If you forget your password, this key is the only way back into your files. VaultSpace can't see it or reset it for you.")
        card(10, 20) {
            // Two lines of four groups reads more easily than one long wrapped string.
            val groups = formatted.split("-")
            text(groups.take(4).joinToString("  ") + "\n" + groups.drop(4).joinToString("  "), 21f, bold = true) {
                typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                gravity = Gravity.CENTER
                letterSpacing = 0.04f
                contentDescription = formatted.toList().joinToString(" ")
            }
        }
        button("Copy", Btn.OUTLINE) { app.copySecret("Recovery key", formatted) }
        caption("Write it on paper or save it in a password manager. Don't send it to anyone, and don't keep it in your photos or chats.")
        if (!firstTime) {
            button("Done") { app.back() }
            return
        }
        val check = add(CheckBox(context)) { text = "I've stored my recovery key somewhere safe"; textSize = 15f }
        val last = field("Type the last 4 characters to confirm", "e.g. ${formatted.takeLast(4).replace(Regex("."), "X")}", Field.SECRET)
        button("I've saved it") {
            when {
                !check.isChecked -> app.snack("Tick the box once your key is stored safely.")
                RecoveryKey.normalise(last.value) != formatted.takeLast(4) -> app.snack("That doesn't match the end of your key. Check what you saved.")
                else -> {
                    app.reset(HomeScreen(app))
                    authKey?.let { app.offerBiometric(it) }
                }
            }
        }
    }

    override fun onClose() = key.fill(0)
}

/** Forgotten password: email code + recovery key, then a new password and a new recovery key. */
class ForgotScreen(app: MainActivity) : Screen(app) {
    private var step = 0
    private var email = Prefs.email
    private var ticket = ""
    private var vault: ByteArray? = null

    override fun LinearLayout.build() {
        val subs = listOf("Step 1 of 3 · Your email", "Step 2 of 3 · Prove it's you", "Step 3 of 3 · New password")
        header("Reset password", subs[step], onBack = { app.back() })
        when (step) {
            0 -> {
                text("You'll need two things: a code we email you, and your recovery key.")
                val e = field("Email", "you@example.com", Field.EMAIL).apply { setText(email) }
                button("Send code") {
                    email = e.value.lowercase()
                    if (!EMAIL.matches(email)) return@button app.snack("Please enter a valid email.")
                    task("Sending code…", work = { Api.post("/auth/recover/start", JSONObject().put("email", email)) }) { step = 1; rerender() }
                }
                notice("Lost both your password and recovery key?",
                    "Then nobody can decrypt your files, not even us. That's what keeps them private. You can create a new account.", dark = false)
            }
            1 -> {
                text("If $email has an account, we sent it a 6-digit code.")
                val code = field("Email code", "123456", Field.CODE)
                val rkField = field("Recovery key", "XXXX-XXXX-XXXX-…", Field.SECRET)
                button("Verify") { verify(code.value, rkField) }
            }
            else -> {
                val p = field("New password", "At least 12 characters", Field.NEW_PASSWORD)
                strengthMeter(p) { email }
                val c = field("Confirm new password", "Type it again", Field.NEW_PASSWORD)
                button("Reset password") {
                    val problem = PasswordCheck.problem(p.text.toString(), email)
                        ?: if (p.text.toString() != c.text.toString()) "The passwords don't match." else null
                    if (problem != null) return@button app.snack(problem)
                    val pw = p.chars()
                    p.setText("")
                    c.setText("")
                    finish(pw)
                }
            }
        }
    }

    private fun verify(code: String, rkField: EditText) {
        val rk = RecoveryKey.parse(rkField.value) ?: return app.snack("A recovery key has 32 letters and numbers. Check it and try again.")
        if (!Regex("^\\d{6}$").matches(code)) return app.snack("Enter the 6-digit code from the email.")
        task("Checking…", work = {
            val k = Crypto.recoveryKeys(rk)
            rk.fill(0)
            val r = Api.post("/auth/recover/verify", JSONObject().put("email", email).put("code", code).put("rkAuth", Crypto.b64(k.auth)))
            r.getString("ticket") to Crypto.open(k.kek, Crypto.unb64(r.getString("vaultByRk")), "vs-vault")
        }) { (t, v) ->
            ticket = t
            vault = v
            rkField.setText("")
            step = 2
            rerender()
        }
    }

    private fun finish(pw: CharArray) {
        val v = vault ?: return
        task("Creating new keys…", work = {
            val salt = Crypto.random(16)
            val k = Crypto.passwordKeys(pw, salt)
            pw.fill(' ')
            val rk = RecoveryKey.generate()
            val rkKeys = Crypto.recoveryKeys(rk)
            val r = Api.post("/auth/recover/finish", JSONObject().put("email", email).put("ticket", ticket)
                .put("kdfSalt", Crypto.b64(salt)).put("authKey", Crypto.b64(k.auth))
                .put("vaultByPw", Crypto.b64(Crypto.seal(k.kek, v, "vs-vault")))
                .put("rkAuth", Crypto.b64(rkKeys.auth))
                .put("vaultByRk", Crypto.b64(Crypto.seal(rkKeys.kek, v, "vs-vault")))
                .put("rkByVault", Crypto.b64(Crypto.seal(v, rk, "vs-rk"))))
            Triple(r, rk, k.auth)
        }) { (r, rk, auth) ->
            DeviceUnlock.forgetFor(email)   // the server logged out every device
            app.signedIn(r, v, null, RecoveryKeyScreen(app, rk, true, auth, "Your new recovery key"))
        }
    }
}
