package com.vaultspace.app

import android.content.Intent
import android.graphics.Typeface
import android.net.Uri
import android.view.Gravity
import android.widget.LinearLayout
import org.json.JSONObject

/** Turns a server event into a sentence and a tag, using file names the phone decrypted. */
object Events {
    fun describe(e: JSONObject): Pair<String, String> {
        val fileId = e.optString("fileId", "")
        val file = Vault.find(fileId)?.meta?.name ?: if (fileId.isEmpty() || e.isNull("fileId")) "a file" else "a deleted file"
        val who = e.optString("actor", "")
        return when (e.getString("type")) {
            "upload" -> "You uploaded $file" to "Upload"
            "new_version" -> "You uploaded a new version of $file" to "Upload"
            "delete" -> "You deleted a file" to "System"
            "share" -> "You shared $file with $who" to "Shared"
            "received" -> "$who shared a file with you" to "Shared"
            "revoke" -> "You removed $who's access to $file" to "Revoked"
            "revoke_all" -> "You stopped sharing ($who ${if (who == "1") "share" else "shares"})" to "Revoked"
            "open" -> "$who opened $file" to "Viewed"
            "download" -> "$who saved a copy of $file" to "Download"
            "edited" -> "$who uploaded a new version of $file" to "Edit"
            "restore" -> "You restored $file to $who" to "Edit"
            "limit_reached" -> "$who used all their opens of $file" to "System"
            "expired" -> "$who's access to $file expired" to "System"
            "pass_failed" -> "$who entered a wrong passphrase for $file" to "Security"
            "pass_locked" -> "$file was locked after wrong passphrases by $who" to "Security"
            "login" -> "New login: $who" to "Security"
            "login_failed_many" -> "Several failed login attempts on your account" to "Security"
            "account_created" -> "Account created on $who" to "System"
            "device_added" -> "Fingerprint unlock turned on: $who" to "Security"
            "device_removed" -> "A trusted phone was removed" to "Security"
            "recovered" -> "Password reset with your recovery key on $who" to "Security"
            "password_changed" -> "Your password was changed" to "Security"
            "recovery_key_viewed" -> "Your recovery key was viewed" to "Security"
            "2fa_on" -> "Two-factor authentication turned on" to "Security"
            "2fa_off" -> "Two-factor authentication turned off" to "Security"
            "logout_everywhere" -> "Logged out on all other devices" to "Security"
            else -> e.getString("type") to "System"
        }
    }
}

private fun LinearLayout.eventCard(e: JSONObject, unread: Boolean = false) {
    val (text, tag) = Events.describe(e)
    card(4, 14) {
        row(10) {
            column(2, w = 0, weight = 1f) {
                caption(Fmt.time(e.getLong("at")))
                text(text, 14f, bold = unread)
            }
            pill(tag, dark = tag == "Security")
        }
    }
}

class NotificationsScreen(app: MainActivity) : Screen(app) {
    private var items: List<JSONObject>? = null

    override fun LinearLayout.build() {
        header("Notifications", "Opens, downloads and security alerts", onBack = { app.back() })
        button("Full access history", Btn.OUTLINE) { app.push(HistoryScreen(app)) }
        val list = items ?: run { caption("Loading…"); return }
        if (list.isEmpty()) caption("No notifications yet.")
        list.forEach { eventCard(it, it.getInt("read") == 0) }
    }

    override fun onShow() {
        task(null, work = {
            runCatching { Vault.refresh() }
            Api.get("/notifications").also { if (it.getInt("unread") > 0) Api.post("/notifications/read") }
        }) { r -> items = r.getJSONArray("items").objects(); rerender() }
    }
}

class HistoryScreen(app: MainActivity) : Screen(app) {
    private var events: List<JSONObject>? = null

    override fun LinearLayout.build() {
        header("Access history", "Recent activity", onBack = { app.back() })
        button("Verify history", Btn.OUTLINE) {
            task("Checking every entry…", work = { Api.get("/history/verify") }) { r ->
                if (r.getBoolean("ok")) app.info("History is intact", "All ${r.getInt("count")} entries are linked by hashes and none of them were changed or removed.")
                else app.info("History was changed!", "Entry ${r.optInt("brokenAt")} doesn't match the chain. Someone may have edited the history.")
            }
        }
        caption("Each entry includes a hash of the one before it, so editing or deleting an old entry would break the chain.")
        val list = events ?: run { caption("Loading…"); return }
        if (list.isEmpty()) caption("Nothing has happened yet.")
        list.forEach { eventCard(it) }
    }

    override fun onShow() {
        task(null, work = {
            runCatching { Vault.refresh() }
            Api.get("/history").getJSONArray("events").objects()
        }) { events = it; rerender() }
    }
}

class ProfileScreen(app: MainActivity) : Screen(app) {
    override val tab = 3
    private var me: JSONObject? = null

    override fun LinearLayout.build() {
        row(14) {
            avatar(Session.name, 56)
            column(2, w = 0, weight = 1f) {
                text(Session.name, 20f, bold = true)
                caption(Session.email)
            }
        }
        me?.getJSONObject("usage")?.let { u -> caption("${Fmt.size(u.getLong("used"))} of ${Fmt.size(u.getLong("quota"))} used · ${Fmt.plural(u.getInt("files"), "file")}") }
        card(6, 14) {
            text("Your security code", 13f, C.MUTED, bold = true)
            text(Crypto.fingerprint(Session.publicKey), 16f, bold = true) { typeface = Typeface.MONOSPACE }
            caption("People who share with you see the same code. If you compare it in person and it matches, nobody swapped your key.")
        }

        text("Security", 17f, bold = true)
        navRow("See your recovery key", "Needs your password") {
            app.withPassword("Enter your password to show your recovery key.") { k ->
                task("Decrypting…", work = {
                    val r = Api.post("/account/recovery-key", JSONObject().put("authKey", Crypto.b64(k.auth)))
                    Crypto.open(Session.vault, Crypto.unb64(r.getString("rkByVault")), "vs-rk")
                }) { rk -> app.push(RecoveryKeyScreen(app, rk, firstTime = false, title = "Your recovery key")) }
            }
        }
        card(0, 14) {
            val available = DeviceUnlock.available(app)
            toggle("Fingerprint unlock", if (available) "Open VaultSpace on this phone with your fingerprint" else "Not available: add a fingerprint in your phone's settings first",
                DeviceUnlock.isSetUpFor(Session.email)) { sw, on ->
                if (on == DeviceUnlock.isSetUpFor(Session.email)) return@toggle
                if (!available) { sw.isChecked = false; return@toggle }
                sw.isChecked = !on   // the switch only moves once the change really happened
                if (on) {
                    app.withPassword("Enter your password to turn on fingerprint unlock.") { k -> app.enableBiometric(k.auth) { rerender() } }
                } else {
                    val id = Prefs.deviceId
                    DeviceUnlock.forgetFor(Session.email)
                    if (id != null) task(null, work = { Api.delete("/devices/$id") }) {}
                    rerender()
                }
            }
        }
        navRow("Two-factor authentication", if (Session.account.optBoolean("twoFactor")) "On" else "Off · add a code from an authenticator app") { app.push(TwoFactorScreen(app)) }
        navRow("Devices & sessions", "See where you're logged in") { app.push(DevicesScreen(app)) }
        navRow("Change password") { app.push(ChangePasswordScreen(app)) }
        navRow("Access history", "Everything that happened to your files") { app.push(HistoryScreen(app)) }

        text("Settings", 17f, bold = true)
        navRow("Personal information", Session.name) {
            app.ask("Your name", null, "Name", Field.NAME, "Save") { input ->
                task("Saving…", work = { Api.post("/me", JSONObject().put("name", input.value)) }) { r -> Session.account = r.getJSONObject("account"); rerender() }
            }
        }
        card(0, 14) {
            toggle("Notify me when my files are opened", "The default for new shares", Session.account.optBoolean("notifyOpen", true)) { _, on ->
                task(null, work = { Api.post("/me", JSONObject().put("notifyOpen", on)) }) { r -> Session.account = r.getJSONObject("account") }
            }
        }
        navRow("What VaultSpace can and can't protect") { app.push(LimitsScreen(app)) }
        button("Log out", Btn.OUTLINE) {
            app.confirm("Log out?", "You'll need your password or fingerprint to open VaultSpace again.", "Log out") { app.lock(null) }
        }
        button("Delete account", Btn.DANGER) {
            app.confirm("Delete your account?",
                "All your files, versions and shares are deleted for good, and people you shared with lose access. This can't be undone.", "Continue") {
                app.withPassword("Enter your password to delete your account.") { k ->
                    task("Deleting everything…", work = { Api.post("/account/delete", JSONObject().put("authKey", Crypto.b64(k.auth))) }) {
                        DeviceUnlock.forgetFor(Session.email)
                        Prefs.email = ""
                        Session.end()
                        app.reset(LoginScreen(app, "Your account and all its files were deleted."))
                    }
                }
            }
        }
    }

    override fun onShow() {
        task(null, work = { Api.get("/me") }) { r ->
            me = r
            Session.account = r.getJSONObject("account")
            rerender()
        }
    }
}

class TwoFactorScreen(app: MainActivity) : Screen(app) {
    private var setup: JSONObject? = null

    override fun LinearLayout.build() {
        header("Two-factor authentication", onBack = { app.back() })
        val s = setup
        when {
            Session.account.optBoolean("twoFactor") -> {
                notice("Two-factor is on", "Logging in with your password also needs a 6-digit code from your authenticator app.", dark = false)
                button("Turn off", Btn.DANGER) {
                    app.withPassword("Enter your password to turn off two-factor authentication.") { k ->
                        app.ask("Authenticator code", "Enter the current code from your authenticator app.", "123456", Field.CODE, "Turn off") { c ->
                            task("Turning off…", work = {
                                Api.post("/account/2fa/disable", JSONObject().put("authKey", Crypto.b64(k.auth)).put("code", c.value))
                                Api.get("/me")
                            }) { r -> Session.account = r.getJSONObject("account"); rerender() }
                        }
                    }
                }
            }
            s == null -> {
                text("Add a second step to logging in: a 6-digit code from an app such as Google Authenticator or Microsoft Authenticator. Someone who learns your password still can't log in without your phone.")
                button("Set up") {
                    app.withPassword("Enter your password to set up two-factor authentication.") { k ->
                        task("Preparing…", work = { Api.post("/account/2fa/setup", JSONObject().put("authKey", Crypto.b64(k.auth))) }) { setup = it; rerender() }
                    }
                }
            }
            else -> {
                val secret = s.getString("secret")
                text("1. In your authenticator app, add an account and choose \"Enter a setup key\".")
                card(6, 16) {
                    text(secret.chunked(4).joinToString(" "), 18f, bold = true) {
                        typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                        gravity = Gravity.CENTER
                    }
                }
                row(10) {
                    button("Copy key", Btn.OUTLINE, w = 0, weight = 1f) { app.copySecret("Setup key", secret) }
                    button("Open app", Btn.OUTLINE, w = 0, weight = 1f) {
                        runCatching { app.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(s.getString("uri")))) }
                            .onFailure { app.snack("No authenticator app found. Copy the key instead.") }
                    }
                }
                text("2. Enter the 6-digit code it shows:")
                val code = input("123456", Field.CODE)
                button("Turn on") {
                    task("Checking…", work = {
                        Api.post("/account/2fa/enable", JSONObject().put("code", code.value))
                        Api.get("/me")
                    }) { r ->
                        Session.account = r.getJSONObject("account")
                        setup = null
                        app.snack("Two-factor authentication is on.")
                        rerender()
                    }
                }
            }
        }
    }
}

class DevicesScreen(app: MainActivity) : Screen(app) {
    private var sessions: List<JSONObject>? = null
    private var devices: List<JSONObject>? = null

    override fun LinearLayout.build() {
        header("Devices & sessions", onBack = { app.back() })
        val ss = sessions ?: run { caption("Loading…"); return }
        text("Logged in now", 17f, bold = true)
        ss.forEach { s ->
            card(4, 14) {
                row(10) {
                    column(2, w = 0, weight = 1f) {
                        text(s.getString("label"), 15f, bold = true)
                        caption("Active ${Fmt.ago(s.getLong("lastSeen"))} · since ${Fmt.time(s.getLong("createdAt"))}")
                    }
                    if (s.getBoolean("current")) pill("This phone")
                }
            }
        }
        text("Fingerprint unlock", 17f, bold = true)
        caption("Phones that can unlock your vault with a fingerprint.")
        val ds = devices ?: emptyList()
        if (ds.isEmpty()) caption("None.")
        ds.forEach { d ->
            card(4, 14) {
                row(10) {
                    column(2, w = 0, weight = 1f) {
                        text(d.getString("label"), 15f, bold = true)
                        caption("Added ${Fmt.time(d.getLong("createdAt"))} · used ${Fmt.ago(d.getLong("lastUsed"))}")
                    }
                    pillButton("Remove") {
                        app.confirm("Remove this phone?", "It will need the password next time.", "Remove") {
                            task("Removing…", work = { Api.delete("/devices/${d.getString("id")}") }) {
                                if (d.getString("id") == Prefs.deviceId) DeviceUnlock.forget()
                                onShow()
                            }
                        }
                    }
                }
            }
        }
        button("Log out everywhere else", Btn.DANGER) {
            app.confirm("Log out everywhere else?", "Every other session ends and fingerprint unlock is turned off on all phones.", "Log out others") {
                task("Logging out…", work = { Api.post("/sessions/logout-others") }) {
                    DeviceUnlock.forgetFor(Session.email)
                    app.snack("Other sessions were logged out.")
                    onShow()
                }
            }
        }
    }

    override fun onShow() {
        task(null, work = { Api.get("/sessions").getJSONArray("sessions").objects() to Api.get("/devices").getJSONArray("devices").objects() }) { (s, d) ->
            sessions = s
            devices = d
            rerender()
        }
    }
}

class ChangePasswordScreen(app: MainActivity) : Screen(app) {
    override fun LinearLayout.build() {
        header("Change password", onBack = { app.back() })
        val cur = field("Current password", "Current password", Field.PASSWORD)
        val nw = field("New password", "At least 12 characters", Field.NEW_PASSWORD)
        strengthMeter(nw) { Session.email }
        val conf = field("Confirm new password", "Type it again", Field.NEW_PASSWORD)
        caption("Your files don't need re-encrypting: only the key that protects your vault key changes. Your other devices will be logged out.")
        button("Change password") {
            val n = nw.text.toString()
            val problem = PasswordCheck.problem(n, Session.email) ?: when {
                n != conf.text.toString() -> "The new passwords don't match."
                n == cur.text.toString() -> "Choose a password you haven't used here."
                else -> null
            }
            if (problem != null) return@button app.snack(problem)
            val oldPw = cur.chars()
            val newPw = nw.chars()
            listOf(cur, nw, conf).forEach { it.setText("") }
            task("Updating your keys…", work = {
                val pre = Api.post("/auth/prelogin", JSONObject().put("email", Session.email))
                val old = Crypto.passwordKeys(oldPw, Crypto.unb64(pre.getString("salt")), pre.getInt("iters"))
                val salt = Crypto.random(16)
                val k = Crypto.passwordKeys(newPw, salt)
                oldPw.fill(' ')
                newPw.fill(' ')
                Api.post("/account/password", JSONObject().put("authKey", Crypto.b64(old.auth)).put("kdfSalt", Crypto.b64(salt))
                    .put("newAuthKey", Crypto.b64(k.auth)).put("vaultByPw", Crypto.b64(Crypto.seal(k.kek, Session.vault, "vs-vault"))))
            }) {
                DeviceUnlock.forgetFor(Session.email)
                app.snack("Password changed. Your other devices were logged out.")
                app.back()
            }
        }
    }
}

class LimitsScreen(app: MainActivity) : Screen(app) {
    override fun LinearLayout.build() {
        header("What VaultSpace protects", "And what no app can", onBack = { app.back() })
        card(10, 16) {
            text("Protected", 17f, C.GOOD, bold = true)
            listOf(
                "Your files and their names are encrypted on your phone. Our server only stores scrambled data and can't read it, even if it's hacked.",
                "Only the person you share with can open a shared file, with their own VaultSpace account. Forwarding the heads-up message gives nobody access.",
                "Expiry, open limits, view-only and revoking are checked by the server every time, so changing the app can't get around them.",
                "Screenshots and screen recording are blocked inside VaultSpace.",
                "Every open, download and change is recorded in a history that can't be secretly edited.",
                "Network traffic only goes to the VaultSpace server, whose certificate is built into the app.",
            ).forEach { text("• $it", 14f) }
        }
        card(10, 16) {
            text("Not protected", 17f, C.DANGER, bold = true)
            listOf(
                "Someone can still photograph the screen with another phone. Viewed files show the viewer's email as a watermark, so a leaked photo shows who took it.",
                "Copies someone already saved (when you allowed downloads) can't be taken back by revoking.",
                "Someone holding your unlocked phone can see what you can see. VaultSpace locks itself after 5 minutes without activity.",
                "If you forget both your password and your recovery key, nobody, including us, can recover your files.",
                "Our server can see file sizes, when files are uploaded and opened, and who shares with whom, but not what's inside.",
            ).forEach { text("• $it", 14f) }
        }
    }
}
