package com.vaultspace.app

import android.graphics.Color
import android.text.TextUtils
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject

/** Everything the sender chooses on the Share screen. */
class ShareDraft(var notify: Boolean) {
    var email = ""
    var perm = 0                  // 0 view only, 1 view & download, 2 can update
    var expiry = 0                // 0 = 24 h, 1 = 7 days, 2 = 30 days, 3 = custom
    var customHours = 48
    var opens = 3
    var passphrase = ""

    val permCode get() = listOf("view", "download", "edit")[perm]
    val seconds get() = when (expiry) {
        0 -> 86_400
        1 -> 7 * 86_400
        2 -> 30 * 86_400
        else -> customHours * 3600
    }
    val endsAt get() = System.currentTimeMillis() / 1000 + seconds

    /** The rules in one plain sentence, so the sender sees exactly what they're allowing. */
    fun summary(): String {
        val who = email.ifEmpty { "They" }
        val what = when (perm) {
            0 -> "can view this file (no download)"
            1 -> "can view and download this file"
            else -> "can view, download and upload new versions of this file"
        }
        val times = if (opens == 1) "once" else "up to $opens times"
        return buildString {
            append("$who $what $times until ${Fmt.date(endsAt)}.")
            if (passphrase.isNotEmpty()) append(" They'll also need the passphrase.")
            append(if (notify) " You'll be notified each time it's opened." else " You won't get open alerts.")
        }
    }
}

class ShareScreen(app: MainActivity, private val fileId: String) : Screen(app) {
    private val d = ShareDraft(Session.account.optBoolean("notifyOpen", true))
    private var summary: TextView? = null

    private fun update() { summary?.text = d.summary() }

    override fun LinearLayout.build() {
        val f = Vault.find(fileId) ?: run {
            header("Share file", onBack = { app.back() })
            caption("This file is no longer in your vault.")
            return
        }
        header("Share file", f.meta.name, onBack = { app.back() })
        val email = field("Recipient's email", "name@example.com", Field.EMAIL).apply {
            setText(d.email)
            onChange { d.email = it.trim().lowercase(); update() }
        }
        caption("They need a VaultSpace account with this email. Only that account can open the file.")

        text("Access", 15f, bold = true)
        val permHelp = listOf(
            "They can read it inside VaultSpace, but can't save a copy.",
            "They can read it and save a copy to their phone.",
            "They can also upload a new version. You'll be told, and old versions are kept.",
        )
        lateinit var help: TextView
        chips(listOf("View only", "View & download", "Can update"), d.perm) { d.perm = it; help.text = permHelp[it]; update() }
        help = caption(permHelp[d.perm])

        text("Access ends after", 15f, bold = true)
        lateinit var expiryChips: List<TextView>
        expiryChips = chips(listOf("24 hours", "7 days", "30 days", if (d.expiry == 3) "${d.customHours} hours" else "Custom"), d.expiry) { i ->
            if (i == 3) {
                app.ask("Custom time limit", "How many hours should access last? (1 to 720)", "e.g. 48", Field.NUMBER, "Set") { input ->
                    val h = input.value.toIntOrNull()
                    if (h == null || h !in 1..720) return@ask app.snack("Choose between 1 and 720 hours.")
                    d.customHours = h
                    expiryChips[3].text = "$h hours"
                    update()
                }
            }
            d.expiry = i
            update()
        }

        text("Open limit", 15f, bold = true)
        row(12) {
            caption("How many times they can open it", C.INK).apply { (layoutParams as LinearLayout.LayoutParams).apply { width = 0; weight = 1f } }
            lateinit var count: TextView
            pillButton("−") { if (d.opens > 1) { d.opens--; count.text = "${d.opens}"; update() } }.contentDescription = "Fewer opens"
            count = text("${d.opens}", 18f, bold = true, w = WRAP) { gravity = Gravity.CENTER; minWidth = dp(28) }
            pillButton("+", dark = true) { if (d.opens < 50) { d.opens++; count.text = "${d.opens}"; update() } }.contentDescription = "More opens"
        }

        text("Passphrase (optional)", 15f, bold = true)
        input("Add a passphrase if you want", Field.SECRET).onChange { d.passphrase = it; update() }
        caption("Tell them the passphrase in a different way than the heads-up message, for example in person or on a call.")

        toggle("Notify me when it's opened", null, d.notify) { _, on -> d.notify = on; update() }

        card(4, 16, dark = true) {
            text("Summary", 13f, 0xFFCFCFCF.toInt(), bold = true)
            summary = text(d.summary(), 15f, Color.WHITE)
        }
        button("Continue") {
            if (!Regex("^[^@\\s]+@[^@\\s]+\\.[a-z]{2,24}$").matches(d.email)) return@button app.snack("Enter the recipient's email.")
            if (d.passphrase.isNotEmpty() && d.passphrase.length < 6) return@button app.snack("Use a passphrase of at least 6 characters, or leave it empty.")
            email.clearFocus()
            task("Finding ${d.email}…", work = { Sharing.lookup(d.email) }) { r -> app.push(ReviewScreen(app, fileId, d, r)) }
        }
    }
}

class ReviewScreen(app: MainActivity, private val fileId: String, private val d: ShareDraft, private val recipient: JSONObject) : Screen(app) {
    override fun LinearLayout.build() {
        val f = Vault.find(fileId) ?: run { caption("This file is no longer in your vault."); return }
        header("Review & share", "Final check", onBack = { app.back() })
        card(6, 16) {
            caption("You're sharing")
            row(10) {
                text(f.meta.name, 19f, bold = true, w = 0, weight = 1f) { maxLines = 2; ellipsize = TextUtils.TruncateAt.END }
                pill(Fmt.perm(d.permCode), dark = false)
            }
            text("To ${cleanName(recipient.getString("name"))} · ${recipient.getString("email")}", 14f)
            caption("Their security code: ${Crypto.fingerprint(recipient.getString("pubKey"))}")
        }
        card(10, 16) {
            text("Security settings", 15f, bold = true)
            kv("Downloads", if (d.perm == 0) "Blocked" else "Allowed", if (d.perm == 0) C.GOOD else C.INK)
            kv("New versions by them", if (d.perm == 2) "Allowed" else "No")
            kv("Access ends", Fmt.date(d.endsAt))
            kv("Open limit", if (d.opens == 1) "1 open" else "${d.opens} opens")
            kv("Passphrase", if (d.passphrase.isEmpty()) "Off" else "Required")
            kv("Open notifications", if (d.notify) "On" else "Off")
        }
        notice("Good to know",
            "Screenshots are blocked inside VaultSpace, but someone could still photograph the screen. You can remove access at any time; copies they already saved can't be taken back.",
            dark = false)
        button("Share securely") {
            task("Encrypting the key for ${recipient.getString("email")}…", work = {
                val r = Sharing.create(f, recipient, d.permCode, d.seconds, d.opens, d.notify, d.passphrase)
                Vault.refresh()
                r
            }) { r -> app.replace(SharedDoneScreen(app, f.meta.name, d, recipient, r.getString("id"), r.getLong("expiresAt")), count = 2) }
        }
    }
}

class SharedDoneScreen(
    app: MainActivity, private val name: String, private val d: ShareDraft, private val recipient: JSONObject,
    private val shareId: String, private val expiresAt: Long,
) : Screen(app) {
    override fun LinearLayout.build() {
        row { roundButton(R.drawable.ic_back, "Back") { app.back() } }
        column(10) {
            gravity = Gravity.CENTER_HORIZONTAL
            add(android.widget.FrameLayout(context), dp(80), dp(80)) {
                background = shape(C.INK, 0f, oval = true)
                icon(R.drawable.ic_check, 40, Color.WHITE).apply { (layoutParams as android.widget.FrameLayout.LayoutParams).gravity = Gravity.CENTER }
            }
            text("File shared", 26f, bold = true, w = WRAP)
            caption("$name is now shared with ${cleanName(recipient.getString("name"))}.").gravity = Gravity.CENTER
        }
        card(8, 16) {
            kv("Permission", Fmt.perm(d.permCode) + if (d.perm == 0) " · no download" else "")
            kv("Access ends", Fmt.date(expiresAt))
            kv("Open limit", "${d.opens}")
            if (d.passphrase.isNotEmpty()) kv("Passphrase", "Required")
        }
        button("Send a heads-up") {
            app.shareText(buildString {
                append("I've shared a file with you on VaultSpace.\n")
                append("Open VaultSpace and look in \"Shared With Me\", or tap: vaultspace://share/$shareId\n")
                append("Only your VaultSpace account can open it, so forwarding this message doesn't give anyone else access.")
                if (d.passphrase.isNotEmpty()) append("\nI'll tell you the passphrase separately.")
            })
        }
        caption("The message contains no secret. It just tells them where to look.")
        button("Manage access", Btn.SECONDARY) { app.back() }
        button("Done", Btn.OUTLINE) { app.reset(HomeScreen(app)) }
    }
}

class SharedByMeScreen(app: MainActivity) : Screen(app) {
    override val tab = 1
    private var shares: List<JSONObject>? = null

    override fun LinearLayout.build() {
        header("Shared By Me", "Everyone who can open your files")
        notice("Revoking stops future access.", "But copies already downloaded can't be removed.")
        val all = shares ?: run { caption("Loading…"); return }
        val active = all.filter { it.getString("status") == "active" }
        if (active.isEmpty()) caption("You're not sharing any files right now.")
        else button("Stop all sharing", Btn.DANGER) {
            app.confirm("Stop all sharing?", "Everyone loses access to all your files right away (${active.size} ${if (active.size == 1) "share" else "shares"}).", "Stop all") {
                task("Removing access…", work = { Sharing.revokeAll() }) { r -> app.snack("Removed ${r.getInt("revoked")} shares."); onShow() }
            }
        }
        active.groupBy { it.getString("fileId") }.forEach { (fid, list) ->
            card(10, 16, dark = true) {
                text(Vault.find(fid)?.meta?.name ?: "File", 18f, Color.WHITE, bold = true)
                list.forEach { s ->
                    add(LinearLayout(context)) {
                        orientation = LinearLayout.HORIZONTAL
                        gravity = Gravity.CENTER_VERTICAL
                        gap(dp(12))
                        setPadding(dp(12), dp(12), dp(12), dp(12))
                        background = shape(C.CARD, dpf(16f))
                        avatar(s.getString("email"))
                        column(2, w = 0, weight = 1f) {
                            text(s.getString("email"), 14f, bold = true) { maxLines = 1; ellipsize = TextUtils.TruncateAt.END }
                            caption("${Fmt.perm(s.getString("perm"))} · ends in ${Fmt.left(s.getLong("expiresAt"))}")
                            caption("Opens: ${s.getInt("opensUsed")} of ${s.getInt("maxOpens")}")
                        }
                        pillButton("Revoke") {
                            app.confirm("Revoke ${s.getString("email")}?", "They lose access right away. Copies they already saved can't be removed.", "Revoke") {
                                task("Removing access…", work = { Sharing.revoke(s.getString("id")) }) { app.snack("Access removed."); onShow() }
                            }
                        }
                    }
                }
            }
        }
        val past = all.filter { it.getString("status") != "active" }
        if (past.isNotEmpty()) {
            text("Past shares (last 30 days)", 15f, bold = true)
            past.take(30).forEach { s ->
                row(8) {
                    text("${s.getString("email")} · ${Vault.find(s.getString("fileId"))?.meta?.name ?: "deleted file"}", 13f, w = 0, weight = 1f) {
                        maxLines = 1
                        ellipsize = TextUtils.TruncateAt.END
                    }
                    pill(Fmt.status(s.getString("status")), dark = false)
                }
            }
        }
    }

    override fun onShow() {
        task(null, work = { Vault.refresh(); Sharing.outgoing() }) { shares = it; rerender() }
    }
}

class SharedWithMeScreen(app: MainActivity, private var openId: String? = null) : Screen(app) {
    override val tab = 2
    private var items: List<Incoming>? = null

    override fun LinearLayout.build() {
        header("Shared With Me", "Files other people shared with you")
        val list = items ?: run { caption("Loading…"); return }
        if (list.isEmpty()) notice("Nothing here yet", "When someone shares a file with ${Session.email}, it appears here.", dark = false)
        list.forEach { s ->
            val active = s.status == "active"
            add(LinearLayout(context)) {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                gap(dp(12))
                setPadding(dp(14), dp(14), dp(14), dp(14))
                pressable(shape(C.CARD, dpf(18f), C.LINE, dp(1)))
                alpha = if (active) 1f else 0.6f
                val label = title(s)
                contentDescription = "$label, shared by ${s.sender}, ${Fmt.perm(s.perm)}"
                iconBox(if (s.meta == null) R.drawable.ic_lock else R.drawable.ic_file)
                column(2, w = 0, weight = 1f) {
                    text(label, 15f, bold = true) { maxLines = 1; ellipsize = TextUtils.TruncateAt.END }
                    caption("Shared by ${s.sender} · ${Fmt.size(s.size)}")
                    caption(if (active) "${s.opensLeft} of ${s.maxOpens} opens left · ends in ${Fmt.left(s.expiresAt)}" else Fmt.status(s.status))
                }
                column(4, w = WRAP) {
                    gravity = Gravity.END
                    caption("Permission")
                    pill(Fmt.perm(s.perm), dark = active)
                }
                setOnClickListener { open(s) }
            }
        }
        if (list.isNotEmpty()) caption("Each time you open a file, it uses one of the opens the owner allowed.")
    }

    private fun title(s: Incoming) = s.meta?.name ?: if (s.hasPass && s.status == "active") "Protected file" else "Unavailable file"

    /** fromLink: opened by a vaultspace:// link, which any website or app can fire, so always ask first. */
    private fun open(s: Incoming, fromLink: Boolean = false) {
        if (s.status != "active") return app.snack(when (s.status) {
            "revoked" -> "${s.fromName} removed your access to this file."
            "expired" -> "Your access to this file has ended."
            "used_up" -> "You've used all the opens ${s.fromName} allowed."
            else -> "This share was locked after too many wrong passphrases."
        })
        val go = { pass: String? ->
            task("Opening securely…", work = { p -> Sharing.open(s, pass) { p("Decrypting… $it%") } }) { o ->
                app.push(viewerFor(o))
                onShow()
            }
        }
        val proceed = {
            if (s.hasPass) app.ask("Passphrase needed", "${s.sender} protected this file with a passphrase.", "Passphrase", Field.PASSWORD, "Open") { go(it.text.toString()) }
            else go(null)
        }
        when {
            s.opensLeft == 1 ->
                app.confirm("Last open", "This is your last allowed open. After this, ask ${s.fromName} to share it again if you need it.", "Open now") { proceed() }
            fromLink ->
                app.confirm("Open this file?", "${title(s)} from ${s.sender}. Opening it uses 1 of your ${s.opensLeft} opens.", "Open") { proceed() }
            else -> proceed()
        }
    }

    private fun viewerFor(o: Opened): ViewerScreen {
        val actions = mutableListOf<Pair<String, () -> Unit>>()
        if (o.perm != "view") actions += "Save a copy" to {
            app.task(null, "Checking permission…", null, { Sharing.allowDownload(o) }) { saveCopy(app, o.meta.name, o.data) }
        }
        if (o.perm == "edit") actions += "Upload a new version" to {
            app.pickFile { uri ->
                app.task(null, "Reading file…", null, { Vault.readPicked(app, uri) }) { p ->
                    app.confirm("Upload ${p.name}?", "${o.share.fromName} will see it as the newest version of ${o.meta.name}. Older versions are kept.", "Upload") {
                        app.task(null, "Encrypting…", null, { pr -> Sharing.uploadVersion(o, p) { pr("Encrypting & uploading… $it%") } }) {
                            p.data.fill(0)
                            app.snack("New version uploaded. ${o.share.fromName} was notified.")
                        }
                    }
                }
            }
        }
        val mark = "${Session.email} · ${Fmt.time(System.currentTimeMillis() / 1000)}"
        return ViewerScreen(app, o.meta, o.data, "${Fmt.perm(o.perm)} · from ${o.share.sender} · ${Fmt.plural(o.opensLeft, "open")} left", mark, actions)
    }

    override fun onShow() {
        task(null, work = { Sharing.incoming() }) { list ->
            items = list
            rerender()
            val id = openId ?: return@task
            openId = null
            list.firstOrNull { it.id == id }?.let { open(it, fromLink = true) } ?: app.snack("That share isn't available to this account.")
        }
    }
}
