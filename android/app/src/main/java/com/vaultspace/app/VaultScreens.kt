package com.vaultspace.app

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.pdf.PdfRenderer
import android.media.MediaDataSource
import android.media.MediaPlayer
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.text.TextUtils
import android.view.Gravity
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.View
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import java.io.File

/** Saves a decrypted copy through the system "Save as" dialog (only when the user/owner allows it). */
fun saveCopy(app: MainActivity, name: String, data: ByteArray) = app.saveFile(name) { uri ->
    app.task(null, "Saving…", null, { app.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(data) } }) {
        app.snack("Saved. Note: this copy is outside VaultSpace and is not encrypted.")
    }
}

fun LinearLayout.fileCard(app: MainActivity, f: VaultFile, onChanged: () -> Unit) = add(LinearLayout(context)) {
    orientation = LinearLayout.HORIZONTAL
    gravity = Gravity.CENTER_VERTICAL
    gap(dp(12))
    setPadding(dp(14), dp(14), dp(10), dp(14))
    pressable(shape(C.CARD, dpf(18f), C.LINE, dp(1)))
    contentDescription = "${f.meta.name}, ${Fmt.size(f.size)}, ${if (f.activeShares > 0) "shared with ${f.activeShares}" else "only you"}"
    iconBox(R.drawable.ic_file)
    column(2, w = 0, weight = 1f) {
        text(f.meta.name, 15f, bold = true) { maxLines = 1; ellipsize = TextUtils.TruncateAt.END }
        if (f.damaged) caption("Its details can't be read · tap to restore", C.DANGER)
        else caption("Updated ${Fmt.ago(f.updatedAt)} · ${Fmt.size(f.size)}")
    }
    column(6, w = WRAP) {
        gravity = Gravity.END
        add(ImageView(context), dp(32), dp(28)) {
            setImageResource(R.drawable.ic_more)
            contentDescription = "More options for ${f.meta.name}"
            setOnClickListener { fileMenu(app, f, this, onChanged) }
        }
        if (f.activeShares > 0) pill("Shared · ${f.activeShares}", dark = false) else pill("Only you")
    }
    setOnClickListener { app.push(FileDetailsScreen(app, f.id)) }
}

fun fileMenu(app: MainActivity, f: VaultFile, anchor: View, onChanged: () -> Unit) {
    val menu = PopupMenu(app, anchor)
    listOf("Open", "Share", "Who has access", "Rename", "Delete").forEachIndexed { i, s -> menu.menu.add(0, i, i, s) }
    menu.setOnMenuItemClickListener { item ->
        when (item.itemId) {
            0 -> openOwn(app, f)
            1 -> app.push(ShareScreen(app, f.id))
            2 -> app.push(FileDetailsScreen(app, f.id))
            3 -> rename(app, f, onChanged)
            else -> deleteFile(app, f, onChanged)
        }
        true
    }
    menu.show()
}

fun openOwn(app: MainActivity, f: VaultFile, version: Int = f.version, size: Long = f.size) =
    app.task(null, "Decrypting…", null, { p -> Vault.read(f, version, size) { p("Decrypting… $it%") } }) { data ->
        val name = if (version == f.version) f.meta.name else "${f.meta.name} (v$version)"
        lateinit var viewer: ViewerScreen
        viewer = ViewerScreen(app, f.meta.copy(name = name), data, "Your file · only you can open it", null,
            listOf("Save a copy" to { saveCopy(app, f.meta.name, viewer.data) }))
        app.push(viewer)
    }

fun rename(app: MainActivity, f: VaultFile, onChanged: () -> Unit) =
    app.ask("Rename file", null, "File name", Field.TEXT, "Save") { input ->
        val name = cleanName(input.value)
        app.task(null, "Saving…", null, { Vault.updateMeta(f, f.meta.copy(name = name)); Vault.refresh() }) { onChanged() }
    }

fun deleteFile(app: MainActivity, f: VaultFile, onDone: () -> Unit) =
    app.confirm("Delete ${f.meta.name}?",
        "This removes the file and all its versions, and everyone you shared it with loses access. This can't be undone.", "Delete") {
        app.task(null, "Deleting…", null, { Vault.delete(f); Vault.refresh() }) {
            app.snack("Deleted.")
            onDone()
        }
    }

class HomeScreen(app: MainActivity) : Screen(app) {
    override val tab = 0
    private var query = ""
    private var category: String? = null
    private var allCategories = false
    private var unread = 0
    private var loaded = false
    private lateinit var list: LinearLayout

    override fun LinearLayout.build() {
        header("My Vault", "Only you hold the key to these files") {
            roundButton(R.drawable.ic_history, "Access history", dark = false) { app.push(HistoryScreen(app)) }
            roundButton(R.drawable.ic_bell, "Notifications", badge = unread) { app.push(NotificationsScreen(app)) }
        }
        input("Search your files", Field.TEXT).apply {
            setText(query)
            contentDescription = "Search your files"
            onChange { query = it.trim(); fillList() }
        }
        add(LinearLayout(context), MATCH, dp(56)) {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), 0, dp(10), 0)
            pressable(shape(C.INK, dpf(16f)), 0x33FFFFFF)
            contentDescription = "Upload document"
            text("Upload document", 16f, Color.WHITE, bold = true, w = 0, weight = 1f)
            add(FrameLayout(context), dp(36), dp(36)) {
                background = shape(Color.WHITE, 0f, oval = true)
                icon(R.drawable.ic_plus, 20).apply { (layoutParams as FrameLayout.LayoutParams).gravity = Gravity.CENTER }
            }
            setOnClickListener { app.push(UploadScreen(app, category)) }
        }
        if (loaded) caption("${Fmt.size(Vault.used)} of ${Fmt.size(Vault.quota)} used · everything is encrypted on this phone")
        text("Categories", 17f, bold = true)
        val cats = if (allCategories) Vault.CATEGORIES else Vault.CATEGORIES.take(4)
        cats.chunked(2).forEach { pair ->
            row(10) {
                pair.forEach { c ->
                    val count = Vault.files.count { it.meta.category == c }
                    add(LinearLayout(context), 0, dp(58), 1f) {
                        orientation = LinearLayout.HORIZONTAL
                        gravity = Gravity.CENTER_VERTICAL
                        gap(dp(8))
                        setPadding(dp(12), 0, dp(8), 0)
                        val on = c == category
                        pressable(shape(if (on) C.INK else C.CARD, dpf(14f), C.LINE, if (on) 0 else dp(1)))
                        icon(R.drawable.ic_file, 20, if (on) Color.WHITE else C.INK)
                        text("$c${if (count > 0) " ($count)" else ""}", 13f, if (on) Color.WHITE else C.INK, bold = true, w = 0, weight = 1f) { maxLines = 2 }
                        isSelected = on
                        setOnClickListener { category = if (on) null else c; rerender() }
                    }
                }
                if (pair.size == 1) add(View(context), 0, 1, 1f)
            }
        }
        pillButton(if (allCategories) "Less" else "More") { allCategories = !allCategories; rerender() }
            .apply { (layoutParams as LinearLayout.LayoutParams).gravity = Gravity.CENTER_HORIZONTAL }
        row {
            text(category ?: "Recent documents", 17f, bold = true, w = 0, weight = 1f)
            if (category != null) pillButton("Show all") { category = null; rerender() }
        }
        list = column(10)
        fillList()
    }

    private fun fillList() {
        list.removeAllViews()
        val files = Vault.files.filter {
            (category == null || it.meta.category == category) && (query.isEmpty() || it.meta.name.contains(query, ignoreCase = true))
        }
        when {
            !loaded -> list.caption("Loading your vault…")
            Vault.files.isEmpty() -> list.notice("Your vault is empty",
                "Upload your first document. It's encrypted on this phone before it leaves, so only you can read it.", dark = false)
            files.isEmpty() -> list.caption("No files match.")
            else -> files.forEach { f -> list.fileCard(app, f) { onShow() } }
        }
    }

    override fun onShow() {
        task(null, work = {
            Vault.refresh()
            Api.get("/notifications").getInt("unread")
        }) { n ->
            unread = n
            loaded = true
            rerender()
        }
    }
}

class UploadScreen(app: MainActivity, private var category: String?) : Screen(app) {
    private var picked: Picked? = null
    private var nameField: EditText? = null

    override fun LinearLayout.build() {
        header("Upload", "Any kind of file, up to 50 MB", onBack = { app.back() })
        val p = picked
        add(LinearLayout(context), MATCH, dp(190)) {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            gap(dp(10))
            pressable(shape(C.INK, dpf(20f)), 0x33FFFFFF)
            text(if (p == null) "Choose a file" else p.name, 16f, Color.WHITE, bold = true, w = WRAP) { gravity = Gravity.CENTER; setPadding(dp(16), 0, dp(16), 0) }
            icon(R.drawable.ic_cloud, 48, Color.WHITE)
            text(if (p == null) "Tap to pick from your phone" else "${Fmt.size(p.data.size.toLong())} · tap to choose another", 13f, 0xFFCFCFCF.toInt(), w = WRAP)
            setOnClickListener {
                app.pickFile { uri ->
                    task("Reading file…", work = { Vault.readPicked(app, uri) }) { np ->
                        picked?.data?.fill(0)
                        picked = np
                        rerender()
                    }
                }
            }
        }
        if (p != null) nameField = field("File name", "Name", Field.TEXT).apply { setText(p.name) }
        text("Category", 15f, bold = true)
        val start = Vault.CATEGORIES.indexOf(category).coerceAtLeast(0)
        if (category == null) category = Vault.CATEGORIES[start]
        chips(Vault.CATEGORIES, start) { category = Vault.CATEGORIES[it] }
        button("Encrypt & upload") {
            val file = picked ?: return@button app.snack("Choose a file first.")
            val name = cleanName(nameField?.value ?: file.name)
            task("Encrypting…", work = { progress ->
                Vault.upload(Picked(name, file.type, file.data), category ?: "Other") { pct -> progress("Encrypting & uploading… $pct%") }
            }) {
                file.data.fill(0)
                picked = null
                app.snack("Uploaded. It was encrypted on this phone first.")
                app.back()
            }
        }
        caption("A new random key is made for this file and it is encrypted on this phone before upload. The file name and category are encrypted too.")
    }

    override fun onClose() { picked?.data?.fill(0) }
}

class FileDetailsScreen(app: MainActivity, private val fileId: String) : Screen(app) {
    private var details: JSONObject? = null
    private var showPast = false

    override fun LinearLayout.build() {
        val f = Vault.find(fileId)
        if (f == null) {
            header("File", onBack = { app.back() })
            caption("This file is no longer in your vault.")
            return
        }
        header(f.meta.name, f.meta.category, onBack = { app.back() })
        if (f.damaged) notice("This version's details can't be read",
            "Version ${f.version} was uploaded with a name and type that can't be decrypted, so they may have been changed on purpose. " +
                "Restore an earlier version below, or rename the file. Your other files are not affected.", dark = false)
        card(10, 16) {
            row(12) {
                iconBox(R.drawable.ic_lock, C.INK, Color.WHITE)
                column(2, w = 0, weight = 1f) {
                    text("Encrypted", 16f, bold = true)
                    caption("Encrypted on your phone. Only you hold the key.")
                }
            }
            kv("Owner", "You")
            details?.let { kv("Uploaded", Fmt.date(it.getLong("createdAt"))) }
            kv("Size", Fmt.size(f.size))
            kv("Version", "v${f.version}")
        }
        row(10) {
            button("Open", Btn.OUTLINE, w = 0, weight = 1f) { openOwn(app, f) }
            button("Share file", w = 0, weight = 1f) { app.push(ShareScreen(app, f.id)) }
        }

        val d = details
        val shares = d?.getJSONArray("shares")?.objects() ?: emptyList()
        val active = shares.filter { it.getString("status") == "active" }
        text("Who has access?", 17f, bold = true)
        when {
            d == null -> caption("Loading…")
            active.isEmpty() -> caption("Only you. Share it to give someone limited access.")
            else -> caption("${active.size} active ${if (active.size == 1) "share" else "shares"}")
        }
        active.forEach { s -> shareCard(s) { revoke(s) } }
        if (active.size > 1) button("Stop sharing this file", Btn.DANGER) {
            app.confirm("Stop sharing ${f.meta.name}?", "All ${active.size} people lose access right away.", "Stop sharing") {
                task("Removing access…", work = { Sharing.revokeAll(f.id) }) { onShow() }
            }
        }
        val past = shares - active.toSet()
        if (past.isNotEmpty()) {
            pillButton(if (showPast) "Hide past shares" else "Show past shares (${past.size})") { showPast = !showPast; rerender() }
            if (showPast) past.forEach { shareCard(it, null) }
        }

        val versions = d?.getJSONArray("versions")?.objects() ?: emptyList()
        if (versions.size > 1) {
            text("Versions", 17f, bold = true)
            versions.forEach { v ->
                val n = v.getInt("version")
                card(6, 14) {
                    row(10) {
                        column(2, w = 0, weight = 1f) {
                            text("Version $n · ${Fmt.size(v.getLong("size"))}", 15f, bold = true)
                            caption("By ${if (v.optString("uploadedBy") == Session.email) "you" else v.optString("uploadedBy", "someone")} · ${Fmt.ago(v.getLong("createdAt"))}")
                        }
                        pillButton("Open") { openOwn(app, f, n, v.getLong("size")) }
                        if (n == f.version) pill("Current") else pillButton("Restore", dark = true) {
                            app.confirm("Restore version $n?", "It becomes the current version. Newer versions are kept.", "Restore") {
                                task("Restoring…", work = { Api.post("/files/$fileId/restore", JSONObject().put("version", n)); Vault.refresh() }) { onShow() }
                            }
                        }
                    }
                }
            }
        }

        row(10) {
            button("Rename", Btn.OUTLINE, w = 0, weight = 1f) { rename(app, f) { onShow() } }
            button("Category", Btn.OUTLINE, w = 0, weight = 1f) {
                app.choose("Category", Vault.CATEGORIES) { i ->
                    task("Saving…", work = { Vault.updateMeta(f, f.meta.copy(category = Vault.CATEGORIES[i])); Vault.refresh() }) { rerender() }
                }
            }
        }
        button("Delete file", Btn.DANGER) { deleteFile(app, f) { app.back() } }
    }

    private fun LinearLayout.shareCard(s: JSONObject, onRevoke: (() -> Unit)?) = card(6, 14) {
        row(12) {
            avatar(s.getString("email"))
            column(2, w = 0, weight = 1f) {
                text(s.getString("email"), 15f, bold = true) { maxLines = 1; ellipsize = TextUtils.TruncateAt.END }
                val status = s.getString("status")
                caption("${Fmt.perm(s.getString("perm"))} · ${if (status == "active") "ends in ${Fmt.left(s.getLong("expiresAt"))}" else Fmt.status(status)}")
                caption("Opens: ${s.getInt("opensUsed")} of ${s.getInt("maxOpens")}${if (s.optBoolean("hasPass")) " · passphrase" else ""}")
            }
            if (onRevoke != null) pillButton("Remove", dark = true) { onRevoke() }
        }
    }

    private fun revoke(s: JSONObject) {
        val name = Vault.find(fileId)?.meta?.name ?: "this file"
        app.confirm("Remove ${s.getString("email")}'s access?",
            "They won't be able to open $name any more. Copies they already saved can't be removed.", "Remove access") {
            task("Removing access…", work = { Sharing.revoke(s.getString("id")) }) { app.snack("Access removed."); onShow() }
        }
    }

    override fun onShow() {
        task(null, work = { Api.get("/files/$fileId") }) { details = it; rerender() }
    }
}

/** Plays a video straight from memory: the decrypted bytes are never written to storage. */
private class BytesSource(private val b: ByteArray) : MediaDataSource() {
    override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
        if (position >= b.size) return -1
        val n = minOf(size, (b.size - position).toInt())
        System.arraycopy(b, position.toInt(), buffer, offset, n)
        return n
    }
    override fun getSize() = b.size.toLong()
    override fun close() {}
}

/**
 * Shows a decrypted file. The type comes from the file's first bytes, never from its name, and
 * only safe built-in renderers are used (PdfRenderer, BitmapFactory, TextView, MediaPlayer).
 * Screenshots are blocked by FLAG_SECURE, and recipients see a watermark with their email.
 */
class ViewerScreen(
    app: MainActivity, private val meta: Meta, var data: ByteArray, private val subtitle: String,
    private val watermark: String?, private val actions: List<Pair<String, () -> Unit>>,
) : Screen(app) {
    override val scrolls = false
    private val kind = FileType.sniff(data)
    private var pdf: PdfRenderer? = null
    private var pfd: ParcelFileDescriptor? = null
    private var bitmap: Bitmap? = null
    private var player: MediaPlayer? = null

    override fun LinearLayout.build() {
        header(meta.name, subtitle, onBack = { app.back() })
        val frame = add(FrameLayout(context), MATCH, 0, 1f) {
            background = shape(C.CARD, dpf(18f), C.LINE, dp(1))
            clipToOutline = true
        }
        var pager: LinearLayout? = null
        when (kind) {
            Preview.PDF -> pager = showPdf(frame)
            Preview.IMAGE -> showImage(frame)
            Preview.TEXT -> showText(frame)
            Preview.VIDEO -> showVideo(frame)
            Preview.OTHER -> message(frame, "Preview isn't available for this kind of file.")
        }
        if (watermark != null) frame.add(Watermark(context, watermark), MATCH, MATCH)
        pager?.let { addView(it) }
        caption("${kind.label} · ${Fmt.size(data.size.toLong())} · screenshots are blocked in VaultSpace")
        actions.forEach { (label, fn) -> button(label, Btn.OUTLINE) { fn() } }
    }

    private fun message(frame: FrameLayout, msg: String) = frame.text(msg, 15f, C.MUTED) {
        (layoutParams as FrameLayout.LayoutParams).gravity = Gravity.CENTER
        gravity = Gravity.CENTER
        setPadding(dp(24), dp(24), dp(24), dp(24))
    }

    // PdfRenderer needs a file descriptor. On Android 11+ we use an in-memory file (memfd), so the
    // decrypted PDF never touches storage. On older phones a temp file is deleted right after opening.
    private fun pdfDescriptor(): ParcelFileDescriptor {
        if (Build.VERSION.SDK_INT >= 30) {
            val fd = Os.memfd_create("vs-view", 0)
            var off = 0
            while (off < data.size) off += Os.write(fd, data, off, data.size - off)
            Os.lseek(fd, 0, OsConstants.SEEK_SET)
            return ParcelFileDescriptor.dup(fd).also { Os.close(fd) }
        }
        val tmp = File.createTempFile("vs", null, app.cacheDir)
        tmp.writeBytes(data)
        return ParcelFileDescriptor.open(tmp, ParcelFileDescriptor.MODE_READ_ONLY).also { tmp.delete() }
    }

    private fun showPdf(frame: FrameLayout): LinearLayout? {
        val renderer = try {
            pfd = pdfDescriptor()
            PdfRenderer(pfd!!).also { pdf = it }
        } catch (e: Exception) {
            message(frame, "This PDF can't be shown. It may be damaged.")
            return null
        }
        val image = ImageView(app).apply { adjustViewBounds = true; contentDescription = "PDF page" }
        frame.add(ScrollView(app), MATCH, MATCH) { addView(image) }
        val pager = LinearLayout(app).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            gap(dp(10))
        }
        lateinit var label: TextView
        var page = 0
        fun show(i: Int) {
            page = i
            renderer.openPage(i).use { p ->
                val w = minOf(1600, app.resources.displayMetrics.widthPixels)
                val h = (w.toLong() * p.height / maxOf(1, p.width)).toInt().coerceIn(1, 4000)
                val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
                bmp.eraseColor(Color.WHITE)
                p.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                image.setImageBitmap(bmp)
                bitmap?.recycle()
                bitmap = bmp
            }
            label.text = "Page ${i + 1} of ${renderer.pageCount}"
        }
        pager.pillButton("‹ Previous") { if (page > 0) show(page - 1) }
        label = pager.text("", 14f, C.MUTED, w = 0, weight = 1f) { gravity = Gravity.CENTER }
        pager.pillButton("Next ›") { if (page < renderer.pageCount - 1) show(page + 1) }
        if (renderer.pageCount > 0) show(0)
        return pager
    }

    // Decodes the size first and samples big images down, so a huge image can't exhaust memory.
    private fun showImage(frame: FrameLayout) {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(data, 0, data.size, bounds)
        var sample = 1
        while (bounds.outWidth / sample > 2048 || bounds.outHeight / sample > 2048) sample *= 2
        val bmp = BitmapFactory.decodeByteArray(data, 0, data.size, BitmapFactory.Options().apply { inSampleSize = sample })
        if (bmp == null) {
            message(frame, "This image can't be shown.")
            return
        }
        bitmap = bmp
        frame.add(ImageView(app), MATCH, MATCH) {
            setImageBitmap(bmp)
            scaleType = ImageView.ScaleType.FIT_CENTER
            contentDescription = meta.name
        }
    }

    private fun showText(frame: FrameLayout) {
        val limit = 200_000
        val body = String(data, 0, minOf(data.size, limit), Charsets.UTF_8) + if (data.size > limit) "\n\n[Only the first 200 KB is shown]" else ""
        frame.add(ScrollView(app), MATCH, MATCH) {
            add(TextView(app), MATCH, WRAP) {
                text = body
                textSize = 13f
                typeface = Typeface.MONOSPACE
                setTextColor(C.INK)
                setPadding(dp(16), dp(16), dp(16), dp(16))
                setTextIsSelectable(false)
            }
        }
    }

    private fun showVideo(frame: FrameLayout) {
        val surface = frame.add(SurfaceView(app), MATCH, MATCH) {
            contentDescription = "Video. Tap to pause or play."
            if (BuildConfig.SECURE_SCREEN) setSecure(true)   // video frames live in their own surface: block capture there too
        }
        surface.holder.addCallback(object : SurfaceHolder.Callback {
            override fun surfaceCreated(h: SurfaceHolder) {
                player = MediaPlayer().apply {
                    setDataSource(BytesSource(data))
                    setDisplay(h)
                    setOnVideoSizeChangedListener { _, w, ht ->
                        if (w == 0 || ht == 0) return@setOnVideoSizeChangedListener
                        val scale = minOf(frame.width.toFloat() / w, frame.height.toFloat() / ht)
                        surface.layoutParams = FrameLayout.LayoutParams((w * scale).toInt(), (ht * scale).toInt(), Gravity.CENTER)
                    }
                    setOnPreparedListener { start() }
                    setOnErrorListener { _, _, _ -> app.snack("This video can't be played."); true }
                    prepareAsync()
                }
            }
            override fun surfaceChanged(h: SurfaceHolder, f: Int, w: Int, ht: Int) {}
            override fun surfaceDestroyed(h: SurfaceHolder) {
                player?.release()
                player = null
            }
        })
        surface.setOnClickListener { player?.let { if (it.isPlaying) it.pause() else it.start() } }
    }

    // Leaving the viewer wipes the decrypted bytes and frees every renderer.
    override fun onClose() {
        player?.release()
        player = null
        runCatching { pdf?.close() }
        runCatching { pfd?.close() }
        bitmap?.recycle()
        data.fill(0)
    }
}
