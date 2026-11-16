package com.vaultspace.app

import android.content.Context
import android.content.SharedPreferences
import android.net.Uri
import android.provider.OpenableColumns
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.PrivateKey

fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }

/** Removes control and invisible/bidi characters (e.g. U+202E, which can show "fdp.exe" as "exe.pdf"). */
fun cleanName(s: String) =
    s.replace(Regex("[\\p{Cntrl}\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u206F\\uFEFF]"), "").trim().take(120).ifEmpty { "Untitled" }

/** Who is logged in, and their keys. Lives only in memory: locking or closing the app wipes it. */
object Session {
    @Volatile var token: String? = null
    var account = JSONObject()
    var vaultKey: ByteArray? = null
    var privateKey: PrivateKey? = null
    var publicKey = ""
    val email: String get() = account.optString("email")
    val name: String get() = account.optString("name")
    val isOpen get() = token != null && vaultKey != null
    val vault: ByteArray get() = vaultKey ?: throw IllegalStateException("The vault is locked.")

    fun start(payload: JSONObject, vault: ByteArray) {
        val keys = payload.getJSONObject("keys")
        privateKey = Crypto.privateKey(Crypto.open(vault, Crypto.unb64(keys.getString("privByVault")), "vs-priv"))
        publicKey = keys.getString("pubKey")
        account = payload.getJSONObject("account")
        vaultKey = vault
        token = payload.getString("token")
    }

    fun end() {
        vaultKey?.fill(0)
        vaultKey = null
        privateKey = null
        token = null
        account = JSONObject()
        Vault.files.forEach { it.key.fill(0) }
        Vault.files = emptyList()
    }
}

/** Small, non-secret settings in app-private storage. The device-unlock blob is encrypted by the Keystore. */
object Prefs {
    private lateinit var sp: SharedPreferences
    fun init(ctx: Context) { sp = ctx.getSharedPreferences("vaultspace", Context.MODE_PRIVATE) }
    var email: String
        get() = sp.getString("email", "") ?: ""
        set(v) = sp.edit().putString("email", v).apply()
    var deviceBlob: String?
        get() = sp.getString("device", null)
        set(v) = sp.edit().putString("device", v).apply()
    var deviceId: String?
        get() = sp.getString("deviceId", null)
        set(v) = sp.edit().putString("deviceId", v).apply()
    var deviceEmail: String?          // which account the fingerprint unlock on this phone belongs to
        get() = sp.getString("deviceEmail", null)
        set(v) = sp.edit().putString("deviceEmail", v).apply()
}

/** File details that only the owner and recipients can read: stored encrypted with the file key. */
data class Meta(val name: String, val type: String, val category: String, val size: Long) {
    private fun encode() = JSONObject().put("name", name).put("type", type).put("cat", category).put("size", size).toString().toByteArray()

    companion object {
        fun seal(fileKey: ByteArray, fileId: String, m: Meta) = Crypto.b64(Crypto.seal(fileKey, m.encode(), "vs-meta|$fileId"))
        fun open(fileKey: ByteArray, fileId: String, b64: String): Meta {
            val j = JSONObject(String(Crypto.open(fileKey, Crypto.unb64(b64), "vs-meta|$fileId")))
            return Meta(cleanName(j.optString("name")), j.optString("type"), j.optString("cat", "Other"), j.optLong("size"))
        }
    }
}

class VaultFile(
    val id: String, val version: Int, val size: Long, val key: ByteArray, val meta: Meta,
    val updatedAt: Long, val activeShares: Int,
)

class Picked(val name: String, val type: String, val data: ByteArray)

/** The user's own files: listing, upload, download, rename and delete. */
object Vault {
    const val CHUNK = 1024 * 1024
    const val MAX_FILE = 50L * 1024 * 1024
    val CATEGORIES = listOf("Government IDs", "College Documents", "Bank & Finance", "Medical", "Photos", "Videos", "Work", "Other")

    @Volatile var files: List<VaultFile> = emptyList()
    var used = 0L
    var quota = 0L

    fun find(id: String?) = files.firstOrNull { it.id == id }
    fun chunkCount(size: Long) = maxOf(1, ((size + CHUNK - 1) / CHUNK).toInt())

    // Each chunk is bound to its file, version, position and "is last" flag, so the server cannot
    // reorder chunks, swap them between files, or cut a file short without decryption failing.
    private fun aad(fileId: String, version: Int, i: Int, last: Boolean) = "vs-chunk|$fileId|$version|$i|${if (last) 1 else 0}"

    fun refresh() {
        val r = Api.get("/files")
        val vault = Session.vault
        files = r.getJSONArray("files").objects().map { f ->
            val id = f.getString("id")
            val key = Crypto.open(vault, Crypto.unb64(f.getString("keyByVault")), "vs-fkey|$id")
            VaultFile(id, f.getInt("version"), f.getLong("size"), key, Meta.open(key, id, f.getString("meta")),
                f.getLong("updatedAt"), f.getInt("activeShares"))
        }
        used = r.getLong("used")
        quota = r.getLong("quota")
    }

    fun encryptChunks(data: ByteArray, key: ByteArray, fileId: String, version: Int, put: (Int, ByteArray) -> Unit, progress: (Int) -> Unit) {
        val n = chunkCount(data.size.toLong())
        for (i in 0 until n) {
            val from = i * CHUNK
            put(i, Crypto.seal(key, data.copyOfRange(from, minOf(data.size, from + CHUNK)), aad(fileId, version, i, i == n - 1)))
            progress((i + 1) * 100 / n)
        }
    }

    fun decryptChunks(fileId: String, version: Int, size: Long, key: ByteArray, fetch: (Int) -> ByteArray, progress: (Int) -> Unit): ByteArray {
        val n = chunkCount(size)
        val out = ByteArrayOutputStream(size.toInt())
        for (i in 0 until n) {
            out.write(Crypto.open(key, fetch(i), aad(fileId, version, i, i == n - 1)))
            progress((i + 1) * 100 / n)
        }
        return out.toByteArray().also { if (it.size.toLong() != size) throw TamperedException() }
    }

    fun upload(p: Picked, category: String, progress: (Int) -> Unit) {
        val id = Api.post("/files", JSONObject().put("size", p.data.size)).getString("id")
        val key = Crypto.random(32)
        encryptChunks(p.data, key, id, 1, { i, c -> Api.upload("/files/$id/v/1/$i", c) }, progress)
        Api.post("/files/$id/v/1/commit", JSONObject()
            .put("meta", Meta.seal(key, id, Meta(p.name, p.type, category, p.data.size.toLong())))
            .put("keyByVault", Crypto.b64(Crypto.seal(Session.vault, key, "vs-fkey|$id"))))
    }

    fun read(f: VaultFile, version: Int = f.version, size: Long = f.size, progress: (Int) -> Unit = {}) =
        decryptChunks(f.id, version, size, f.key, { i -> Api.download("/files/${f.id}/v/$version/$i") }, progress)

    fun updateMeta(f: VaultFile, m: Meta) = Api.post("/files/${f.id}/meta", JSONObject().put("meta", Meta.seal(f.key, f.id, m)))
    fun delete(f: VaultFile) = Api.delete("/files/${f.id}")

    /** Reads a file the user picked, refusing anything over 50 MB while reading (not trusting the reported size). */
    fun readPicked(ctx: Context, uri: Uri): Picked {
        val cr = ctx.contentResolver
        var name = "Untitled"
        cr.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { if (it.moveToFirst()) name = it.getString(0) ?: name }
        val out = ByteArrayOutputStream()
        cr.openInputStream(uri)?.use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                if (out.size() + n > MAX_FILE) throw IllegalArgumentException("Files can be at most 50 MB.")
                out.write(buf, 0, n)
            }
        } ?: throw IllegalArgumentException("Could not read that file.")
        return Picked(cleanName(name), cr.getType(uri) ?: "application/octet-stream", out.toByteArray())
    }
}

/** A share someone sent me. File name and key are only visible when there is no passphrase. */
class Incoming(j: JSONObject) {
    val id: String = j.getString("id")
    val fileId: String = j.getString("fileId")
    val fromName: String = cleanName(j.getJSONObject("from").optString("name"))
    val fromEmail: String = j.getJSONObject("from").optString("email")
    val perm: String = j.getString("perm")
    val expiresAt = j.getLong("expiresAt")
    val maxOpens = j.getInt("maxOpens")
    val opensUsed = j.getInt("opensUsed")
    val status: String = j.getString("status")
    val size = j.optLong("size")
    val hasPass = j.optBoolean("hasPass")
    val passSalt: String = j.optString("passSalt")
    val opensLeft get() = maxOf(0, maxOpens - opensUsed)
    // Anyone can choose any display name, so the verified email is always shown next to it:
    // a file "from Prof. Sharma" sent by a stranger still shows the stranger's address.
    val sender get() = "$fromName ($fromEmail)"
    var meta: Meta? = null
}

/** A share that was just opened: decrypted bytes stay in memory only. */
class Opened(val share: Incoming, val meta: Meta, var data: ByteArray, val key: ByteArray, val token: String, val perm: String, val opensLeft: Int)

object Sharing {
    fun lookup(email: String) = Api.get("/users/key?email=${Api.q(email)}")

    fun create(f: VaultFile, recipient: JSONObject, perm: String, expiresIn: Int, maxOpens: Int, notify: Boolean, passphrase: String): JSONObject {
        var (ephPub, wrapped) = Crypto.wrapFor(Crypto.unb64(recipient.getString("pubKey")), f.key, f.id)
        val body = JSONObject().put("recipientId", recipient.getString("userId")).put("perm", perm)
            .put("expiresIn", expiresIn).put("maxOpens", maxOpens).put("notify", notify).put("ephPub", ephPub)
        if (passphrase.isNotEmpty()) {
            // Second lock on top of the recipient's key: the passphrase is checked by the server
            // (5 tries) and also needed to decrypt, so the server alone cannot open it either.
            val salt = Crypto.random(16)
            val pk = Crypto.passphraseKeys(passphrase, salt)
            wrapped = Crypto.seal(pk.kek, wrapped, "vs-pass")
            body.put("pass", JSONObject().put("salt", Crypto.b64(salt)).put("auth", Crypto.b64(pk.auth)))
        }
        return Api.post("/files/${f.id}/shares", body.put("wrappedKey", Crypto.b64(wrapped)))
    }

    fun outgoing() = Api.get("/shares/out").getJSONArray("shares").objects()

    fun incoming(): List<Incoming> = Api.get("/shares/in").getJSONArray("shares").objects().map { j ->
        Incoming(j).also { s ->
            if (!j.isNull("wrappedKey")) runCatching {
                val key = Crypto.unwrapFrom(Session.privateKey!!, j.getString("ephPub"), Crypto.unb64(j.getString("wrappedKey")), s.fileId)
                s.meta = Meta.open(key, s.fileId, j.getString("meta"))
            }
        }
    }

    fun revoke(id: String) = Api.delete("/shares/$id")
    fun revokeAll(fileId: String? = null) = Api.post("/shares/revoke-all", JSONObject().apply { if (fileId != null) put("fileId", fileId) })

    fun open(s: Incoming, passphrase: String?, progress: (Int) -> Unit): Opened {
        val body = JSONObject()
        val pk = if (s.hasPass) Crypto.passphraseKeys(passphrase ?: "", Crypto.unb64(s.passSalt)) else null
        if (pk != null) body.put("passAuth", Crypto.b64(pk.auth))
        val r = Api.post("/shares/${s.id}/open", body)
        var wrapped = Crypto.unb64(r.getString("wrappedKey"))
        if (pk != null) wrapped = Crypto.open(pk.kek, wrapped, "vs-pass")
        val key = Crypto.unwrapFrom(Session.privateKey!!, r.getString("ephPub"), wrapped, s.fileId)
        val meta = Meta.open(key, s.fileId, r.getString("meta"))
        val token = r.getString("openToken")
        val data = Vault.decryptChunks(s.fileId, r.getInt("version"), r.getLong("size"), key,
            { i -> Api.download("/shares/${s.id}/chunk/$i", mapOf("X-Open-Token" to token)) }, progress)
        return Opened(s, meta, data, key, token, r.getString("perm"), r.getInt("opensLeft"))
    }

    /** Asks the server for permission before saving a copy; view-only shares are refused there. */
    fun allowDownload(o: Opened) = Api.post("/shares/${o.share.id}/download", JSONObject(), mapOf("X-Open-Token" to o.token))

    fun uploadVersion(o: Opened, p: Picked, progress: (Int) -> Unit) {
        val id = o.share.id
        // The open token proves this upload follows a real open (passphrase checked, open counted).
        val version = Api.post("/shares/$id/versions", JSONObject().put("size", p.data.size), mapOf("X-Open-Token" to o.token)).getInt("version")
        Vault.encryptChunks(p.data, o.key, o.share.fileId, version, { i, c -> Api.upload("/shares/$id/v/$version/$i", c) }, progress)
        val meta = Meta(o.meta.name, p.type, o.meta.category, p.data.size.toLong())
        Api.post("/shares/$id/v/$version/commit", JSONObject().put("meta", Meta.seal(o.key, o.share.fileId, meta)))
    }
}

/** What a file really is, from its first bytes (never from its name or claimed type). */
enum class Preview(val label: String) { PDF("PDF document"), IMAGE("Image"), VIDEO("Video"), TEXT("Text"), OTHER("File") }

object FileType {
    private fun starts(b: ByteArray, at: Int, vararg sig: Int) = b.size >= at + sig.size && sig.indices.all { b[at + it] == sig[it].toByte() }

    fun sniff(b: ByteArray): Preview = when {
        starts(b, 0, 0x25, 0x50, 0x44, 0x46, 0x2D) -> Preview.PDF                       // %PDF-
        starts(b, 0, 0x89, 0x50, 0x4E, 0x47) || starts(b, 0, 0xFF, 0xD8, 0xFF) ||        // PNG, JPEG
            starts(b, 0, 0x47, 0x49, 0x46, 0x38) ||                                       // GIF8
            (starts(b, 0, 0x52, 0x49, 0x46, 0x46) && starts(b, 8, 0x57, 0x45, 0x42, 0x50)) -> Preview.IMAGE  // RIFF....WEBP
        starts(b, 4, 0x66, 0x74, 0x79, 0x70) || starts(b, 0, 0x1A, 0x45, 0xDF, 0xA3) -> Preview.VIDEO      // MP4 "ftyp", WebM
        looksLikeText(b) -> Preview.TEXT
        else -> Preview.OTHER
    }

    private fun looksLikeText(b: ByteArray): Boolean {
        val head = b.copyOf(minOf(b.size, 4096))
        if (head.any { it == 0.toByte() }) return false
        return runCatching {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(head, 0, trimPartialUtf8(head)))
        }.isSuccess
    }

    // A 4096-byte cut can split a multi-byte character; ignore up to 3 trailing continuation bytes.
    private fun trimPartialUtf8(b: ByteArray): Int {
        var end = b.size
        var back = 0
        while (back < 3 && end > 0 && (b[end - 1].toInt() and 0xC0) == 0x80) { end--; back++ }
        if (end > 0 && (b[end - 1].toInt() and 0xC0) == 0xC0) end--
        return if (b.size < 4096) b.size else end
    }
}
