package com.vaultspace.app

import android.os.Build
import org.json.JSONObject
import java.net.URL
import java.net.URLEncoder
import javax.net.ssl.HttpsURLConnection

class ApiError(val status: Int, message: String, val body: JSONObject = JSONObject()) : Exception(message)

/**
 * HTTPS client for the VaultSpace server. HttpsURLConnection uses the app's network security
 * config, so it only accepts our pinned server certificate. Casting to HttpsURLConnection also
 * means a misconfigured http:// address fails instead of sending data in the clear.
 */
object Api {
    private val base = BuildConfig.SERVER_URL.trimEnd('/')
    // ASCII only: HTTP headers cannot carry characters like "·".
    private val device = "${Build.MANUFACTURER} ${Build.MODEL} (Android ${Build.VERSION.RELEASE})".filter { it.code in 32..126 }.take(60)

    fun get(path: String) = json("GET", path, null)
    fun post(path: String, body: JSONObject = JSONObject(), headers: Map<String, String> = emptyMap()) = json("POST", path, body, headers)
    fun delete(path: String) = json("DELETE", path, null)
    fun upload(path: String, data: ByteArray) = request("PUT", path, data, "application/octet-stream")
    fun download(path: String, headers: Map<String, String> = emptyMap()) = request("GET", path, null, null, headers)
    fun q(s: String): String = URLEncoder.encode(s, "UTF-8")

    /** Ends a session on the server after the app has already forgotten it locally. */
    fun logout(token: String) = request("POST", "/auth/logout", "{}".toByteArray(), "application/json", mapOf("Authorization" to "Bearer $token"))

    private fun json(method: String, path: String, body: JSONObject?, headers: Map<String, String> = emptyMap()): JSONObject {
        val bytes = request(method, path, body?.toString()?.toByteArray(), if (body != null) "application/json" else null, headers)
        return if (bytes.isEmpty()) JSONObject() else JSONObject(String(bytes))
    }

    private fun request(method: String, path: String, data: ByteArray?, type: String?, headers: Map<String, String> = emptyMap()): ByteArray {
        val conn = URL(base + path).openConnection() as HttpsURLConnection
        try {
            conn.requestMethod = method
            conn.connectTimeout = 15_000
            conn.readTimeout = 60_000
            conn.useCaches = false
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("Accept", "application/json")
            // A fresh connection for every request. Reusing a pooled one fails if the server already
            // closed it (idle for more than 5 s, e.g. while the user reads an email code), and Android
            // can't retry a streamed POST, so the user would see "can't reach" for no real reason.
            conn.setRequestProperty("Connection", "close")
            conn.setRequestProperty("X-Device", device)
            Session.token?.let { conn.setRequestProperty("Authorization", "Bearer $it") }
            headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
            if (data != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", type)
                conn.setFixedLengthStreamingMode(data.size)
                conn.outputStream.use { it.write(data) }
            }
            val code = conn.responseCode
            val bytes = (if (code >= 400) conn.errorStream else conn.inputStream)?.use { it.readBytes() } ?: ByteArray(0)
            if (code >= 400) {
                val body = runCatching { JSONObject(String(bytes)) }.getOrDefault(JSONObject())
                throw ApiError(code, body.optString("error", "Request failed ($code)."), body)
            }
            return bytes
        } finally {
            conn.disconnect()
        }
    }
}
