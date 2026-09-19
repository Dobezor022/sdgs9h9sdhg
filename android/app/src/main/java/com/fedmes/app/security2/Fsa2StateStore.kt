package com.fedmes.app.security2

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Encrypted-at-rest local store for FSA2 identity/trust/ratchet state. */
class Fsa2StateStore(context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "fedmes/fsa2/state.v1"))

    @Synchronized fun write(json: ByteArray) {
        require(json.isNotEmpty() && json.size <= MAX_STATE)
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val ciphertext = cipher.doFinal(json)
        val out = ByteArray(1 + cipher.iv.size + ciphertext.size)
        out[0] = cipher.iv.size.toByte(); cipher.iv.copyInto(out, 1); ciphertext.copyInto(out, 1 + cipher.iv.size)
        val stream = file.startWrite()
        try { stream.write(out); stream.fd.sync(); file.finishWrite(stream) }
        catch (t: Throwable) { file.failWrite(stream); throw t }
        finally { ciphertext.fill(0); out.fill(0) }
    }

    @Synchronized fun read(): ByteArray? {
        val raw = try { file.openRead().use { it.readBytes() } } catch (_: java.io.FileNotFoundException) { return null }
        require(raw.size in 30..(MAX_STATE + 64))
        val n = raw[0].toInt() and 0xff; require(n in 12..16 && raw.size > 1+n+16)
        val iv = raw.copyOfRange(1,1+n); val ct = raw.copyOfRange(1+n,raw.size)
        return try { val c=Cipher.getInstance(TRANSFORM);c.init(Cipher.DECRYPT_MODE,key(),GCMParameterSpec(128,iv));c.doFinal(ct) }
        finally { raw.fill(0);iv.fill(0);ct.fill(0) }
    }

    @Synchronized fun clear(){ file.delete() }

    private fun key(): SecretKey = synchronized(lock) {
        val ks=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
        (ks.getKey(ALIAS,null) as? SecretKey) ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore").run {
            init(KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setUnlockedDeviceRequired(true).setUserAuthenticationRequired(false).build());generateKey()
        }
    }

    private companion object { const val ALIAS="fedmes.fsa2.v1";const val TRANSFORM="AES/GCM/NoPadding";const val MAX_STATE=4*1024*1024;val lock=Any() }
}
