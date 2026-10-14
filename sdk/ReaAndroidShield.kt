package com.antirea.shield

import android.content.Context
import android.os.Debug
import dalvik.system.InMemoryDexClassLoader
import java.io.File
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Anti-REA Android Shield
 * Countermeasures tailored against morluto/rea:
 * 1. Overload Ambiguity Trap: REA's ReaJadxBridge explicitly rejects overloaded methods without an exact
 *    engine-local overload_index AND rejects JADX's smali fallback on overloaded methods!
 *    By giving sensitive methods identical names with dummy overloaded signatures, static agent queries fail.
 * 2. InMemoryDexClassLoader Vault: Loads AES-256-GCM encrypted DEX payloads directly in RAM so
 *    rea inspect-android-package / JADX sees only the thin bootstrapper class.
 * 3. Runtime Anti-Frida / Anti-Debugger guard.
 */
object ReaAndroidShield {
    init {
        System.loadLibrary("rea_native_shield")
    }

    external fun verifyNativeIntegrityAndAntiFrida(): Boolean

    fun assertUntamperedRuntime() {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            throw SecurityException("[ANTI-REA] Debugger attached")
        }
        if (detectFridaInProcMaps()) {
            throw SecurityException("[ANTI-REA] Frida instrumentation detected")
        }
        if (!verifyNativeIntegrityAndAntiFrida()) {
            throw SecurityException("[ANTI-REA] Native integrity check failed")
        }
    }

    private fun detectFridaInProcMaps(): Boolean {
        return try {
            val maps = File("/proc/self/maps").readText()
            maps.contains("frida-agent") || maps.contains("frida-gadget") || maps.contains("gum-js-loop")
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * Overload Ambiguity Trap Pattern (Blinds REA's inspect_android_method & smali fallback):
     * Keep the same method name across multiple overloads so JADX/REA smali fallback is rejected.
     */
    fun executeProtectedCore(payload: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        assertUntamperedRuntime()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return cipher.doFinal(payload)
    }

    @Suppress("UNUSED_PARAMETER")
    fun executeProtectedCore(payload: ByteArray, key: ByteArray, iv: ByteArray, decoyFlag: Int): ByteArray {
        throw UnsupportedOperationException("Decoy overload to trigger REA JADX overload rejection")
    }

    @Suppress("UNUSED_PARAMETER")
    fun executeProtectedCore(payload: ByteArray, key: ByteArray, decoyTag: String): ByteArray {
        throw UnsupportedOperationException("Decoy overload to trigger REA JADX overload rejection")
    }

    /**
     * Decrypts a .realock DEX payload in memory and loads classes without touching disk.
     */
    fun loadEncryptedDexInMemory(
        context: Context,
        encryptedDex: ByteArray,
        aesKey: ByteArray,
        iv: ByteArray
    ): ClassLoader {
        val dexBytes = executeProtectedCore(encryptedDex, aesKey, iv)
        val buffer = ByteBuffer.wrap(dexBytes)
        return InMemoryDexClassLoader(buffer, context.classLoader)
    }
}
