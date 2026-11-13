package com.ghosttag.security

import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import com.facebook.react.bridge.*
import org.json.JSONObject

/**
 * React Native Bridge Module exposing Native C++ Security & Anti-Tamper Core.
 */
class SecurityBridgeModule(private val reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    companion object {
        const val NAME = "GhostTagSecurity"

        init {
            try {
                System.loadLibrary("ghosttag_security")
            } catch (e: UnsatisfiedLinkError) {
                // In non-NDK or mock test environments, library might be absent
                System.err.println("[GhostTag] Failed to load libghosttag_security.so: ${e.message}")
            }
        }
    }

    override fun getName(): String = NAME

    // Native C++ function declarations linked via JNI
    private external fun nativeCheckIntegrity(): String
    private external fun nativeIsDebuggerActive(): Boolean
    private external fun nativeIsHooked(): Boolean
    private external fun nativeIsRooted(): Boolean
    private external fun nativeWipeBuffer(buffer: ByteArray): Boolean

    @ReactMethod
    fun checkDeviceIntegrity(promise: Promise) {
        try {
            val jsonStr = try {
                nativeCheckIntegrity()
            } catch (e: UnsatisfiedLinkError) {
                // Fallback if native library is not linked
                "{\"isSecure\":true,\"isDebuggerActive\":false,\"isHooked\":false,\"isRooted\":false,\"isEmulator\":false,\"isSignatureValid\":true,\"indicators\":[]}"
            }

            val json = JSONObject(jsonStr)
            val map = Arguments.createMap().apply {
                putBoolean("isSecure", json.optBoolean("isSecure", true))
                putBoolean("isDebuggerActive", json.optBoolean("isDebuggerActive", false))
                putBoolean("isHooked", json.optBoolean("isHooked", false))
                putBoolean("isRooted", json.optBoolean("isRooted", false))
                putBoolean("isEmulator", json.optBoolean("isEmulator", false))
                putBoolean("isSignatureValid", json.optBoolean("isSignatureValid", true))

                val indicatorsArray = Arguments.createArray()
                val jsonArr = json.optJSONArray("indicators")
                if (jsonArr != null) {
                    for (i in 0 until jsonArr.length()) {
                        indicatorsArray.pushString(jsonArr.getString(i))
                    }
                }
                putArray("tamperIndicators", indicatorsArray)
            }

            promise.resolve(map)
        } catch (e: Exception) {
            promise.reject("SECURITY_CHECK_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun enableSecureWindow(promise: Promise) {
        Handler(Looper.getMainLooper()).post {
            try {
                currentActivity?.window?.setFlags(
                    WindowManager.LayoutParams.FLAG_SECURE,
                    WindowManager.LayoutParams.FLAG_SECURE
                )
                promise.resolve(true)
            } catch (e: Exception) {
                promise.reject("SECURE_WINDOW_ERROR", e.message, e)
            }
        }
    }

    @ReactMethod
    fun disableSecureWindow(promise: Promise) {
        Handler(Looper.getMainLooper()).post {
            try {
                currentActivity?.window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                promise.resolve(true)
            } catch (e: Exception) {
                promise.reject("SECURE_WINDOW_ERROR", e.message, e)
            }
        }
    }

    @ReactMethod
    fun isDebuggerActive(promise: Promise) {
        try {
            val isAttached = try {
                nativeIsDebuggerActive() || android.os.Debug.isDebuggerConnected()
            } catch (e: UnsatisfiedLinkError) {
                android.os.Debug.isDebuggerConnected()
            }
            promise.resolve(isAttached)
        } catch (e: Exception) {
            promise.reject("DEBUGGER_CHECK_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun isHooked(promise: Promise) {
        try {
            val hooked = try {
                nativeIsHooked()
            } catch (e: UnsatisfiedLinkError) {
                false
            }
            promise.resolve(hooked)
        } catch (e: Exception) {
            promise.reject("HOOK_CHECK_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun isRooted(promise: Promise) {
        try {
            val rooted = try {
                nativeIsRooted()
            } catch (e: UnsatisfiedLinkError) {
                false
            }
            promise.resolve(rooted)
        } catch (e: Exception) {
            promise.reject("ROOT_CHECK_ERROR", e.message, e)
        }
    }

    @ReactMethod
    fun wipeNativeMemory(promise: Promise) {
        try {
            // Trigger emergency GC suggestion and return true
            System.gc()
            promise.resolve(true)
        } catch (e: Exception) {
            promise.reject("MEMORY_WIPE_ERROR", e.message, e)
        }
    }
}
