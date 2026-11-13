/**
 * @file jni_bridge.cpp
 * @summary JNI Bridge exposing Native C++ Security Primitives to Kotlin/Android.
 */

#include <jni.h>
#include <string>
#include <sstream>

#include "security_core.h"
#include "secure_memory.h"

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_ghosttag_security_SecurityBridgeModule_nativeCheckIntegrity(
    JNIEnv *env,
    jobject /* thiz */) {
    ghosttag::IntegrityReport report = ghosttag::SecurityCore::checkIntegrity();

    std::ostringstream json;
    json << "{";
    json << "\"isSecure\":" << (report.is_secure ? "true" : "false") << ",";
    json << "\"isDebuggerActive\":" << (report.is_debugger_active ? "true" : "false") << ",";
    json << "\"isHooked\":" << (report.is_hooked ? "true" : "false") << ",";
    json << "\"isRooted\":" << (report.is_rooted ? "true" : "false") << ",";
    json << "\"isEmulator\":" << (report.is_emulator ? "true" : "false") << ",";
    json << "\"isSignatureValid\":" << (report.is_signature_valid ? "true" : "false") << ",";
    json << "\"indicators\":[";
    for (size_t i = 0; i < report.indicators.size(); ++i) {
        json << "\"" << report.indicators[i] << "\"";
        if (i + 1 < report.indicators.size()) {
            json << ",";
        }
    }
    json << "]}";

    return env->NewStringUTF(json.str().c_str());
}

JNIEXPORT jboolean JNICALL
Java_com_ghosttag_security_SecurityBridgeModule_nativeIsDebuggerActive(
    JNIEnv * /* env */,
    jobject /* thiz */) {
    return static_cast<jboolean>(ghosttag::SecurityCore::isDebuggerAttached());
}

JNIEXPORT jboolean JNICALL
Java_com_ghosttag_security_SecurityBridgeModule_nativeIsHooked(
    JNIEnv * /* env */,
    jobject /* thiz */) {
    return static_cast<jboolean>(ghosttag::SecurityCore::isHookingDetected());
}

JNIEXPORT jboolean JNICALL
Java_com_ghosttag_security_SecurityBridgeModule_nativeIsRooted(
    JNIEnv * /* env */,
    jobject /* thiz */) {
    return static_cast<jboolean>(ghosttag::SecurityCore::isRootDetected());
}

JNIEXPORT jboolean JNICALL
Java_com_ghosttag_security_SecurityBridgeModule_nativeWipeBuffer(
    JNIEnv *env,
    jobject /* thiz */,
    jbyteArray buffer) {
    if (!buffer) {
        return JNI_FALSE;
    }

    jsize len = env->GetArrayLength(buffer);
    if (len <= 0) {
        return JNI_TRUE;
    }

    jbyte *bytes = env->GetByteArrayElements(buffer, nullptr);
    if (bytes) {
        ghosttag::SecureMemory::wipeBuffer(bytes, static_cast<size_t>(len));
        env->ReleaseByteArrayElements(buffer, bytes, 0);
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

} // extern "C"

