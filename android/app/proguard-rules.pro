# ---------------------------------------------------------------------------
# Ghost-Tag Strict ProGuard / R8 Obfuscation & Hardening Rules
# ---------------------------------------------------------------------------

# Flatten obfuscated packages to hinder reverse-engineering directory analysis
-repackageclasses 'com.ghosttag.obf'
-allowaccessmodification

# Optimization passes
-optimizationpasses 5
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose

# Strip debugging attributes: line numbers, local variables, source files
-renamesourcefileattribute ''
-keepattributes Exceptions,InnerClasses,Signature

# Strip logging calls across release builds to prevent credential/hash leaks
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
}

-assumenosideeffects class java.io.PrintStream {
    public void println(...);
    public void print(...);
}

# Preserve native JNI methods and symbols
-keepclasseswithmembernames class * {
    native <methods>;
}

# Preserve React Native entrypoints and bridge reflection
-keep class com.facebook.react.** { *; }
-keep class com.facebook.jni.** { *; }
-keep class com.ghosttag.MainApplication { *; }
-keep class com.ghosttag.MainActivity { *; }
-keep class com.ghosttag.security.SecurityBridgeModule { *; }
-keep class com.ghosttag.security.SecurityPackage { *; }
-keep class com.ghosttag.security.KeyStoreMasterKey { *; }

# Keep React Native annotations
-keepclassmembers class * {
    @com.facebook.react.bridge.ReactMethod *;
    @com.facebook.react.bridge.ReactContextBaseJavaModule *;
}
