# ---------------------------------------------------------------------------
# Ghost-Tag ProGuard / R8 Hardening Rules for React Native 0.88+
# ---------------------------------------------------------------------------

# Disable aggressive bytecode optimization and obfuscation to guarantee JNI & TurboModule integrity
-dontoptimize
-dontobfuscate
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose

# Strip debugging attributes: line numbers, local variables, source files
-renamesourcefileattribute ''
-keepattributes *Annotation*,Exceptions,InnerClasses,Signature,EnclosingMethod

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
-keepclassmembers,includedescriptorclasses class * {
    native <methods>;
}

# Official React Native & TurboModules Keep Rules
-keep,allowobfuscation @interface com.facebook.proguard.annotations.DoNotStrip
-keep @com.facebook.proguard.annotations.DoNotStrip class *
-keepclassmembers class * {
    @com.facebook.proguard.annotations.DoNotStrip *;
}
-keep @com.facebook.proguard.annotations.DoNotStripAny class * { *; }
-keep @com.facebook.jni.annotations.DoNotStrip class *
-keepclassmembers class * {
    @com.facebook.jni.annotations.DoNotStrip *;
}
-keep @com.facebook.jni.annotations.DoNotStripAny class * { *; }

-keep class * implements com.facebook.react.bridge.JavaScriptModule { *; }
-keep class * implements com.facebook.react.bridge.NativeModule { *; }
-keep class * implements com.facebook.react.turbomodule.core.interfaces.TurboModule { *; }
-keep class * extends com.facebook.react.bridge.BaseJavaModule { *; }
-keep class * extends com.facebook.react.bridge.ReactContextBaseJavaModule { *; }
-keepclassmembers class * { @com.facebook.react.uimanager.annotations.ReactProp <methods>; }
-keepclassmembers class * { @com.facebook.react.uimanager.annotations.ReactPropGroup <methods>; }

-dontwarn com.facebook.react.**
-keep,includedescriptorclasses class com.facebook.react.** { *; }
-keep,includedescriptorclasses class com.facebook.jni.** { *; }
-keep,includedescriptorclasses class com.facebook.fbreact.specs.** { *; }
-keep,includedescriptorclasses class com.facebook.react.bridge.** { *; }
-keep,includedescriptorclasses class com.facebook.react.turbomodule.core.** { *; }
-keep,includedescriptorclasses class com.facebook.react.internal.turbomodule.core.** { *; }
-keep,includedescriptorclasses class com.facebook.react.defaults.** { *; }
-keep,includedescriptorclasses class com.facebook.react.uimanager.** { *; }
-keep,includedescriptorclasses class com.facebook.soloader.** { *; }
-keep,includedescriptorclasses class com.facebook.hermes.** { *; }

# Ghost-Tag Native & Security Components
-keep class com.ghosttag.MainApplication { *; }
-keep class com.ghosttag.MainActivity { *; }
-keep class com.ghosttag.security.** { *; }
-keep class com.ghosttag.** { *; }

# 3rd-Party React Native Libraries
-keep class com.swmansion.rnscreens.** { *; }
-keep class com.th3rdwave.safeareacontext.** { *; }
-keep class com.quickcrypto.** { *; }
-keep class com.tencent.mmkv.** { *; }
-keep class com.margelo.nitro.** { *; }
-keep class community.revteltech.nfc.** { *; }
-keep class com.lambdapioneer.argon2kt.** { *; }
-keep class com.oblador.keychain.** { *; }

-dontwarn com.swmansion.rnscreens.**
-dontwarn com.th3rdwave.safeareacontext.**
-dontwarn com.quickcrypto.**
-dontwarn com.tencent.mmkv.**
-dontwarn com.margelo.nitro.**
-dontwarn community.revteltech.nfc.**
-dontwarn com.lambdapioneer.argon2kt.**
-dontwarn com.oblador.keychain.**
