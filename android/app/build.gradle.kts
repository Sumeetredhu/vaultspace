import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing details live in keystore.properties, which is never committed.
val signing = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "com.vaultspace.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.vaultspace.app"
        minSdk = 28            // Android 9: framework BiometricPrompt and modern Keystore
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
        buildConfigField("String", "SERVER_URL", "\"${providers.gradleProperty("vsServer").get()}\"")
        // Screenshot blocking. Only a local test build may turn it off (-PvsSecure=false) so the
        // team can take screenshots for the user guide; release builds always force it on.
        buildConfigField("boolean", "SECURE_SCREEN", providers.gradleProperty("vsSecure").getOrElse("true"))
    }

    signingConfigs {
        if (signing.getProperty("storeFile") != null) create("release") {
            storeFile = rootProject.file(signing.getProperty("storeFile"))
            storePassword = signing.getProperty("storePassword")
            keyAlias = signing.getProperty("keyAlias")
            keyPassword = signing.getProperty("keyPassword")
        }
    }

    buildTypes {
        debug {
            buildConfigField("String", "SERVER_URL", "\"${providers.gradleProperty("vsDevServer").get()}\"")
        }
        release {
            isMinifyEnabled = true      // R8 shrinks and obfuscates the release APK
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
            buildConfigField("boolean", "SECURE_SCREEN", "true")
        }
    }

    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

// No dependencies: networking, JSON, crypto, biometrics, PDF rendering and the UI all come
// from the Android framework itself.
dependencies { }
