// Build tooling only. The app itself has no library dependencies: it uses the Android framework.
plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
}
