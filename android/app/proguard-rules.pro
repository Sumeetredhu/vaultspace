# Strip all android.util.Log calls from the release build, so nothing can leak into logcat.
-assumenosideeffects class android.util.Log { *; }
