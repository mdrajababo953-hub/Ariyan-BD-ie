package com.example.apps

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class InstalledAppInfo(
    val packageName: String,
    val appName: String,
    val uid: Int,
    val isGame: Boolean,
    val isSystemApp: Boolean,
    val icon: Drawable?
)

class InstalledAppsRepository(private val context: Context) {

    suspend fun getLaunchableApps(): List<InstalledAppInfo> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val intent = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_LAUNCHER)
        }

        val resolved = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            pm.queryIntentActivities(intent, 0)
        }

        val seenPackages = hashSetOf<String>()
        val result = mutableListOf<InstalledAppInfo>()

        for (info in resolved) {
            val activityInfo = info.activityInfo ?: continue
            val pkg = activityInfo.packageName ?: continue
            if (pkg == context.packageName || !seenPackages.add(pkg)) continue

            val appInfo = activityInfo.applicationInfo
            val label = info.loadLabel(pm)?.toString()?.trim().takeUnless { it.isNullOrEmpty() } ?: pkg
            val icon = runCatching { info.loadIcon(pm) }.getOrNull()
            val isGame = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                appInfo.category == ApplicationInfo.CATEGORY_GAME
            } else {
                @Suppress("DEPRECATION")
                (appInfo.flags and ApplicationInfo.FLAG_IS_GAME) != 0
            }
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0

            result.add(
                InstalledAppInfo(
                    packageName = pkg,
                    appName = label,
                    uid = appInfo.uid,
                    isGame = isGame,
                    isSystemApp = isSystem,
                    icon = icon
                )
            )
        }

        result.sortedWith(
            compareByDescending<InstalledAppInfo> { it.isGame }
                .thenBy { it.isSystemApp }
                .thenBy { it.appName.lowercase() }
        )
    }
}
