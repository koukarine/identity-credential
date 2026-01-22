package org.multipaz.compose.branding

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.createFontFamilyResolver
import com.google.accompanist.drawablepainter.DrawablePainter
import org.multipaz.context.applicationContext

internal actual val defaultAppName: String?
    get() {
        val appInfo = applicationContext.applicationInfo
        return if (appInfo.labelRes != 0) {
            applicationContext.getString(appInfo.labelRes)
        } else {
            appInfo.nonLocalizedLabel.toString()
        }
    }

internal actual val defaultAppIconPainter: Painter?
    get() = DrawablePainter(applicationContext.packageManager.getApplicationIcon(applicationContext.packageName))

@Composable
private fun AppThemeDefault(content: @Composable () -> Unit) {
    val darkScheme = isSystemInDarkTheme()
    val colorScheme = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        val context = LocalContext.current
        if (darkScheme) {
            dynamicDarkColorScheme(context)
        } else {
            dynamicLightColorScheme(context)
        }
    } else {
        if (darkScheme) {
            darkColorScheme()
        } else {
            lightColorScheme()
        }
    }
    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}

internal actual val defaultTheme: @Composable (content: @Composable () -> Unit) -> Unit = { AppThemeDefault(it) }

internal actual fun createFontFamilyResolver(): FontFamily.Resolver {
    return createFontFamilyResolver(applicationContext)
}
