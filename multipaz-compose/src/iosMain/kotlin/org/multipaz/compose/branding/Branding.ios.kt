package org.multipaz.compose.branding

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.createFontFamilyResolver
import org.multipaz.compose.camera.toSkiaImage
import platform.Foundation.NSBundle
import platform.UIKit.UIImage

internal actual val defaultAppName: String?
    get() {
        val bundle = NSBundle.mainBundle
        return bundle.objectForInfoDictionaryKey("CFBundleDisplayName") as? String
            ?: bundle.objectForInfoDictionaryKey("CFBundleName") as? String
    }

internal actual val defaultAppIconPainter: Painter?
    get() {
        val bundle = NSBundle.mainBundle
        val icons: Map<String, Any>? = bundle.objectForInfoDictionaryKey("CFBundleIcons") as? Map<String, Any>
        val primaryIcon: Map<String, Any>? = icons?.get("CFBundlePrimaryIcon") as? Map<String, Any>
        val iconFiles = primaryIcon?.get("CFBundleIconFiles") as? List<String>
        val lastIconName = iconFiles?.lastOrNull()
        return if (lastIconName != null) {
            val uiImage = UIImage.imageNamed(lastIconName)
            val imageBitmap = uiImage?.toSkiaImage()?.toComposeImageBitmap()
            if (imageBitmap != null) {
                BitmapPainter(imageBitmap)
            } else {
                null
            }
        } else {
            null
        }
    }

@Composable
private fun AppThemeDefault(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme(),
        content = content
    )
}

internal actual val defaultTheme: @Composable (content: @Composable () -> Unit) -> Unit = { AppThemeDefault(it) }

internal actual fun createFontFamilyResolver(): FontFamily.Resolver {
    return createFontFamilyResolver()
}
