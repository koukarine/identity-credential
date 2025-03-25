package org.multipaz.compose.camera.plugins.facedetect

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.launch
import org.multipaz.compose.camera.Camera
import org.multipaz.compose.camera.CameraPlugin

/**
 * Configuration for the BitmapSaverPlugin.
 *
 * @param isAutoSave Determines if images should be saved automatically upon capture.
 * @param prefix Optional prefix for image filenames when auto-saving.
 * @param tableName Optional custom folder name within the specified directory.
 */
data class BitmapSaverConfig(
    val isAutoSave: Boolean = false,
    val prefix: String? = null,
    val tableName: String? = null,
)

/**
 * Abstract plugin to save captured images.
 *
 * Provides methods to save images either manually or automatically based on configuration.
 *
 * @param config Configuration settings for the plugin.
 */
abstract class BitmapSaverPlugin(
    val config: BitmapSaverConfig
) : CameraPlugin {

    /**
     * Saves the captured image data to storage manually.
     *
     * @param byteArray The image data as a [ByteArray].
     * @param imageName Optional custom name for the image. If not provided, a default name is generated.
     */
    abstract suspend fun saveImage(byteArray: ByteArray, imageName: String? = null): String?

    /**
     * Initializes the plugin. If auto-save is enabled, sets up listeners to save images automatically.
     *
     * @param camera The [Camera] instance to attach listeners.
     */
    override fun initialize(camera: Camera) {
        if (config.isAutoSave) {
            camera.addFrameCaptureListener { byteArray ->
                CoroutineScope(Dispatchers.IO).launch {
                    val imageName = config.prefix?.let { "CameraK" }
                    saveImage(byteArray, imageName)
                }
            }
        }
    }

    abstract fun getByteArrayFrom(bitmapRecordId: String): ByteArray
}

/**
 * Factory function to create a platform-specific [BitmapSaverPlugin].
 *
 * @param config Configuration settings for the plugin.
 * @return An instance of [BitmapSaverPlugin].
 */
@Composable
fun rememberBitmapSaverPlugin(
    config: BitmapSaverConfig
): BitmapSaverPlugin {
    return remember(config) {
        createPlatformBitmapSaverPlugin(config)
    }
}

/**
 * Platform-specific implementation of the [rememberBitmapSaverPlugin] factory function.
 */

expect fun createPlatformBitmapSaverPlugin(
    config: BitmapSaverConfig
): BitmapSaverPlugin
