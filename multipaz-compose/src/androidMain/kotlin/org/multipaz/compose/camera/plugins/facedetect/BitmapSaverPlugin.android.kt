package org.multipaz.compose.camera.plugins.facedetect

/**
 * Platform-specific implementation of the [rememberBitmapSaverPlugin] factory function.
 */
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Android-specific implementation of [BitmapSaverPlugin] using Scoped Storage.
 *
 * @param config The configuration settings for the plugin.
 */
class AndroidBitmapSaverPlugin(
    config: BitmapSaverConfig
) : BitmapSaverPlugin(config) {

    override suspend fun saveImage(byteArray: ByteArray, imageName: String?): String? {
        return withContext(Dispatchers.IO) {
            "Placeholder for Android implementation of saving into StorageTable"
        }
    }

    override fun getByteArrayFrom(bitmapRecordId: String): ByteArray {
        // Placeholder for Android implementation of retrieving from StorageTable
        return ByteArray(0)
    }
}
/**
 * Factory function to create an Android-specific [BitmapSaverPlugin].
 *
 * @param config Configuration settings for the plugin.
 * @return An instance of [AndroidBitmapSaverPlugin].
 */

actual fun createPlatformBitmapSaverPlugin(
    config: BitmapSaverConfig
): BitmapSaverPlugin {
    return AndroidBitmapSaverPlugin(config)
}