package org.multipaz.compose.camera.plugins.facedetect

/**
 * Platform-specific implementation of the [rememberBitmapSaverPlugin] factory function.
 */
import io.ktor.utils.io.errors.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.multipaz.compose.camera.KmpBitmap.KmpBitmap
import platform.Foundation.NSCondition
import platform.Foundation.NSData
import platform.Photos.PHAssetChangeRequest
import platform.Photos.PHPhotoLibrary
import platform.UIKit.UIImage
import platform.UIKit.UIImagePNGRepresentation

/**
 * iOS-specific implementation of [BitmapSaverPlugin].
 *
 * @param config The configuration settings for the plugin.
 * @param onImageSaved Callback invoked when the image is successfully saved.
 * @param onImageSavedFailed Callback invoked when the image saving fails.
 */
class IOSBitmapSaverPlugin(
    config: BitmapSaverConfig,
    private val onImageSaved: () -> Unit,
    private val onImageSavedFailed: (String) -> Unit
) : BitmapSaverPlugin(config) {

    override suspend fun saveImage(byteArray: ByteArray, imageName: String?): String? {
        return withContext(Dispatchers.Main) {
            try {
                val bitmap = KmpBitmap()
                bitmap.imageData = byteArray
                val nsData = UIImagePNGRepresentation(bitmap.decode())

                if (nsData == null) {
                    println("Failed to convert ByteArray to NSData.")
                    onImageSavedFailed("Failed to convert ByteArray to NSData.")
                    return@withContext null
                }

                val image = UIImage.imageWithData(nsData)

                if (image == null) {
                    println("Failed to convert NSData to UIImage.")
                    onImageSavedFailed("Failed to create UIImage from NSData.")
                    return@withContext null
                }

                var assetId: String? = null
                val semaphore = NSCondition()

                PHPhotoLibrary.sharedPhotoLibrary().performChanges({
                    val request = PHAssetChangeRequest.creationRequestForAssetFromImage(image)
                    assetId = request.placeholderForCreatedAsset?.localIdentifier
                }) { success, error ->
                    if (success && assetId != null) {
                        println("Image successfully saved to Photos album with ID: $assetId")
                    } else {
                        println("Failed to save image: ${error?.localizedDescription}")
                        assetId = null
                    }
                    semaphore.signal()
                }

                semaphore.wait()
                assetId
            } catch (e: Exception) {
                println("Exception while saving image: ${e.message}")
                null
            }
        }
    }

    override fun getByteArrayFrom(bitmapRecordId: String): ByteArray {
        var imageData: NSData? = null

        // TODO async retrieve the bitmap from StorageTables

        if (imageData == null) {
            throw IOException("Failed to get image data from Tables: $bitmapRecordId")
        }

        val result = KmpBitmap()
        result.initialize(UIImage(data = imageData!!))
        return result.imageData
    }
}

/**
 * Factory function to create an iOS-specific [BitmapSaverPlugin].
 *
 * @param config Configuration settings for the plugin.
 * @return An instance of [IOSBitmapSaverPlugin].
 */

actual fun createPlatformBitmapSaverPlugin(
    config: BitmapSaverConfig
): BitmapSaverPlugin {

    return IOSBitmapSaverPlugin(config = config, onImageSaved = {

        println("Image saved successfully!")
    }, onImageSavedFailed = { errorMessage ->

        println("Failed to save image: $errorMessage")
    })
}