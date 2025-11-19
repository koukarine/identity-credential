package org.multipaz.compose.pickers

import androidx.compose.runtime.Composable
import kotlinx.io.bytestring.ByteString

/**
 * Creates and remembers a platform-specific file picker.
 *
 * The picker allows selecting images from device storage.
 *
 * @param  allowMultiple whether multiple image selection is supported.
 * @param onResult callback invoked with selected image bytes. Empty when cancelled.
 */
@Composable
expect fun rememberImagePicker(
    allowMultiple: Boolean,
    onResult: (fileData: List<ByteString>) -> Unit,
): ImagePicker

/**
 * Represents a platform image picker instance
 *
 * Use [launch] to show the picker UI.
 *
 * @param  allowMultiple whether multiple image selection is supported.
 * @param onLaunch function triggered internally when [launch] is called.
 */
expect class ImagePicker(
    allowMultiple: Boolean,
    onLaunch: () -> Unit
) {
    fun launch()
}
