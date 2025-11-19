package org.multipaz.compose.pickers

import androidx.compose.runtime.Composable
import kotlinx.io.bytestring.ByteString

/**
 * Creates and remembers a platform-specific file picker.
 *
 * The picker allows selecting a document from the device storage.
 *
 * @param types list of MIME types the picker should filter on (e.g., `"application/pkix-cert"`).
 * @param allowMultiple whether multiple file selection is supported.
 * @param onResult callback invoked with a list of selected file bytes. Empty when cancelled.
 */
@Composable
expect fun rememberFilePicker(
    types: List<String>,
    allowMultiple: Boolean,
    onResult: (fileData: List<ByteString>) -> Unit,
): FilePicker

/**
 * Represents a platform file picker instance
 *
 * Use [launch] to show the picker UI.
 *
 * @param types list of MIME types allowed.
 * @param  allowMultiple whether multiple file selection is supported.
 * @param onLaunch function triggered internally when [launch] is called.
 */
expect class FilePicker(
    types: List<String>,
    allowMultiple: Boolean,
    onLaunch: () -> Unit
) {
    /**
     * Launches the platform file picker UI.
     */
    fun launch()
}
