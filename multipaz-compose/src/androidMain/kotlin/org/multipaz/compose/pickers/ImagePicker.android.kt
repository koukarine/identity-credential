package org.multipaz.compose.pickers

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import kotlinx.io.bytestring.ByteString
import org.multipaz.context.applicationContext
import org.multipaz.util.Logger

private const val TAG = "ImagePicker"
@Composable
actual fun rememberImagePicker(
    allowMultiple: Boolean,
    onResult: (fileData: List<ByteString>) -> Unit,
): ImagePicker {
    val imagePicker =
        rememberLauncherForActivityResult(
            contract = ActivityResultContracts.PickVisualMedia(),
            onResult = { uri ->
                if (uri != null) {
                    val inputStream = applicationContext.contentResolver.openInputStream(uri)
                    if (inputStream != null) {
                        val bytes = inputStream.readBytes()
                        inputStream.close()
                        onResult(listOf(ByteString(bytes)))
                    } else {
                        Logger.e(TAG, "File not found")
                    }
                } else {
                    onResult(emptyList())
                }
            },
        )

    val multiSelectionImagePicker =
        rememberLauncherForActivityResult(
            contract = ActivityResultContracts.PickMultipleVisualMedia(),
            onResult = { uris ->
                if (uris.isEmpty()) {
                    onResult(emptyList())
                } else {
                    uris.forEach { uri ->
                        val inputStream = applicationContext.contentResolver.openInputStream(uri)
                        if (inputStream != null) {
                            val bytes = inputStream.readBytes()
                            inputStream.close()
                            onResult(listOf(ByteString(bytes)))
                        } else {
                            Logger.e(TAG, "File not found")
                        }
                    }
                }
            },
        )

    return remember {
        ImagePicker(
            allowMultiple = allowMultiple,
            onLaunch = {
                if(allowMultiple) {
                    multiSelectionImagePicker.launch(
                        PickVisualMediaRequest.Builder()
                            .setMediaType(ActivityResultContracts.PickVisualMedia.ImageOnly)
                            .build()
                    )
                } else {
                    imagePicker.launch(
                        PickVisualMediaRequest.Builder()
                            .setMediaType(ActivityResultContracts.PickVisualMedia.ImageOnly)
                            .build()
                    )
                }

            },
        )
    }
}
actual class ImagePicker actual constructor(
    val allowMultiple: Boolean,
    val onLaunch: () -> Unit
) {
    actual fun launch() {
        onLaunch()
    }
}
