package org.multipaz.compose.camera

import androidx.camera.view.PreviewView
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView

/**
 * Android platform-specific implementation of [CameraPreview].
 *
 * @param modifier Modifier to be applied to the camera preview.
 * @param cameraConfiguration Lambda to configure the [CameraBuilder].
 * @param onCameraReady Callback invoked with the initialized [Camera].
 */
@Composable
actual fun PlatformCameraPreview(
    modifier: Modifier,
    cameraConfiguration: CameraBuilder.() -> Unit,
    onCameraReady: (Camera) -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current

    val isCameraReady = remember { mutableStateOf(false) }
    val camera = remember {
        AndroidCameraBuilder(context, lifecycleOwner)
            .apply(cameraConfiguration)
            .build()
    }

    val previewView = remember { PreviewView(context) }

    DisposableEffect(previewView) {
        camera.bindCamera(previewView) {
            onCameraReady(camera)
        }
        onDispose {
            camera.stopSession()
        }
    }

    AndroidView(
        factory = { previewView },
        modifier = modifier,
    )
}