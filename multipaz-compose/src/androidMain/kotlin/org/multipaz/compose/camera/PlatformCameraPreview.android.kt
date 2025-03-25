package org.multipaz.compose.camera

import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView

/**
 * Android platform-specific implementation of [CameraPreview].
 *
 * The BoxWithConstraints is used to maintain correct aspect ratio of the preview in portrait and Landscape modes.
 * When the preview is available (camera initialized) the size of the camera frame is retrieved to calculate the aspect
 * ratio. On CameraReady event the container need to be recomposed for that change. However, for an unknown reason,
 * some cameras report a wider sized frame (landscape) than the preview size, which sometimes leads to black sides
 * visible on the preview.
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

    val camera = remember {
        AndroidCameraBuilder(context, lifecycleOwner)
            .apply(cameraConfiguration)
            .build()
    }

    val previewView = remember { PreviewView(context) }
    previewView.implementationMode = PreviewView.ImplementationMode.COMPATIBLE
    previewView.scaleType = PreviewView.ScaleType.FIT_CENTER

    DisposableEffect(previewView) {
        camera.bindCamera(previewView) {
            camera.saveSensorSize()
            onCameraReady(camera)
        }
        onDispose {
            camera.stopSession()
        }
    }

    BoxWithConstraints(modifier=modifier){
        val cameraRatio = camera.cameraPreviewAspectRatio
        val containerRatio = constraints.maxWidth.toFloat() / constraints.maxHeight.toFloat()

        val isCameraWiderThanContainer = cameraRatio > containerRatio

        val scaledModifier = if (isCameraWiderThanContainer) { // Portrait.
            Modifier
                .aspectRatio(cameraRatio.toFloat())
        } else {
            Modifier
                .aspectRatio((1.0/cameraRatio).toFloat())
        }

        AndroidView(
            factory = { previewView },
            modifier = scaledModifier.fillMaxWidth()
        )
    }
}