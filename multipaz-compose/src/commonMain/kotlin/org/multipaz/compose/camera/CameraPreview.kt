package org.multipaz.compose.camera

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

/**
 * Cross-platform composable function to display the camera preview.
 *
 * @param modifier Modifier to be applied to the camera preview.
 * @param cameraConfiguration Lambda to configure the [Camera] with needed components.
 * @param onCameraReady Callback invoked with the fully initialized [Camera] object.
 */
@Composable
fun CameraPreview(
    modifier: Modifier = Modifier,
    cameraConfiguration: CameraBuilder.() -> Unit,
    onCameraReady: (Camera) -> Unit,
) {
    PlatformCameraPreview(modifier, cameraConfiguration, onCameraReady)
}

/** Platform dependent implementations of the Preview. */
@Composable
expect fun PlatformCameraPreview(
    modifier: Modifier = Modifier,
    cameraConfiguration: CameraBuilder.() -> Unit,
    onCameraReady: (Camera) -> Unit
)
