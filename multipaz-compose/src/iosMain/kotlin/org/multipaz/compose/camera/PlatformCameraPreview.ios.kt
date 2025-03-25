// org.multipaz.compose.camera/IOSCamera.kt (iOS platform code)

package org.multipaz.compose.camera

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.UIKitView

import androidx.compose.runtime.*
import platform.Foundation.NSNotificationCenter
import platform.UIKit.*

/**
 * iOS-specific implementation of [CameraPreview].
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

    val camera = remember {
        IosCameraBuilder()
            .apply(cameraConfiguration)
            .build()
    }

    LaunchedEffect(camera) {
        onCameraReady(camera)
    }

    // Camera frame orientation updates on physical device rotation.
    DisposableEffect(Unit) {
        val notificationCenter = NSNotificationCenter.defaultCenter
        val observer = notificationCenter.addObserverForName(
            name = UIDeviceOrientationDidChangeNotification,
            `object` = null,
            queue = null
        ) { _ ->
            camera.currentVideoOrientation()?.let { newOrientation ->
                camera.getCameraPreviewLayer()?.connection?.videoOrientation = newOrientation
            }
        }

        onDispose {
            notificationCenter.removeObserver(observer)
        }
    }

    UIKitView(
        factory = { camera.view },
        modifier = modifier,
    )
}