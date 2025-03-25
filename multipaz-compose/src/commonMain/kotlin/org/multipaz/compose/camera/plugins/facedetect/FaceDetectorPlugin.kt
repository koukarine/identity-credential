package org.multipaz.compose.camera.plugins.facedetect

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.ImageBitmap
import kotlinx.atomicfu.atomic
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import org.multipaz.compose.camera.Camera
import org.multipaz.compose.camera.CameraPlugin
import org.multipaz.compose.camera.CameraWorkResult
import org.multipaz.util.Logger

/**
 * Multiplatform CameraPlugin facility implementation for the fce detection functionality.
 */
class FaceDetectorPlugin(private val coroutineScope: CoroutineScope) : CameraPlugin {
    private val TAG = "FaceDetectorPlugin ZAND"
    private var camera: Camera? = null
    private var isDetecting = atomic(false)
    val faceDetectionFlow = Channel<CameraWorkResult>()

    private var imageSize: Size? = null
    private var imageRotation: Int? = null

    /** Common API for the plugin initialization. */
    override fun initialize(camera: Camera) {
        this.camera = camera
    }

    /** Detection code is called from the process capturing frames (TBD). */
    fun detectFace(cameraImage: ImageBitmap) = coroutineScope.launch {
        Logger.d(TAG, "Starting face detection on the bitmap")
        val faceDetectedData = platformDetectFace(cameraImage)
        Logger.d(TAG, "Face Detection result: $faceDetectedData")
    }

    /**
     * Detection can be started on main thread and obtain any needed parameters, as well as map the flow.
     */
    fun startDetection() {
        isDetecting.value = true
        coroutineScope.launch {
            platformStartDetection(
                camera!!,
                onFaceDetected = {
                    if (isDetecting.value) {
                        if (isDetectionSatisfactory(it)) faceDetectionFlow.trySend(it)
                    }
                },
                onImageSize = { imageSize = it },
                onImageRotation = { imageRotation = it },
                coroutineScope = coroutineScope
            )
        }
    }

    /**
     * Disable detection when needed and/or on lifecycle.
     */
    fun stopDetection() {
        isDetecting.value = false
    }

    private fun isDetectionSatisfactory(detectionResult: CameraWorkResult): Boolean {
        // TODO: figure a way for platform-independent criteria.
        return true
    }
}

@Composable
fun rememberFaceDetectorPlugin(coroutineScope: CoroutineScope = rememberCoroutineScope()): FaceDetectorPlugin {
    return remember {
        FaceDetectorPlugin(coroutineScope)
    }
}

/**
 * Detect face on a Bitmap (for future implementation).
 */
expect suspend fun platformDetectFace(bitmap: ImageBitmap): CameraWorkResult

/**
 * Start face detection on the camera.
 *
 * @param camera Camera instance.
 * @param onFaceDetected Primary data callback for the face detection result processing.
 * @param onImageSize Callback for the image size change to support UI composition.
 * @param onImageRotation Callback for the image rotation support in UI.
 * @param coroutineScope Coroutine scope for the detection.
 */
expect fun platformStartDetection(
    camera: Camera,
    onFaceDetected: (faceData: CameraWorkResult) -> Unit,
    onImageSize: (Size) -> Unit,
    onImageRotation: (Int) -> Unit,
    coroutineScope: CoroutineScope
)