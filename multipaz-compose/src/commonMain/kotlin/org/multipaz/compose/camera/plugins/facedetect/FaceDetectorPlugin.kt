package org.multipaz.compose.camera.plugins.facedetect

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
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
class FaceDetectorPlugin(val coroutineScope: CoroutineScope) : CameraPlugin {
    private val TAG = "FaceDetectorPlugin"
    private var camera: Camera? = null
    private var isDetecting = atomic(false)
    val faceDetectionFlow = Channel<CameraWorkResult>()

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
        platformStartDetection(camera!!) {
            if (isDetecting.value) {
                if (isDetectionSatisfactory(it)) faceDetectionFlow.trySend(it)
            }
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

expect suspend fun platformDetectFace(bitmap: ImageBitmap): CameraWorkResult

expect fun platformStartDetection(camera: Camera, onFaceDetected: (faceDetectedData: CameraWorkResult) -> Unit)

@Composable
fun rememberFaceDetectorPlugin(coroutineScope: CoroutineScope = rememberCoroutineScope()): FaceDetectorPlugin {
    return remember {
        FaceDetectorPlugin(coroutineScope)
    }
}