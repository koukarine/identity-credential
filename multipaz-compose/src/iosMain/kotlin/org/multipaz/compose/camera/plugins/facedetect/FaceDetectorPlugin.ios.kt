package org.multipaz.compose.camera.plugins.facedetect

import androidx.compose.ui.graphics.ImageBitmap
import kotlinx.atomicfu.atomic
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.multipaz.compose.camera.Camera
import org.multipaz.compose.camera.CameraWorkResult
import platform.AVFoundation.AVCaptureConnection
import platform.AVFoundation.AVCaptureMetadataOutputObjectsDelegateProtocol
import platform.AVFoundation.AVCaptureOutput
import platform.AVFoundation.AVMetadataMachineReadableCodeObject
import platform.darwin.NSObject

actual suspend fun platformDetectFace(bitmap: ImageBitmap): CameraWorkResult {
    TODO("Not yet implemented")
}

actual fun platformStartDetection(
    camera: Camera,
    onFaceDetected: (faceData: CameraWorkResult) -> Unit,
    onImageSize: (androidx.compose.ui.geometry.Size) -> Unit,
    onImageRotation: (Int) -> Unit,
    coroutineScope: CoroutineScope
) {

    // TODO: Placeholder for Apple face detection impl. with Apple Vision.
    val faceDetector = FaceDetector(onFaceDetected = {
        onFaceDetected(it)
    })
//    camera.setAVMetadaObjectsDelegate(faceDetector)
//    camera.setAvMetadataObjectTypes(
//      listOf(
//    AVMetadataObjectTypeFace
//    )
    camera.startSession()
}

private class FaceDetector(
    private val onFaceDetected: (CameraWorkResult) -> Unit,
    private val faceDetectionDelay: Long = 1000L
) : NSObject(), AVCaptureMetadataOutputObjectsDelegateProtocol {

    private val isProcessing = atomic(false)
    private val scope = CoroutineScope(Dispatchers.Main)
    private var lastFaceDetected: CameraWorkResult? = null
    private var detectionJob: Job? = null

    override fun captureOutput(
        output: AVCaptureOutput,
        didOutputMetadataObjects: List<*>,
        fromConnection: AVCaptureConnection
    ) {
        if (isProcessing.value) return

//        for (metadata in didOutputMetadataObjects) {
//            if (metadata !is AVMetadataMachineReadableCodeObject) continue
//            val faceData = CameraWorkResult.FaceDetectionSuccess.fromAVMetadata(metadata) ?: continue
//            if (faceData == lastFaceDetected) continue
//
//            processFace(lastFaceDetected!!)
//            break
//        }
    }

    private fun processFace(faceData: CameraWorkResult) {
        detectionJob?.cancel()
        detectionJob = scope.launch {
            if (isProcessing.compareAndSet(expect = false, update = true)) {
                try {
                    lastFaceDetected = faceData
                    onFaceDetected(faceData)
                    delay(faceDetectionDelay)
                } finally {
                    isProcessing.value = false
                }
            }
        }
    }
}