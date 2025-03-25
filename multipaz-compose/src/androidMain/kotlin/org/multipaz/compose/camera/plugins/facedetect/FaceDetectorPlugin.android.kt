package org.multipaz.compose.camera.plugins.facedetect

import androidx.compose.ui.graphics.ImageBitmap
import org.multipaz.compose.camera.Camera
import org.multipaz.compose.camera.CameraWorkResult

actual suspend fun platformDetectFace(bitmap: ImageBitmap): CameraWorkResult {
    TODO("Not yet implemented")
}

actual fun platformStartDetection(
    camera: Camera,
    onFaceDetected: (faceData: CameraWorkResult) -> Unit
) {
}