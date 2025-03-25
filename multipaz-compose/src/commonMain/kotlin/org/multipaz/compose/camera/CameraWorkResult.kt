package org.multipaz.compose.camera

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import kotlinx.io.bytestring.ByteString

/**
 * Sealed class representing the result of camera operations, including the error handling.
 */
sealed class CameraWorkResult {

    data class FrameCaptureSuccess(val byteArray: ByteArray) : CameraWorkResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as FrameCaptureSuccess

            return byteArray.contentEquals(other.byteArray)
        }

        override fun hashCode(): Int {
            return byteArray.contentHashCode()
        }
    }

    data class FaceData(
        val faceRect: Rect,
        val leftEyePosition: Offset?,
        val rightEyePosition: Offset?,
        val mouthPosition: Offset?
    )

    data class FaceDetectionSuccess(
        val faceData: FaceData,
        val imageSize: Size,
        val imageRotation: Int
    ) : CameraWorkResult()

    data class FaceMatchSuccess(val faceData: ByteString) : CameraWorkResult()

    data class QrCodeScanSuccess(val qrCodeData: ByteString) : CameraWorkResult()

    /**
     * Represents a failed image capture.
     *
     * @param exception The exception that occurred during image capture.
     */
    data class Error(val exception: Exception) : CameraWorkResult()

}
