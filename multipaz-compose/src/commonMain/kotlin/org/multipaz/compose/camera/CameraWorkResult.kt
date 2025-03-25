package org.multipaz.compose.camera

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

    data class FaceDetectionSuccess(val faceData: ByteString) : CameraWorkResult()

    data class FaceMatchSuccess(val faceData: ByteString) : CameraWorkResult()

    data class QrCodeScanSuccess(val qrCodeData: ByteString) : CameraWorkResult()

    /**
     * Represents a failed image capture.
     *
     * @param exception The exception that occurred during image capture.
     */
    data class Error(val exception: Exception) : CameraWorkResult()

}
