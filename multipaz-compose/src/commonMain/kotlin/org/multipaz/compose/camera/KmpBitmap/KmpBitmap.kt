package org.multipaz.compose.camera.KmpBitmap



class KmpBitmap {
    var imageData: ByteArray = ByteArray(0)

    fun initialize(image: PlatformImage) {
        imageData = platformInitialize(image)
    }

    fun scaleTo(width: Int, height: Int) {
        imageData = platformScale(imageData, width, height)
    }

    fun decode(): PlatformImage {
        return platformDecode(imageData)
    }
}

expect class PlatformImage

// These functions are expected to be implemented on each platform
expect fun platformInitialize(image: PlatformImage): ByteArray
expect fun platformScale(byteArray: ByteArray, width: Int, height: Int): ByteArray
expect fun platformDecode(byteArray: ByteArray): PlatformImage

