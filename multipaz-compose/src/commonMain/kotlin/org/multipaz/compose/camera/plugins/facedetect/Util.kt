package org.multipaz.compose.camera.plugins.facedetect

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import org.multipaz.util.Logger
import kotlin.math.max

fun transformPoint(
    point: Offset?,
    imageSize: Size,
    imageRotation: Int,
    previewSize: Size,
    isFrontCamera: Boolean = false
): Offset {
    if (point == null) return Offset(0f, 0f)

    val rotatedImageWidth = if (imageRotation == 90 || imageRotation == 270) imageSize.height else imageSize.width
    val rotatedImageHeight = if (imageRotation == 90 || imageRotation == 270) imageSize.width else imageSize.height

    val scaleX = previewSize.width / rotatedImageWidth
    val scaleY = previewSize.height / rotatedImageHeight

    val scaledImageWidth: Float
    val scaledImageHeight: Float
    val dx: Float
    val dy: Float

    if (previewSize.width / previewSize.height > rotatedImageWidth / rotatedImageHeight) {
        // preview wider than rotated image, then black bars on top and bottom
        scaledImageWidth = previewSize.width
        scaledImageHeight = rotatedImageHeight * scaleX
        dx = 0f
        dy = (previewSize.height - scaledImageHeight) / 2
    } else {
        // rotated image wider than preview, then black bars on left and right
        scaledImageWidth = rotatedImageWidth * scaleY
        scaledImageHeight = previewSize.height
        dx = (previewSize.width - scaledImageWidth) / 2
        dy = 0f
    }

    val transformedPoint = when (imageRotation) {
        270 -> { // Portrait preview (most typical).
            Offset(
                x = point.x * scaleX + dx,
                y = point.y * scaleY + dy
            )
        }
        0 -> {
            Offset(
                x = point.y * scaleY + dy,
                y = (imageSize.width - point.x) * scaleX + dx
            )
        }
        90 -> {
            Offset(
                x = (imageSize.width - point.x) * scaleX + dx,
                y = (imageSize.height - point.y) * scaleY + dy
            )
        }
        180 -> {
            Offset(
                x = (imageSize.height - point.y) * scaleY + dy,
                y = point.x * scaleX + dx
            )
        }
        else -> throw IllegalArgumentException("Invalid image rotation: $imageRotation")
    }

    val finalX = if (isFrontCamera) previewSize.width - transformedPoint.x else transformedPoint.x

    return Offset(finalX, transformedPoint.y)
}

fun transformRect(
    rect: Rect,
    imageSize: Size,
    imageRotation: Int,
    previewSize: Size,
    isFrontCamera: Boolean = false
): Rect {
    val topLeft = transformPoint(rect.topLeft, imageSize, imageRotation, previewSize, isFrontCamera)
    val bottomRight = transformPoint(rect.bottomRight, imageSize, imageRotation, previewSize, isFrontCamera)
    return Rect(topLeft, bottomRight)
}
