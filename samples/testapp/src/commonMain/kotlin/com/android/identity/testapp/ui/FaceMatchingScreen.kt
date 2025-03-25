package com.android.identity.testapp.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Rect
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.ui.Alignment.Companion.CenterHorizontally
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Paint
import androidx.compose.ui.graphics.PaintingStyle
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.multipaz.compose.permissions.rememberCameraPermissionState

private const val TAG = "FaceMatchingScreen ZAND"

@Composable
fun FaceMatchingScreen(
    showToast: (message: String) -> Unit,
) {
    val cameraPermissionState = rememberCameraPermissionState()
    val isFaceEnrolled = remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()

    if (!cameraPermissionState.isGranted) {
        Column(
            modifier = Modifier
                .fillMaxSize(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Button(
                onClick = {
                    coroutineScope.launch {
                        cameraPermissionState.launchPermissionRequest()
                    }
                }
            ) {
                Text("Request Camera permission")
            }
        }
    } else {
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            color = MaterialTheme.colorScheme.background
        ) {
            Column {
                if (isFaceEnrolled.value) {
                    Text("Enrolled face")
                    Image(
                        bitmap = createRectangularImageBitmap(100, 150, Color.Gray),
                        contentDescription = "Temporary Image",
                        modifier = Modifier
                            .size(200.dp, 300.dp)
                            .align(CenterHorizontally)
                    )
                } else {
                    Text("No Face Enrolled")
                }
                TextButton(onClick = {
                    isFaceEnrolled.value = false
                }) {
                    Text("Delete Enrolled Face")
                }
                TextButton(onClick = {
                    isFaceEnrolled.value = true
                }) {
                    Text("Enroll Face")
                }
            }
        }
    }
}

/** Placeholder. */
fun createRectangularImageBitmap(width: Int, height: Int, color: Color): ImageBitmap {
    val bitmap = ImageBitmap(width, height)
    val paint = Paint().apply {
        this.color = color
        style = PaintingStyle.Fill
    }

    val path = Path().apply {
        addRect(Rect(0f, 0f, width.toFloat(), height.toFloat()))
    }

    val canvas = androidx.compose.ui.graphics.Canvas(bitmap)

    canvas.drawPath(path, paint)
    return bitmap
}