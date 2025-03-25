package com.android.identity.testapp.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.boundsInRoot
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.consumeAsFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch
import org.multipaz.compose.camera.Camera
import org.multipaz.compose.camera.CameraPreview
import org.multipaz.compose.camera.CameraSelection
import org.multipaz.compose.camera.CameraWorkResult
import org.multipaz.compose.camera.plugins.facedetect.rememberFaceDetectorPlugin
import org.multipaz.compose.camera.plugins.facedetect.transformPoint
import org.multipaz.compose.camera.plugins.facedetect.transformRect
import org.multipaz.compose.permissions.rememberCameraPermissionState
import org.multipaz.util.Logger

private const val TAG = "CameraScreen ZAND"

// Define a sealed class to represent different camera screen states
private sealed class CameraScreenState {
    data object CameraOptions : CameraScreenState()
    data class CameraPreview(val cameraSelection: CameraSelection) : CameraScreenState()
    data class FaceDetection(val cameraSelection: CameraSelection) : CameraScreenState()
}

@Composable
fun CameraScreen(
    showToast: (message: String) -> Unit,
) {
    val cameraPermissionState = rememberCameraPermissionState()
    val coroutineScope = rememberCoroutineScope()
    var cameraScreenState: CameraScreenState by remember { mutableStateOf(CameraScreenState.CameraOptions) }

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
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background
        ) {
            when (cameraScreenState) {
                is CameraScreenState.CameraOptions ->
                    CameraOptionsScreen(
                        onPreviewCamera = { cameraSelection ->
                            cameraScreenState = CameraScreenState.CameraPreview(cameraSelection)
                        },
                        onFaceDetection = { cameraSelection ->
                            cameraScreenState =
                                CameraScreenState.FaceDetection(cameraSelection)
                        }
                    )

                is CameraScreenState.CameraPreview -> {
                    CameraPreviewCase(
                        cameraSelection = (cameraScreenState as CameraScreenState.CameraPreview).cameraSelection,
                        onNavigateBack = {
                            cameraScreenState = CameraScreenState.CameraOptions
                        }
                    )
                }

                is CameraScreenState.FaceDetection -> {
                    FaceDetectionCase(
                        cameraSelection = (cameraScreenState as CameraScreenState.FaceDetection).cameraSelection,
                        onNavigateBack = {
                            cameraScreenState = CameraScreenState.CameraOptions
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun CameraOptionsScreen(
    onPreviewCamera: (CameraSelection) -> Unit,
    onFaceDetection: (CameraSelection) -> Unit,
) {
    val cameraOptions = listOf(
        "Front Camera Preview",
        "Back Camera Preview",
        "Detect face on the front camera"
    )

    Column(
        modifier = Modifier.fillMaxSize().padding(8.dp)
    ) {
        cameraOptions.forEach { option ->
            TextButton(
                onClick = {
                    when (option) {
                        cameraOptions[0] -> onPreviewCamera(CameraSelection.DEFAULT_FRONT_CAMERA)
                        cameraOptions[1] -> onPreviewCamera(CameraSelection.DEFAULT_BACK_CAMERA)
                        cameraOptions[2] -> onFaceDetection(CameraSelection.DEFAULT_FRONT_CAMERA)
                    }
                },
                modifier = Modifier.padding(vertical = 4.dp)
            ) {
                Text(option)
            }
        }
    }
}

@Composable
private fun FaceDetectionCase(
    cameraSelection: CameraSelection,
    onNavigateBack: () -> Unit
) {
    // Trigger recomposition when camera is initialized
    var cameraInitialized by remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()
    var faceData by remember { mutableStateOf<CameraWorkResult.FaceData?>(null) }
    var imageSize by remember { mutableStateOf<Size?>(null) }
    var imageRotation by remember { mutableStateOf<Int?>(null) }
    var camera by remember { mutableStateOf<Camera?>(null) }
    val faceDetector = rememberFaceDetectorPlugin(coroutineScope)
    var cameraRatio by remember { mutableStateOf(1f) }
    var borderRect by remember { mutableStateOf(Rect(0f, 0f, 0f, 0f)) }

    Dialog(onDismissRequest = { onNavigateBack() }) {
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .wrapContentHeight(),
            shape = RoundedCornerShape(16.dp),
            color = MaterialTheme.colorScheme.background
        ) {
            Column {
                Text(
                    text = "Face detector",
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(16.dp)
                )
                Box( //TODO: The landscape mode is broken because of the Box not resizing. Make it a custom Box?
                    modifier =
                        if (cameraRatio < 1) { //Portrait
                            Modifier.fillMaxWidth()
                                .aspectRatio(cameraRatio, false)
                        } else {
                            Modifier.fillMaxSize()
                                .aspectRatio(1f / cameraRatio, false)
                        }
                            .onGloballyPositioned { coordinates ->
                                borderRect = coordinates.boundsInRoot()
                            }

                            .onGloballyPositioned {
                                borderRect = it.boundsInRoot()
                                Logger.d(TAG, "Camera preview size: ${borderRect.width} ${borderRect.height}")
                            }
                ) {
                    CameraPreview(
                        modifier = if (cameraInitialized) Modifier.fillMaxWidth() else Modifier.fillMaxSize(),
                        cameraConfiguration = {
                            setCameraLens(cameraSelection)
                            addPlugin(faceDetector)
                        },
                        onCameraReady = {
                            if (!cameraInitialized) {
                                camera = it
                                camera!!.initializePlugins()
                                faceDetector.startDetection()
                                cameraRatio = camera?.getAspectRatio()?.toFloat() ?: 1f
                                cameraInitialized = true
                                Logger.d(TAG, "Camera ready")
                            }
                        }
                    )
                    Canvas(
                        modifier = Modifier
                            .fillMaxSize()
                    ) {
                        drawRect(
                            color = Color.Green,
                            topLeft = Offset(0f, 0f),
                            size = Size(
                                borderRect.width,
                                borderRect.height
                            ),
                            style = Stroke(width = 5.dp.toPx())
                        )
                        drawFaceOverlay(faceData, imageSize, imageRotation, cameraSelection)
                    }
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = {
                        cameraInitialized = false
                        onNavigateBack()
                    }) {
                        Text(text = "Close")
                    }
                }
            }
            LaunchedEffect(coroutineScope) {
                Logger.d(TAG, "Detection coroutine lunch.")
                coroutineScope.launch {
                    faceDetector.faceDetectionFlow.consumeAsFlow().distinctUntilChanged()
                        .collectLatest { result ->
                            when (result) {
                                is CameraWorkResult.FaceDetectionSuccess -> {
                                    faceData = result.faceData
                                    imageSize = result.imageSize
                                    imageRotation = result.imageRotation
                                    Logger.d(TAG, "FD OK r=${imageRotation}, sz=${imageSize}")
                                }

                                else -> {
                                    Logger.d(TAG, "Face detection error. Detection stopped?")
                                }
                            }
                        }
                }
            }
        }
    }
}

private fun DrawScope.drawFaceOverlay(
    faceData: CameraWorkResult.FaceData?,
    imageSize: Size?,
    imageRotation: Int?,
    cameraSelection: CameraSelection
) {
    faceData?.let { data ->
        imageSize?.let { imageSize ->
            imageRotation?.let { imageRotation ->
                val transformedRect = transformRect(
                    rect = data.faceRect,
                    previewSize = size,
                    imageSize = imageSize,
                    imageRotation = imageRotation,
                    isFrontCamera = cameraSelection == CameraSelection.DEFAULT_FRONT_CAMERA
                )

                drawRect(
                    color = Color.Red,
                    topLeft = Offset(transformedRect.left, transformedRect.top),
                    size = Size(
                        transformedRect.width,
                        transformedRect.height
                    ),
                    style = Stroke(width = 5.dp.toPx())
                )

                val leftEye = transformPoint(
                    data.leftEyePosition,
                    previewSize = size,
                    imageSize = imageSize,
                    imageRotation = imageRotation,
                    isFrontCamera = cameraSelection == CameraSelection.DEFAULT_FRONT_CAMERA
                )

                val rightEye = transformPoint(
                    data.rightEyePosition,
                    previewSize = size,
                    imageSize = imageSize,
                    imageRotation = imageRotation,
                    isFrontCamera = cameraSelection == CameraSelection.DEFAULT_FRONT_CAMERA
                )

                val mouthBottom = transformPoint(
                    data.mouthPosition,
                    previewSize = size,
                    imageSize = imageSize,
                    imageRotation = imageRotation,
                    isFrontCamera = cameraSelection == CameraSelection.DEFAULT_FRONT_CAMERA
                )

                drawLine(
                    color = Color.Red,
                    leftEye, rightEye,
                    strokeWidth = 5.dp.toPx()
                )

                drawLine(
                    color = Color.Red,
                    leftEye, mouthBottom,
                    strokeWidth = 5.dp.toPx()
                )

                drawLine(
                    color = Color.Red,
                    rightEye, mouthBottom,
                    strokeWidth = 5.dp.toPx()
                )
            }
        }
    }
}

@Composable
private fun CameraPreviewCase(
    cameraSelection: CameraSelection,
    onNavigateBack: () -> Unit
) {
    // Trigger recomposition when camera is initialized
    var cameraInitialized by remember { mutableStateOf(false) }

    Dialog(onDismissRequest = { onNavigateBack() }) {
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .wrapContentHeight(),
            shape = RoundedCornerShape(16.dp),
            color = MaterialTheme.colorScheme.background
        ) {
            Column {
                Text(
                    text = "Camera preview",
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(16.dp)
                )

                CameraPreview(
                    modifier = if (cameraInitialized) Modifier.fillMaxWidth() else Modifier.fillMaxSize(),
                    cameraConfiguration = {
                        setCameraLens(cameraSelection)
                    },
                    onCameraReady = {
                        cameraInitialized = true
                        Logger.d(TAG, "Camera ready")
                    }
                )

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = {
                        cameraInitialized = false
                        onNavigateBack()
                    }) {
                        Text(text = "Close")
                    }
                }
            }
        }
    }
}