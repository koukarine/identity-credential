package com.android.identity.testapp.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.consumeAsFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch
import org.multipaz.compose.camera.Camera
import org.multipaz.compose.camera.CameraPreview
import org.multipaz.compose.camera.CameraSelection
import org.multipaz.compose.camera.plugins.facedetect.rememberFaceDetectorPlugin
import org.multipaz.compose.permissions.rememberCameraPermissionState


@Composable
fun CameraScreen(
    showToast: (message: String) -> Unit
) {
    val cameraOptions = listOf(
        "Demo front Camera Preview",
        "Demo back Camera Preview",
        "Detect face on the front camera"
    )
    val showCameraDialog = remember { mutableStateOf<String?>(null) }
    val cameraPermissionState = rememberCameraPermissionState()
    val coroutineScope = rememberCoroutineScope()
    val camera = remember { mutableStateOf<Camera?>(null) }
    val faceDetector = rememberFaceDetectorPlugin()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        faceDetector.faceDetectionFlow.consumeAsFlow().distinctUntilChanged()
            .collectLatest { data ->
                println("Face Detected: $data")
                snackbarHostState.showSnackbar(
                    message = "Face Detected: $data",
                    actionLabel = "Dismiss"
                )
                faceDetector.stopDetection()
            }
    }

    if (showCameraDialog.value != null) {
        AlertDialog(
            title = { Text(text = "Camera dialog") },
            text = {
                    CameraPreview(
                        modifier = Modifier.fillMaxSize(),
                        cameraConfiguration = {
                            when (showCameraDialog.value) {
                                cameraOptions[0] -> { // Demo front Camera Preview.
                                    setCameraLens(CameraSelection.DEFAULT_FRONT_CAMERA)
                                }

                                cameraOptions[1] -> { // "Demo back Camera Preview"
                                    setCameraLens(CameraSelection.DEFAULT_BACK_CAMERA)
                                }

                                cameraOptions[2] -> { // "Detect face on the front camera"
                                    setCameraLens(CameraSelection.DEFAULT_FRONT_CAMERA)
                                    addPlugin(faceDetector)
                                    faceDetector.startDetection()
                                }

                                else -> {
                                    setCameraLens(CameraSelection.DEFAULT_FRONT_CAMERA)
                                }
                            }
                        },
                        onCameraReady = {
                            camera.value = it
                            println("AK: Camera ready")
                        }
                    )
            },
            onDismissRequest = { showCameraDialog.value = null },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = {
                    showCameraDialog.value = null
                }) {
                    Text(text = "Close")
                }
            }
        )
    }

    if (!cameraPermissionState.isGranted) {
        Column(
            modifier = Modifier.fillMaxSize(),
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
            LazyColumn(
                modifier = Modifier.padding(8.dp)
            ) {
                cameraOptions.map { option ->
                    item {
                        TextButton(
                            onClick = {
                                showCameraDialog.value = option
                            }
                        ) {
                            Text(option)
                        }
                    }
                }
            }
        }
    }
}
