package org.multipaz.selfiecheck

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.multipaz.compose.camera.Camera
import org.multipaz.compose.camera.CameraCaptureResolution
import org.multipaz.facedetection.detectFaces

//todo: MLKit: consider setPerformanceMode(FaceDetectorOptions.PERFORMANCE_MODE_ACCURATE)? Works OK withhout.
// setMinFaceSize() can be useful to filter out very small detections which are often false positives.
// Verify Accessibility options (voice prompts).

@Composable
fun SelfieCheck(
    modifier: Modifier = Modifier,
    viewModel: SelfieCheckViewModel = remember { SelfieCheckViewModel() }
) {
    val currentStep by viewModel.currentStep.collectAsState()
    val instructionText by viewModel.instructionText.collectAsState()
    val hapticFeedback = LocalHapticFeedback.current
    val countdownSeconds by viewModel.countdownSeconds.collectAsState()
    val countdownProgress by viewModel.countdownProgress.collectAsState()

    // Step success feedback monitor. todo: add extended UI feedback here.
    LaunchedEffect(viewModel.stepSuccessEvent) {
        viewModel.stepSuccessEvent.collect {
            hapticFeedback.performHapticFeedback(HapticFeedbackType.LongPress)
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = "Selfie Verification",
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.padding(bottom = 24.dp)
        )

        Box(
            modifier = Modifier
                .fillMaxWidth(0.8f) // Limit to 80 % of the full preview size. todo: m/b different for landscape
                .aspectRatio(1f)
                .clip(CircleShape)
                .clipToBounds(),
            contentAlignment = Alignment.Center
        ) {
            Camera(
                modifier = Modifier.fillMaxSize(),
                captureResolution = CameraCaptureResolution.MEDIUM,
                showCameraPreview = true,
                onFrameCaptured = { frameData ->
                    if (currentStep != SelfieCheckStep.INITIAL &&
                        currentStep != SelfieCheckStep.COMPLETED &&
                        currentStep != SelfieCheckStep.FAILED
                    ) {
                        val faces = detectFaces(frameData)
                        if (!faces.isNullOrEmpty()) {
                            viewModel.onFaceDataUpdated(
                                faces[0],
                                Size(frameData.width.toFloat(), frameData.height.toFloat()
                            ))
                        }
                    }
                }
            )

            if (currentStep != SelfieCheckStep.INITIAL &&
                currentStep != SelfieCheckStep.COMPLETED &&
                currentStep != SelfieCheckStep.FAILED
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth(0.7f)
                        .aspectRatio(0.75f)
                        .border(
                            BorderStroke(4.dp, MaterialTheme.colorScheme.primary),
                            CircleShape
                        )
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Step prompt.
        Card(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
        ) {
            Text(
                text = instructionText,
                modifier = Modifier
                    .padding(16.dp)
                    .fillMaxWidth(),
                textAlign = TextAlign.Center,
                style = MaterialTheme.typography.titleMedium,
                minLines = 2
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        when (currentStep) {
            SelfieCheckStep.INITIAL, SelfieCheckStep.FAILED -> {
                Button(
                    onClick = { viewModel.startSelfieCheck() },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(if (currentStep == SelfieCheckStep.FAILED) "TRY AGAIN" else "START SELFIE CHECK")
                }
            }
            SelfieCheckStep.COMPLETED -> {
                Text(
                    "Verification Complete!",
                    color = Color(0xff007f00), // Darker green.
                    style = MaterialTheme.typography.headlineSmall,
                    textAlign = TextAlign.Center
                )
                // Todo: Save the frame here. Pause. Change text to "Saving..." then "Done".
            }
            else -> {
                Box(contentAlignment = Alignment.Center, modifier = Modifier.size(64.dp)) { // Increased size for text
                    CircularProgressIndicator(
                        progress = { countdownProgress },
                        modifier = Modifier.fillMaxSize(),
                        strokeWidth = 6.dp,
                        color = MaterialTheme.colorScheme.primary,
                        trackColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                    Text(
                        text = "$countdownSeconds",
                        style = MaterialTheme.typography.titleLarge.copy(
                            fontWeight = FontWeight.Bold,
                            fontSize = 20.sp
                        ),
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
        Spacer(modifier = Modifier.height(16.dp))
    }
}