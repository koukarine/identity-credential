package org.multipaz.compose.selfiecheck

import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember

@Composable
fun SelfieCheck() {
    val selfieViewModel = remember { SelfieCheckViewModel() }

    val currentStep by selfieViewModel.currentStep
    val instruction by selfieViewModel.instructionText

    Text(text = instruction)

    // ... your camera preview and overlay ...

    selfieViewModel.onFaceDetected(faceBounds)
    selfieViewModel.onHeadPoseDetected(x, y, z)
    selfieViewModel.onEyeStateDetected(leftProb, rightProb)
    selfieViewModel.onSmileDetected(smileProb)

    // Example button to start
    Button(onClick = { selfieViewModel.startSelfieCheck() }) {
        Text("Start Selfie Check")
    }
}

//todo: MLKit: consider setPerformanceMode(FaceDetectorOptions.PERFORMANCE_MODE_ACCURATE)
//  setMinFaceSize() can be useful to filter out very small detections.
// Accessibility options (voice prompts).