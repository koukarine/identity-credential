package org.multipaz.compose.selfiecheck

import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.geometry.isEmpty
import androidx.lifecycle.ViewModel // Or use a simple observable class if not using ViewModel directly

// --- Enums for State and Directions ---

enum class SelfieCheckStep {
    INITIAL, // Waiting to start or initial prompt
    CENTER_FACE,
    ROTATE_HEAD_LEFT,
    ROTATE_HEAD_RIGHT,
    ROTATE_HEAD_UP,
    ROTATE_HEAD_DOWN,
    CLOSE_EYES,
    SMILE,
    COMPLETED,
    FAILED // Optional: For error states
}

enum class HeadRotationDirection {
    LEFT, RIGHT, UP, DOWN
}

// --- Thresholds (Consider making these configurable) ---
private const val FACE_CENTER_TOLERANCE = 0.1f // e.g., 10% tolerance from center
private const val HEAD_ROTATION_ANGLE_THRESHOLD = 20.0f // degrees
private const val EYE_CLOSED_THRESHOLD = 0.3f // ML Kit probability (0.0 = closed, 1.0 = open)
private const val SMILING_THRESHOLD = 0.7f // ML Kit probability

class SelfieCheckViewModel : ViewModel() { // Or a plain Kotlin class if not using Android ViewModel

    // --- Observable State for the UI ---
    val currentStep = mutableStateOf(SelfieCheckStep.INITIAL)
    val instructionText = mutableStateOf("Please position your face in the frame.") // Example initial instruction

    // --- Internal State Management ---
    private var requiredRotations = mutableListOf<HeadRotationDirection>()
    private var completedRotations = mutableSetOf<HeadRotationDirection>()

    // --- Public Methods to Control the Flow ---

    fun startSelfieCheck() {
        resetState()
        currentStep.value = SelfieCheckStep.CENTER_FACE
        updateInstructionText()
    }

    private fun resetState() {
        requiredRotations.clear()
        completedRotations.clear()
        // Initialize random order of rotations
        val allRotations = HeadRotationDirection.values().toMutableList()
        allRotations.shuffle()
        requiredRotations.addAll(allRotations)
        currentStep.value = SelfieCheckStep.INITIAL
        updateInstructionText()
    }

    // --- Methods to be called by ML Kit data processing ---

    /**
     * Call this with the normalized bounding box of the detected face.
     * x, y, width, height should be in range [0.0, 1.0] relative to the preview size.
     */
    fun onFaceDetected(faceBounds: FaceBounds?) {
        if (currentStep.value != SelfieCheckStep.CENTER_FACE || faceBounds == null) return

        val centerX = faceBounds.x + faceBounds.width / 2
        val centerY = faceBounds.y + faceBounds.height / 2

        // Check if face is reasonably centered
        if (kotlin.math.abs(centerX - 0.5f) < FACE_CENTER_TOLERANCE &&
            kotlin.math.abs(centerY - 0.5f) < FACE_CENTER_TOLERANCE
        ) {
            proceedToNextRotation()
        } else {
            // Optionally, provide feedback if not centered
            // instructionText.value = "Keep your face centered."
        }
    }

    /**
     * Call this with Euler angles from ML Kit.
     * headEulerAngleY for left/right (yaw)
     * headEulerAngleX for up/down (pitch)
     */
    fun onHeadPoseDetected(headEulerAngleX: Float, headEulerAngleY: Float, headEulerAngleZ: Float) {
        when (currentStep.value) {
            SelfieCheckStep.ROTATE_HEAD_LEFT -> {
                if (headEulerAngleY > HEAD_ROTATION_ANGLE_THRESHOLD) { // Positive Y is often left
                    markRotationComplete(HeadRotationDirection.LEFT)
                }
            }
            SelfieCheckStep.ROTATE_HEAD_RIGHT -> {
                if (headEulerAngleY < -HEAD_ROTATION_ANGLE_THRESHOLD) { // Negative Y is often right
                    markRotationComplete(HeadRotationDirection.RIGHT)
                }
            }
            SelfieCheckStep.ROTATE_HEAD_UP -> {
                if (headEulerAngleX > HEAD_ROTATION_ANGLE_THRESHOLD) { // Positive X is often up
                    markRotationComplete(HeadRotationDirection.UP)
                }
            }
            SelfieCheckStep.ROTATE_HEAD_DOWN -> {
                if (headEulerAngleX < -HEAD_ROTATION_ANGLE_THRESHOLD) { // Negative X is often down
                    markRotationComplete(HeadRotationDirection.DOWN)
                }
            }
            else -> return // Not in a rotation step
        }
    }

    /**
     * Call this with eye open probabilities from ML Kit.
     */
    fun onEyeStateDetected(leftEyeOpenProbability: Float?, rightEyeOpenProbability: Float?) {
        if (currentStep.value != SelfieCheckStep.CLOSE_EYES) return

        if (leftEyeOpenProbability != null && rightEyeOpenProbability != null &&
            leftEyeOpenProbability < EYE_CLOSED_THRESHOLD &&
            rightEyeOpenProbability < EYE_CLOSED_THRESHOLD
        ) {
            currentStep.value = SelfieCheckStep.SMILE
            updateInstructionText()
        }
    }

    /**
     * Call this with smiling probability from ML Kit.
     */
    fun onSmileDetected(smilingProbability: Float?) {
        if (currentStep.value != SelfieCheckStep.SMILE || smilingProbability == null) return

        if (smilingProbability > SMILING_THRESHOLD) {
            currentStep.value = SelfieCheckStep.COMPLETED
            updateInstructionText()
            // Potentially trigger final action (e.g., capture image, notify completion)
        }
    }

    // --- Helper Methods ---

    private fun proceedToNextRotation() {
        if (requiredRotations.isEmpty()) {
            // All rotations done, move to close eyes
            currentStep.value = SelfieCheckStep.CLOSE_EYES
        } else {
            val nextRotation = requiredRotations.removeAt(0)
            currentStep.value = when (nextRotation) {
                HeadRotationDirection.LEFT -> SelfieCheckStep.ROTATE_HEAD_LEFT
                HeadRotationDirection.RIGHT -> SelfieCheckStep.ROTATE_HEAD_RIGHT
                HeadRotationDirection.UP -> SelfieCheckStep.ROTATE_HEAD_UP
                HeadRotationDirection.DOWN -> SelfieCheckStep.ROTATE_HEAD_DOWN
            }
        }
        updateInstructionText()
    }

    private fun markRotationComplete(direction: HeadRotationDirection) {
        if (completedRotations.add(direction)) { // Ensures we only process each direction once
            // Optionally, provide immediate feedback for successful rotation
            // showToast("Head ${direction.name.toLowerCase()} detected!")
            proceedToNextRotation()
        }
    }

    private fun updateInstructionText() {
        instructionText.value = when (currentStep.value) {
            SelfieCheckStep.INITIAL -> "Get ready for selfie check."
            SelfieCheckStep.CENTER_FACE -> "Please center your face in the oval."
            SelfieCheckStep.ROTATE_HEAD_LEFT -> "Slowly turn your head to the LEFT."
            SelfieCheckStep.ROTATE_HEAD_RIGHT -> "Slowly turn your head to the RIGHT."
            SelfieCheckStep.ROTATE_HEAD_UP -> "Slowly tilt your head UP."
            SelfieCheckStep.ROTATE_HEAD_DOWN -> "Slowly tilt your head DOWN."
            SelfieCheckStep.CLOSE_EYES -> "Please close your eyes."
            SelfieCheckStep.SMILE -> "Now, please smile!"
            SelfieCheckStep.COMPLETED -> "Selfie check completed! Thank you."
            SelfieCheckStep.FAILED -> "Selfie check failed. Please try again."
        }
    }

    fun getCurrentStep(): SelfieCheckStep = currentStep.value
}

// Simple data class for face bounds (assuming normalized coordinates)
data class FaceBounds(val x: Float, val y: Float, val width: Float, val height: Float)