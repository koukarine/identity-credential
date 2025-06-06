package org.multipaz.selfiecheck

import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.multipaz.facedetection.DetectedFace
import org.multipaz.util.Logger
import kotlin.random.Random

// todo: recompose for landscape somehow.

enum class SelfieCheckStep {
    INITIAL,
    CENTER_FACE,
    ROTATE_HEAD_LEFT,
    ROTATE_HEAD_RIGHT,
    ROTATE_HEAD_UP,
    ROTATE_HEAD_DOWN,
    CLOSE_EYES,
    SMILE,
    COMPLETED,
    FAILED
}

enum class HeadRotationDirection {
    LEFT, RIGHT, UP, DOWN
}

private const val TAG = "SelfieCheck"
private const val FACE_CENTER_TOLERANCE = 0.1f
private const val HEAD_ROTATION_ANGLE_THRESHOLD = 20.0f
private const val EYE_CLOSED_THRESHOLD = 0.1f
private const val SMILING_THRESHOLD = 0.7f
private const val STEP_TIMEOUT_SECONDS = 10 // Timeout in seconds
private const val ONE_SECOND_MS = 1000L

class SelfieCheckViewModel(externalScope: CoroutineScope? = null) {
    private val viewModelScope = externalScope ?: CoroutineScope(Dispatchers.Default + SupervisorJob())

    private val stepSuccessEventFlow = MutableSharedFlow<Unit>(
        extraBufferCapacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    private val currentStepFlow = MutableStateFlow(SelfieCheckStep.INITIAL)

    val currentStep: StateFlow<SelfieCheckStep> = currentStepFlow.asStateFlow()
    private val instructionTextFlow = MutableStateFlow("Please position your face in the frame.")

    val instructionText: StateFlow<String> = instructionTextFlow.asStateFlow()
    private var requiredRotations = mutableListOf<HeadRotationDirection>()
    private var completedRotations = mutableSetOf<HeadRotationDirection>()

    private var currentRotationTarget: HeadRotationDirection? = null
    val stepSuccessEvent: SharedFlow<Unit> = stepSuccessEventFlow.asSharedFlow()
    private var stepTimeoutJob: Job? = null
    private val countdownSecondsFlow = MutableStateFlow(STEP_TIMEOUT_SECONDS)
    val countdownSeconds: StateFlow<Int> = countdownSecondsFlow.asStateFlow()

    // New StateFlow for progress (0.0 to 1.0) for the CircularProgressIndicator
    private val countdownProgressFlow = MutableStateFlow(1.0f)
    val countdownProgress: StateFlow<Float> = countdownProgressFlow.asStateFlow()

    init {
        updateInstructionText()
        countdownSecondsFlow.value = STEP_TIMEOUT_SECONDS // Initialize countdown
        countdownProgressFlow.value = 1.0f
    }

    fun startSelfieCheck() {
        resetState()
        currentStepFlow.value = SelfieCheckStep.CENTER_FACE
        updateInstructionText()
        startStepTimeout()
    }

    private fun resetState() {
        requiredRotations.clear()
        completedRotations.clear()
        currentRotationTarget = null
        val allRotations = HeadRotationDirection.entries.toMutableList()
        var currentIndex = allRotations.size
        while (currentIndex != 0) {
            val randomIndex = Random.nextInt(currentIndex)
            currentIndex--
            val temporaryValue = allRotations[currentIndex]
            allRotations[currentIndex] = allRotations[randomIndex]
            allRotations[randomIndex] = temporaryValue
        }
        requiredRotations.addAll(allRotations)
        currentStepFlow.value = SelfieCheckStep.INITIAL // Reset step
        updateInstructionText() // Update instruction for initial state
    }

    /**
     * Update model on new frame with detected face data and frame size to feed current check processor.
     */
    internal fun onFaceDataUpdated(faceData: DetectedFace, previewSize: Size) {
        // Do not process if already completed or failed.
        if (currentStepFlow.value == SelfieCheckStep.COMPLETED || currentStepFlow.value == SelfieCheckStep.FAILED) {
            return
        }

        when (currentStepFlow.value) {
            SelfieCheckStep.CENTER_FACE -> {
                processFaceCentering(faceData.boundingBox, previewSize)
            }

            SelfieCheckStep.ROTATE_HEAD_LEFT,
            SelfieCheckStep.ROTATE_HEAD_RIGHT,
            SelfieCheckStep.ROTATE_HEAD_UP,
            SelfieCheckStep.ROTATE_HEAD_DOWN -> {
                processHeadRotation(
                    targetDirection = currentRotationTarget, // The direction we are currently asking for
                    headEulerAngleX = faceData.headEulerAngleX,
                    headEulerAngleY = faceData.headEulerAngleY
                )
            }

            SelfieCheckStep.CLOSE_EYES -> {
                processEyeClosure(faceData.leftEyeOpenProbability, faceData.rightEyeOpenProbability)
            }

            SelfieCheckStep.SMILE -> {
                processSmile(faceData.smilingProbability)
            }

            else -> { /* INITIAL, COMPLETED, FAILED - no processing needed. */
            }
        }
    }

    private fun startStepTimeout() {
        cancelStepTimeout() // Cancel previous timeout if any
        countdownSecondsFlow.value = STEP_TIMEOUT_SECONDS // Reset for new step
        countdownProgressFlow.value = 1.0f

        // Only start timeout for actionable steps
        val current = currentStepFlow.value
        if (current == SelfieCheckStep.INITIAL
            || current == SelfieCheckStep.COMPLETED
            || current == SelfieCheckStep.FAILED) {
            return
        }

        stepTimeoutJob = viewModelScope.launch {
            for (i in STEP_TIMEOUT_SECONDS downTo 0) {
                if (!isActive) break // Exit if job is cancelled.

                countdownSecondsFlow.value = i
                countdownProgressFlow.value = i.toFloat() / STEP_TIMEOUT_SECONDS.toFloat()

                if (i == 0) {
                    // Timeout reached only if the step hasn't been completed/failed by other means
                    if (currentStepFlow.value != SelfieCheckStep.COMPLETED
                        && currentStepFlow.value != SelfieCheckStep.FAILED) {
                        Logger.w(TAG, "SelfieCheck: Step '${currentStepFlow.value}' timed out.")
                        failCheck("Step timed out.")
                    }
                    break // Exit loop
                }
                delay(ONE_SECOND_MS)
            }
        }
    }

    private fun cancelStepTimeout() {
        stepTimeoutJob?.cancel()
        stepTimeoutJob = null
    }

    private fun failCheck(reason: String) {
        cancelStepTimeout()
        currentStepFlow.value = SelfieCheckStep.FAILED
        instructionTextFlow.value = "Verification Failed: $reason Please try again."
        countdownSecondsFlow.value = 0 // Show 0 on failure
        countdownProgressFlow.value = 0.0f
    }

    private fun processFaceCentering(faceBounds: Rect?, previewSize: Size?) {
        if ((faceBounds == null || previewSize == null) || previewSize.width < 1 || previewSize.height < 1) {
            instructionTextFlow.value = "Cannot detect face position. Ensure camera is active." // Or similar
            return
        }

        // Calculate the center of the face in pixels
        val faceCenterXpx = faceBounds.left + faceBounds.width / 2f
        val faceCenterYpx = faceBounds.top + faceBounds.height / 2f

        // Normalize the face center coordinates with respect to the preview dimensions
        // This gives a value between 0.0 and 1.0 if the face is within the preview
        val normalizedFaceCenterX = faceCenterXpx / previewSize.width
        val normalizedFaceCenterY = faceCenterYpx / previewSize.height

        // Check if the normalized center is within the tolerance of the preview's center (0.5, 0.5)
        val isHorizontallyCentered = kotlin.math.abs(normalizedFaceCenterX - 0.5f) < FACE_CENTER_TOLERANCE
        val isVerticallyCentered = kotlin.math.abs(normalizedFaceCenterY - 0.5f) < FACE_CENTER_TOLERANCE

        if (isHorizontallyCentered && isVerticallyCentered) {
            proceedToNextStep()
        } else {
            if (kotlin.math.abs(normalizedFaceCenterX - 0.5f) >= FACE_CENTER_TOLERANCE) {
                instructionTextFlow.value = "Move face horizontally to center."
            } else {
                instructionTextFlow.value = "Move face vertically to center."
            }
        }
    }

    private fun processHeadRotation(
        targetDirection: HeadRotationDirection?,
        headEulerAngleX: Float?,
        headEulerAngleY: Float?
    ) {
        if (targetDirection == null || headEulerAngleX == null || headEulerAngleY == null) return

        val achieved = when (targetDirection) {
            HeadRotationDirection.LEFT -> headEulerAngleY > HEAD_ROTATION_ANGLE_THRESHOLD
            HeadRotationDirection.RIGHT -> headEulerAngleY < -HEAD_ROTATION_ANGLE_THRESHOLD
            HeadRotationDirection.UP -> headEulerAngleX > HEAD_ROTATION_ANGLE_THRESHOLD
            HeadRotationDirection.DOWN -> headEulerAngleX < -HEAD_ROTATION_ANGLE_THRESHOLD
        }

        if (achieved) {
            if (completedRotations.add(targetDirection)) { // Ensure we only mark it complete once
                proceedToNextStep()
            }
        }
    }

    private fun processEyeClosure(leftEyeOpenProbability: Float?, rightEyeOpenProbability: Float?) {
        if (leftEyeOpenProbability != null && rightEyeOpenProbability != null &&
            leftEyeOpenProbability < EYE_CLOSED_THRESHOLD &&
            rightEyeOpenProbability < EYE_CLOSED_THRESHOLD
        ) {
            proceedToNextStep()
        }
    }

    private fun processSmile(smilingProbability: Float?) {
        if (smilingProbability != null && smilingProbability > SMILING_THRESHOLD) {
            proceedToNextStep()
        }
    }

    private fun proceedToNextStep() {
        cancelStepTimeout() // Step completed successfully, cancel its timeout

        val successfullyAdvanced = when (val previousStep = currentStepFlow.value) {
            SelfieCheckStep.CENTER_FACE -> {
                // Start first rotation.
                moveToNextRotationOrCompletion()
                true
            }

            SelfieCheckStep.ROTATE_HEAD_LEFT,
            SelfieCheckStep.ROTATE_HEAD_RIGHT,
            SelfieCheckStep.ROTATE_HEAD_UP,
            SelfieCheckStep.ROTATE_HEAD_DOWN -> {
                // Current rotation done, try next one.
                moveToNextRotationOrCompletion()
                currentStepFlow.value != previousStep
            }

            SelfieCheckStep.CLOSE_EYES -> {
                currentStepFlow.value = SelfieCheckStep.SMILE
                true
            }

            SelfieCheckStep.SMILE -> {
                currentStepFlow.value = SelfieCheckStep.COMPLETED
                true
            }

            else -> false
        }

        // Signal back step success for haptic feedback in composable and UI alterations.
        if (successfullyAdvanced && currentStepFlow.value != SelfieCheckStep.INITIAL) {
            stepSuccessEventFlow.tryEmit(Unit)
        }

        updateInstructionText()

        if (currentStepFlow.value == SelfieCheckStep.COMPLETED) {
            countdownSecondsFlow.value = STEP_TIMEOUT_SECONDS // Or specific value for completed state
            countdownProgressFlow.value = 1.0f
        } else if (currentStepFlow.value != SelfieCheckStep.FAILED) {
            startStepTimeout() // Start timeout for the *new* step
        }
    }

    private fun moveToNextRotationOrCompletion() {
        if (requiredRotations.isEmpty()
            && currentStepFlow.value != SelfieCheckStep.CLOSE_EYES
            && currentStepFlow.value != SelfieCheckStep.SMILE) { // Ensure it's post-rotation
            if (completedRotations.size == HeadRotationDirection.entries.size) { // All rotations done
                currentStepFlow.value = SelfieCheckStep.CLOSE_EYES
            } else {
                Logger.w(TAG, "Unexpected face direction rotation sequence error.")
            }
        } else if (requiredRotations.isNotEmpty()){
            currentRotationTarget = requiredRotations.removeAt(0)
            currentStepFlow.value = when (currentRotationTarget) {
                HeadRotationDirection.LEFT -> SelfieCheckStep.ROTATE_HEAD_LEFT
                HeadRotationDirection.RIGHT -> SelfieCheckStep.ROTATE_HEAD_RIGHT
                HeadRotationDirection.UP -> SelfieCheckStep.ROTATE_HEAD_UP
                HeadRotationDirection.DOWN -> SelfieCheckStep.ROTATE_HEAD_DOWN
                null -> SelfieCheckStep.FAILED // Should ideally not happen
            }
        }
    }

    private fun updateInstructionText() { //todo: move to composable to grab strings from resources?
        instructionTextFlow.value = when (currentStepFlow.value) {
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
}