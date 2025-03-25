package org.multipaz.compose.camera

import android.content.Context
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageCapture
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.lifecycle.LifecycleOwner
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.Preview
import androidx.core.content.ContextCompat

/**
 * Android platform implementation of [Camera] using CameraX.
 *
 * @param context The Android [Context].
 * @param lifecycleOwner The [LifecycleOwner] to bind the camera lifecycle.
 * @param cameraSelection The desired [CameraLens].
 */
actual class Camera(
    val context: Context,
    val lifecycleOwner: LifecycleOwner,
    internal var cameraSelection: CameraSelection,
    internal var plugins: MutableList<CameraPlugin>
) {
    private val TAG = "Camera"
    private var cameraProvider: ProcessCameraProvider? = null
    private var imageCapture: ImageCapture? = null
    private var preview: Preview? = null
    private var camera: Camera? = null
    private var previewView: PreviewView? = null
    var imageAnalyzer: ImageAnalysis? = null

    private val imageCaptureListeners = mutableListOf<(ByteArray) -> Unit>()

    actual fun startSession() {
        // CameraX handles session start based on lifecycle
    }

    actual fun stopSession() {
        cameraProvider?.unbindAll()
    }

    /**
     * Initialize/reset camera plugins (i.e.face recognition, face matcher, bar code scanner).
     */
    actual fun initializePlugins() {
        plugins.forEach { it.initialize(this) }
    }

    /**
     * Capture the frame.
     *
     * @return The result of the image capture operation.
     */
    actual suspend fun takeCameraFrame(): CameraWorkResult {
        return CameraWorkResult.Error(Exception("Not yet implemented"))
    }

    /**
     * Adds a listener for camera frame capture event.
     *
     * @param listener The new listener receiving image data as [ByteArray].
     */
    actual fun addFrameCaptureListener(listener: (ByteArray) -> Unit) {
    }

    fun bindCamera(previewView: PreviewView, onCameraReady: () -> Unit = {}) {
        this.previewView = previewView
        val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
        cameraProviderFuture.addListener({
            try {
                cameraProvider = cameraProviderFuture.get()
                cameraProvider?.unbindAll()

                preview = Preview.Builder()
                    .build()
                    .also {
                        it.setSurfaceProvider(previewView.surfaceProvider)
                    }

                val cameraSelector = CameraSelector.Builder()
                    .requireLensFacing(cameraSelection.toCameraXLensFacing())
                    .build()


                imageCapture = ImageCapture.Builder()
                    .setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY)
                    .build()

                // Setup ImageAnalysis Use Case only if needed
                val useCases = mutableListOf(preview!!, imageCapture!!)
                imageAnalyzer?.let { useCases.add(it) }

                camera = cameraProvider?.bindToLifecycle(
                    lifecycleOwner,
                    cameraSelector,
                    *useCases.toTypedArray()
                )

                onCameraReady()

            } catch (exc: Exception) {
                println("Use case binding failed: ${exc.message}")
            }

        }, ContextCompat.getMainExecutor(context))
    }

    fun updateImageAnalyzer() {
        camera?.let {
            cameraProvider?.unbind(imageAnalyzer)
            imageAnalyzer?.let { analyzer ->
                cameraProvider?.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.Builder().requireLensFacing(cameraSelection.toCameraXLensFacing())
                        .build(),
                    analyzer // Only bind the analyzer
                )
            }
        } ?: throw CameraExceptionInvalidConfiguration("Camera not initialized.")
    }
}

private fun CameraSelection.toCameraXLensFacing(): Int =
    when (this) {
        CameraSelection.DEFAULT_FRONT_CAMERA -> CameraSelector.LENS_FACING_FRONT
        CameraSelection.DEFAULT_BACK_CAMERA -> CameraSelector.LENS_FACING_BACK
        else -> throw CameraExceptionInvalidConfiguration("Invalid camera selection: $this")
    }

