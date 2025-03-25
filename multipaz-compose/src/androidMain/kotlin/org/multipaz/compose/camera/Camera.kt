package org.multipaz.compose.camera

import android.content.Context
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraManager
import android.util.Size
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageCapture
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.lifecycle.LifecycleOwner
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.Preview
import androidx.core.content.ContextCompat
import org.multipaz.util.Logger

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
    private val TAG = "Camear ZAND"
    private var cameraProvider: ProcessCameraProvider? = null
    private var imageCapture: ImageCapture? = null
    private var preview: Preview? = null
    private var camera: Camera? = null
    private var previewView: PreviewView? = null
    var sensorSize = Size(1, 1)
    var cameraPreviewAspectRatio: Double = 1.0
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

    actual fun saveSensorSize() {
        sensorSize = getCameraSensorSize(context, cameraSelection.toCameraXLensFacing())
        cameraPreviewAspectRatio = sensorSize.height.toDouble() / sensorSize.width.toDouble()
        Logger.d(TAG, "Camera preview aspect ratio: $cameraPreviewAspectRatio")
    }

    actual fun getAspectRatio() : Double {
        Logger.d(TAG, "Camera preview aspect ratio: $cameraPreviewAspectRatio")
        return cameraPreviewAspectRatio
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

                val cameraId = cameraSelection.toCameraXLensFacing()
                val cameraSelector = CameraSelector.Builder()
                    .requireLensFacing(cameraId)
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

                /*//todo: Also see if this is needed  in [updateImageAnalyzer]
                previewView.post {
                    val streamResolutionWidth = previewView.width
                    val streamResolutionHeight = previewView.height
                    cameraPreviewAspectRatio =
                        streamResolutionWidth.toFloat() / streamResolutionHeight.toFloat()

                    Logger.d(TAG, "$streamResolutionWidth:$streamResolutionHeight aspect ($cameraPreviewAspectRatio)")
                }*/

                onCameraReady()

            } catch (exc: Exception) {
                Logger.d(TAG, "Use case binding failed: ${exc.message}")
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

internal fun CameraSelection.toCameraXLensFacing(): Int =
    when (this) {
        CameraSelection.DEFAULT_FRONT_CAMERA -> CameraSelector.LENS_FACING_FRONT
        CameraSelection.DEFAULT_BACK_CAMERA -> CameraSelector.LENS_FACING_BACK
        else -> throw CameraExceptionInvalidConfiguration("Invalid camera selection: $this")
    }

private fun getCameraSensorSize(context: Context, cameraId: Int): Size {
    val cameraManager = context.getSystemService(Context.CAMERA_SERVICE) as CameraManager
    return cameraManager.cameraIdList.find { id ->
        cameraManager.getCameraCharacteristics(id).get(CameraCharacteristics.LENS_FACING) == cameraId
    }?.let { cameraName ->
        cameraManager.getCameraCharacteristics(cameraName)
            .get(CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE)
    }!!
}