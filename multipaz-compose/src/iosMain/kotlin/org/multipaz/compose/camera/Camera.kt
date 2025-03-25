package org.multipaz.compose.camera

import kotlinx.atomicfu.atomic
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.suspendCancellableCoroutine
import org.multipaz.util.toByteArray
import platform.Foundation.NSDate
import platform.Foundation.NSTimeInterval
import platform.Foundation.date
import platform.Foundation.timeIntervalSince1970
import platform.UIKit.UIImageJPEGRepresentation
import platform.UIKit.UIViewController
import kotlin.coroutines.resume
import kotlinx.cinterop.autoreleasepool
import org.multipaz.util.Logger
import platform.UIKit.UIImage

/** iOS platform-specific implementation of [Camera]. */
@Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")
actual class Camera(
    internal var cameraSelection: CameraSelection,
    internal var plugins: MutableList<CameraPlugin>
) : UIViewController(nibName = null, bundle = null) {
    private val TAG = "Camera"
    private val cameraController = CameraViewController()
    private var imageCaptureListeners = mutableListOf<(ByteArray) -> Unit>()
    private var isCapturing = atomic(false)
    private val throttlePeriod = 500L
    private var lastCaptureTime: NSTimeInterval = 0.0

    override fun viewDidLoad() {
        super.viewDidLoad()
        setupCamera()
    }

    fun getCameraPreviewLayer() = cameraController.previewLayer

    internal fun currentVideoOrientation() = cameraController.currentVideoOrientation()

    private fun setupCamera() {
        with (cameraController) {
            setupSession(cameraSelection)
            setupPreviewLayer(view)

            startSession()

            onFrameCapture = { image ->
                image?.let {
                    val data = it.toByteArray()
                    imageCaptureListeners.forEach { it(data) }
                }
            }

            onError = { error ->
                Logger.d(TAG, "Camera Error: $error")
            }
        }
    }

    @OptIn(ExperimentalForeignApi::class)
    override fun viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        cameraController.previewLayer?.setFrame(view.bounds)
    }

    actual fun startSession() {
        cameraController.startSession()

        initializePlugins()
    }

    actual fun stopSession() {
        cameraController.stopSession()
    }

    actual fun initializePlugins() {
        plugins.forEach {
            it.initialize(this)
        }
    }

    /**
     * Captures an image with the capture frequency throttling.
     *
     * @return The result of the image capture operation.
     */
    @OptIn(BetaInteropApi::class)
    actual suspend fun takeCameraFrame(): CameraWorkResult = suspendCancellableCoroutine { continuation ->
        val currentTime = NSDate.date().timeIntervalSince1970()
        if (currentTime - lastCaptureTime < throttlePeriod) {
            continuation.resume(CameraWorkResult.Error(Exception("Capture too frequent")))
            return@suspendCancellableCoroutine
        }

        if (!isCapturing.compareAndSet(false, true)) {
            continuation.resume(CameraWorkResult.Error(Exception("Capture already in progress")))
            return@suspendCancellableCoroutine
        }

        cameraController.onFrameCapture = { image ->
            try {
                if (image != null) {
                    autoreleasepool {
                        // Using UIImageJPEGRepresentation to convert to JPEG formatJPEG Format {
                        UIImageJPEGRepresentation(UIImage(image), 0.9)?.toByteArray()
                            ?.let { imageData ->
                                continuation.resume(CameraWorkResult.FrameCaptureSuccess(imageData))
                            } ?: run {
                            continuation.resume(CameraWorkResult.Error(Exception("JPEG conversion failed")))
                        }
                    }
                } else {
                    continuation.resume(CameraWorkResult.Error(Exception("Capture failed - null image")))
                }
            } finally {
                lastCaptureTime = NSDate.date().timeIntervalSince1970()
                isCapturing.compareAndSet(expect = true, update = false)
                cameraController.onFrameCapture = null
            }
        }

        continuation.invokeOnCancellation {
            cameraController.onFrameCapture = null
            isCapturing.compareAndSet(expect = true, update = false)
        }

        cameraController.captureFrame()
    }

    /**
     * Adds a listener for camera frame capture event.
     *
     * @param listener The new listener receiving image data as [ByteArray].
     */
    actual fun addFrameCaptureListener(listener: (ByteArray) -> Unit) {
        imageCaptureListeners.add(listener)
    }

    actual fun saveSensorSize() {
        TODO("Not yet implemented")
    }

    actual fun getAspectRatio() : Double {
        TODO("Not yet implemented")
    }
}