package org.multipaz.compose.camera

/**
 * Camera operations API
 */
expect class Camera {
    /**
     * Starts the camera session.
     */
    fun startSession()

    /**
     * Stops the camera session.
     */
    fun stopSession()

    /**
     * Initiates the process of retrieving the image data.
     *
     * @return The result of the image capture operation (data or error).
     */
    suspend fun takeCameraFrame(): CameraWorkResult

    /**
     * Adds a listener for camera frame capture event (generic data).
     *
     * @param listener The new listener receiving image data as [ByteArray].
     */
    fun addFrameCaptureListener(listener: (ByteArray) -> Unit)

    /**
     * Initialize/reset camera plugins (i.e.face recognition, face matcher, bar code scanner).
     */
    fun initializePlugins()

    /**
     * Save the sensorSize of the selected camera.
     */
    fun saveSensorSize()

    /** Retrieve aspect ratio from sensor size */
    fun getAspectRatio(): Double

}