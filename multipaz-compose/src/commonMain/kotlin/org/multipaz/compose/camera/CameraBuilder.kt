package org.multipaz.compose.camera

/**
 * Construct a Camera component with customizable configuration and plugins for a particular use case.
 */
interface CameraBuilder {
    /**
     * Sets the camera lens (front or back) for the [Camera].
     *
     * @param cameraSelection The camera lens ID to set
     * @see: [CameraSelection].
     */
    fun setCameraLens(cameraSelection: CameraSelection): CameraBuilder

    /**
     * Adds a [CameraPlugin] to the [Camera].
     *
     * @param plugin The plugin to add.
     * @return The current instance of [CameraBuilder].
     */
    fun addPlugin(plugin: CameraPlugin): CameraBuilder

    /**
     * Builds a [Camera] object with the provided configurations and plugins.
     *
     * @return The fully constructed [Camera] object.
     */
    fun build(): Camera
}