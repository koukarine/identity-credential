package org.multipaz.compose.camera

/**
 * Common interface for all custom Camera plugins.
 */
interface CameraPlugin {
    /**
     * Initializes the plugin with the provided [Camera].
     *
     * @param camera The [Camera] instance this plugin will be using.
     */
    fun initialize(camera: Camera)
}