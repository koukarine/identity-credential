package org.multipaz.compose.camera

/**
 * iOS platform-specific implementation of [CameraBuilder].
 */
class IosCameraBuilder : CameraBuilder {

    private var cameraSelection: CameraSelection = CameraSelection.DEFAULT_BACK_CAMERA
    private val plugins = mutableListOf<CameraPlugin>()

    override fun setCameraLens(cameraSelection: CameraSelection): CameraBuilder {
        this.cameraSelection = cameraSelection
        return this
    }

    override fun addPlugin(plugin: CameraPlugin): CameraBuilder {
        plugins.add(plugin)
        return this
    }

    override fun build(): Camera {
        val camera = Camera(
            cameraSelection = cameraSelection,
            plugins = plugins
        )

        return camera
    }
}