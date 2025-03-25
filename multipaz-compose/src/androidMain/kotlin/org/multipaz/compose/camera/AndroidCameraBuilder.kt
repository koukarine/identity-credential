package org.multipaz.compose.camera

import android.content.Context
import androidx.lifecycle.LifecycleOwner

/**
 * Android-specific implementation of [CameraBuilder].
 *
 * @param context The Android [Context], typically an Activity or Application context.
 * @param lifecycleOwner The [LifecycleOwner], usually the hosting Activity or Fragment.
 */
class AndroidCameraBuilder(
    private val context: Context,
    private val lifecycleOwner: LifecycleOwner
) : CameraBuilder {

    private var cameraSelection = CameraSelection.DEFAULT_BACK_CAMERA

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
            context = context,
            lifecycleOwner = lifecycleOwner,
            cameraSelection = cameraSelection,
            plugins = plugins,
        )

        plugins.forEach {
            it.initialize(camera)
        }

        return camera
    }
}