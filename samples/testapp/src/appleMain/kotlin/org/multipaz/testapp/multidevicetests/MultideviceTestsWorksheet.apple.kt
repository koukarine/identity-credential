package org.multipaz.testapp.multidevicetests

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.io.files.Path
import org.multipaz.util.Logger
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSSearchPathForDirectoriesInDomains
import platform.Foundation.NSURL
import platform.Foundation.NSUserDomainMask
import platform.UIKit.UIActivityViewController
import platform.UIKit.UIApplication

private const val TAG = "MultideviceTestsWorksheet"

actual fun getPlatformDocumentsFolderPath(filename: String): Path? {
    val documentsPath = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory,
        NSUserDomainMask,
        true
    ).firstOrNull() as? String ?: error("Could not get Documents directory path")

    return Path("$documentsPath/$filename")
}

@OptIn(BetaInteropApi::class, ExperimentalForeignApi::class)
actual fun shareCsvFile() {
    val csvFilePath = generateCsvFilePath()
    if (csvFilePath == null) {
        Logger.e(TAG, "Error: CSV file path is null")
        return
    }

    val fileURL = NSURL.fileURLWithPath(csvFilePath.toString())
    if (!fileURL.checkResourceIsReachableAndReturnError(null)) {
        Logger.e(TAG, "Error: File not found or not reachable at $csvFilePath")
        return
    }

    val activityItems = listOf(fileURL)
    val activityViewController = UIActivityViewController(activityItems, null)
    var currentViewController = UIApplication.sharedApplication.keyWindow?.rootViewController
    while (currentViewController?.presentedViewController != null) {
        currentViewController = currentViewController.presentedViewController
    }

    if (currentViewController != null) {
        // TODO: On iPad, UIActivityViewController needs to be presented as a popover.
        //   You might need to provide sourceView and sourceRect for UIPopoverPresentationController.
        //   This impl doesn't explicitly handle iPad popover anchoring.
        //   e.g.: activityViewController.popoverPresentationController?.sourceView = currentViewController.view
        currentViewController.presentViewController(activityViewController, animated = true, completion = null)
    } else {
        Logger.e(TAG, "Error: Could not find a view controller to present the share sheet.")
    }
}