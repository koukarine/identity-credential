package org.multipaz.testapp.multidevicetests

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Environment
import androidx.core.content.FileProvider
import kotlinx.io.files.Path
import org.multipaz.context.applicationContext
import org.multipaz.util.Logger
import java.io.File

private const val TAG = "MultideviceTestsWorksheet"

actual fun getPlatformDocumentsFolderPath(filename: String): Path? {
    val documentsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)
    if (!documentsDir.exists()) {
        documentsDir.mkdirs()
    }
    val file = File(documentsDir, filename)
    return Path(file.absolutePath)
}

actual fun shareCsvFile() {
    val csvFilePath = generateCsvFilePath()
    if (csvFilePath == null) {
        Logger.e(TAG, "Error: CSV file path is null")
        return
    }

    val context: Context = applicationContext

    val file = File(csvFilePath.toString())
    if (!file.exists()) {
        Logger.w(TAG, "Error: File not found at $csvFilePath")
        return
    }

    val authority = "${context.packageName}.provider"
    val contentUri = FileProvider.getUriForFile(context, authority, file)

    val shareIntent = Intent(Intent.ACTION_SEND).apply {
        type = "text.csv"
        putExtra(Intent.EXTRA_STREAM, contentUri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        putExtra(Intent.EXTRA_SUBJECT, "Data File from Multipaz TeatApp")
    }

    val chooserIntent = Intent.createChooser(shareIntent, "Share MultideviceTestsWorksheet csv file")

    if (context is Activity) {
        context.startActivity(chooserIntent)
    } else {
        chooserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            context.startActivity(chooserIntent)
        } catch (e: Exception) {
            Logger.w(TAG, "Error starting share activity: ${e.message}")
        }
    }
}