package org.multipaz.testapp.multidevicetests

import kotlinx.io.files.Path
import org.multipaz.util.Logger

/**
 * Format data for the worksheet csv file line.
 *
 * @param devices The device names pair that were tested. If empty (default) the worksheet is not populating.
 * @param runsAttempted The number of times the test was run.
 * @param runsCompleted The number of times the test was run successfully.
 * @param transactionTimeAverage The average transaction time in milliseconds.
 * @param transactionTimeMin The minimum transaction time in milliseconds.
 * @param transactionTimeMax The maximum transaction time in milliseconds.
 * @param transactionTimeSigma The standard deviation of the transaction times in milliseconds.
 * @param scanTimeAverage The average scan time in milliseconds.
 * @param scanTimeMin The minimum scan time in milliseconds.
 * @param scanTimeMax The maximum scan time in milliseconds.
 * @param scanTimeSigma The standard deviation of the scan times in milliseconds.
 * @return The formatted data string with the colon (:) separators.
 */
fun formatData(
    devices: String,
    runsAttempted: Int,
    runsSucceeded: Int,
    transactionTimeAverage: Int,
    transactionTimeMin: Int,
    transactionTimeMax: Int,
    transactionTimeSigma: Int,
    scanTimeAverage: Int,
    scanTimeMin: Int,
    scanTimeMax: Int,
    scanTimeSigma: Int,
): String =
    "$devices:$runsAttempted:$runsSucceeded:$transactionTimeAverage:$transactionTimeMin:$transactionTimeMax:$transactionTimeSigma:$scanTimeAverage:$scanTimeMin:$scanTimeMax:$scanTimeSigma"

/**
 * Output the Logger line to the csv file in the platform-specific public Documents directory.
 *
 * @param tag The tag to use for the log line.
 * @param data The data to write to the file.
 *
 */
fun Logger.saveToWorksheet(tag: String, data: String) {
    i(tag, "Saving to worksheet: $data")
    generateCsvFilePath()?.let {
        startLoggingToFile(it, overwrite = false)
        i(tag, data)
        stopLoggingToFile()
    } ?: e(tag, "Can't save to worksheet. File Path is null.")
}

fun generateCsvFilePath(): Path? = getPlatformDocumentsFolderPath("multidevicetests.csv")

/**
 * Get the platform-specific path to the Documents directory.
 *
 * @param filename The simple name of the file to write to (will be suffixed with a timestamp).
 *
 * @return The platform-specific path to the Documents directory.
 */
expect fun getPlatformDocumentsFolderPath(filename: String): Path?

/**
 * Initiates the platform-specific sharing mechanism for the file at the given path.
 *
 * @param csvFilePath The platform-specific path to the CSV file.
 * @param mimeType The MIME type of the file, defaults to "text/csv".
 * @param shareSheetTitle The title for the share sheet chooser (primarily for Android).
 */
expect fun shareCsvFile()