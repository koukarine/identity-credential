package com.android.identity.testapp

import android.os.Build
import com.android.identity.android.securearea.AndroidKeystoreCreateKeySettings
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.android.storage.AndroidStorageEngine
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.SecureArea
import com.android.identity.util.AndroidInitializer
import kotlinx.io.files.Path
import java.net.NetworkInterface

actual val platform = Platform.ANDROID

actual fun getLocalIpAddress(): String {
    for (iface in NetworkInterface.getNetworkInterfaces()) {
        for (inetAddress in iface.inetAddresses) {
            if (!inetAddress.isLoopbackAddress) {
                val address = inetAddress.hostAddress
                if (address != null && address.indexOf(':') < 0) {
                    return address
                }
            }
        }
    }
    throw IllegalStateException("Unable to determine address")
}

private val androidKeystoreStorage: AndroidStorageEngine by lazy {
    AndroidStorageEngine.Builder(
        AndroidInitializer.applicationContext,
        Path(AndroidInitializer.applicationContext.dataDir.path, "testapp-default.bin")
    ).build()
}

private val androidKeystoreSecureArea: AndroidKeystoreSecureArea by lazy {
    AndroidKeystoreSecureArea(AndroidInitializer.applicationContext, androidKeystoreStorage)
}

actual fun platformSecureArea(): SecureArea {
    return androidKeystoreSecureArea
}

actual fun platformKeySetting(clientId: String): CreateKeySettings {
    return AndroidKeystoreCreateKeySettings.Builder(clientId.toByteArray()).build()
}

// https://stackoverflow.com/a/21505193/878126
actual val platformIsEmulator: Boolean by lazy {
    // Android SDK emulator
    return@lazy ((Build.MANUFACTURER == "Google" && Build.BRAND == "google" &&
            ((Build.FINGERPRINT.startsWith("google/sdk_gphone_")
                    && Build.FINGERPRINT.endsWith(":user/release-keys")
                    && Build.PRODUCT.startsWith("sdk_gphone_")
                    && Build.MODEL.startsWith("sdk_gphone_"))
                    //alternative
                    || (Build.FINGERPRINT.startsWith("google/sdk_gphone64_")
                    && (Build.FINGERPRINT.endsWith(":userdebug/dev-keys") || Build.FINGERPRINT.endsWith(
                ":user/release-keys"
            ))
                    && Build.PRODUCT.startsWith("sdk_gphone64_")
                    && Build.MODEL.startsWith("sdk_gphone64_"))))
            //
            || Build.FINGERPRINT.startsWith("generic")
            || Build.FINGERPRINT.startsWith("unknown")
            || Build.MODEL.contains("google_sdk")
            || Build.MODEL.contains("Emulator")
            || Build.MODEL.contains("Android SDK built for x86")
            //bluestacks
            || "QC_Reference_Phone" == Build.BOARD && !"Xiaomi".equals(
        Build.MANUFACTURER,
        ignoreCase = true
    )
            //bluestacks
            || Build.MANUFACTURER.contains("Genymotion")
            || Build.HOST.startsWith("Build")
            //MSI App Player
            || Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")
            || Build.PRODUCT == "google_sdk")
    // another Android SDK emulator check
    /* || SystemProperties.getProp("ro.kernel.qemu") == "1") */
}
