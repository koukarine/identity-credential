package org.multipaz

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.multipaz.crypto.Crypto
import java.security.Security

actual fun testUtilSetupCryptoProvider() {
    // On Android (in tests), load BouncyCastleProvider so we can exercise
    // all the tests involving Brainpool curves.
    // We use addProvider() instead of insertProviderAt() to avoid making BC the
    // default provider, which can cause ClassCastExceptions with standard java interfaces.
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME) // remove first to ensure it's not already there
    Security.addProvider(BouncyCastleProvider())

    println("In testUtilCommonSetup for androidInstrumentedTest")
    println("Crypto.provider: ${Crypto.provider}")
    println("Crypto.supportedCurves: ${Crypto.supportedCurves}")
}
