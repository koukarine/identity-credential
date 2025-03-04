package com.android.identity.cose

import com.android.identity.cbor.CborMap
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.toDataItem
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPublicKeyDoubleCoordinate
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.software.SoftwareSecureArea
import com.android.identity.storage.EphemeralStorageEngine
import com.android.identity.util.appendString
import com.android.identity.util.fromHex
import kotlinx.io.bytestring.buildByteString
import kotlinx.io.bytestring.hexToByteString
import kotlin.test.BeforeTest

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CoseTests {

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun coseKeyDecode() {
        // This checks we can decode the first key from the Example set in
        //
        //   https://datatracker.ietf.org/doc/html/rfc9052#name-public-keys
        //
        val x = "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d".hexToByteString()
        val y = "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c".hexToByteString()
        val id = buildByteString { appendString("meriadoc.brandybuck@buckland.example") }
        val item = CborMap.builder()
            .put(-1, 1)
            .put(-2, x)
            .put(-3, y)
            .put(1, 2)
            .put(2, id)
            .end()
            .build()
        val coseKey = item.asCoseKey
        assertEquals(Cose.COSE_KEY_TYPE_EC2, coseKey.keyType.asNumber)
        assertEquals(id, coseKey.labels[Cose.COSE_KEY_KID.toCoseLabel]!!.asBstr)
        assertEquals(x, coseKey.labels[Cose.COSE_KEY_PARAM_X.toCoseLabel]!!.asBstr)
        assertEquals(y, coseKey.labels[Cose.COSE_KEY_PARAM_Y.toCoseLabel]!!.asBstr)

        // Also check we can get an EcPublicKey from this
        val key = coseKey.ecPublicKey as EcPublicKeyDoubleCoordinate
        assertEquals(EcCurve.P256, key.curve)
        assertEquals(x, key.x)
        assertEquals(y, key.y)
    }

    @Test
    fun coseSign1() {
        val key = Crypto.createEcPrivateKey(EcCurve.P256)
        val dataToSign = buildByteString { appendString("This is the data to sign.") }
        val coseSignature = Cose.coseSign1Sign(
            key,
            dataToSign,
            true,
            Algorithm.ES256,
            emptyMap(),
            emptyMap(),
        )

        assertTrue(
            Cose.coseSign1Check(
                key.publicKey,
                null,
                coseSignature,
                Algorithm.ES256
            )
        )

    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun coseSign1TestVector() {
        // This is the COSE_Sign1 example from
        //
        //  https://datatracker.ietf.org/doc/html/rfc9052#appendix-C.2.1
        //
        // The key being signed with is the one with kid '11`, see
        //
        //  https://datatracker.ietf.org/doc/html/rfc9052#name-public-keys
        //
        val x = "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff".fromHex()
        val y = "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e".fromHex()
        val coseKey = CborMap.builder()
            .put(-1, 1)
            .put(-2, x)
            .put(-3, y)
            .put(1, 2)
            .end().build().asCoseKey

        val coseSign1 = CoseSign1(
            mutableMapOf(
                Pair(1L.toCoseLabel, (-7).toDataItem())
            ),
            mutableMapOf(
                Pair(11L.toCoseLabel, byteArrayOf(1, 1).toDataItem())
            ),
            ("8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4" +
                    "d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5" +
                    "a4c345cacb36").hexToByteString(),
            buildByteString { appendString("This is the content.") }
        )

        assertTrue(
            Cose.coseSign1Check(
                coseKey.ecPublicKey,
                null,
                coseSign1,
                Algorithm.ES256
            )
        )
    }


    fun coseSign1_helper(curve: EcCurve) {
        // TODO: use assumeTrue() when available in kotlin-test
        if (!Crypto.supportedCurves.contains(curve)) {
            println("Curve $curve not supported on platform")
            return
        }

        val privateKey = Crypto.createEcPrivateKey(curve)
        val signatureAlgorithm = privateKey.curve.defaultSigningAlgorithm
        val protectedHeaders = mapOf<CoseLabel, DataItem>(
            Pair(
                Cose.COSE_LABEL_ALG.toCoseLabel,
                signatureAlgorithm.coseAlgorithmIdentifier.toDataItem()
            )
        )
        val message = buildByteString { appendString("Hello World") }
        val coseSignature = Cose.coseSign1Sign(
            privateKey,
            message,
            true,
            signatureAlgorithm,
            protectedHeaders,
            mapOf()
        )

        assertTrue(
            Cose.coseSign1Check(
                privateKey.publicKey,
                null,
                coseSignature,
                signatureAlgorithm
            )
        )
    }

    @Test fun coseSign1_P256() = coseSign1_helper(EcCurve.P256)
    @Test fun coseSign1_P384() = coseSign1_helper(EcCurve.P384)
    @Test fun coseSign1_P521() = coseSign1_helper(EcCurve.P521)
    @Test fun coseSign1_BRAINPOOLP256R1() = coseSign1_helper(EcCurve.BRAINPOOLP256R1)
    @Test fun coseSign1_BRAINPOOLP320R1() = coseSign1_helper(EcCurve.BRAINPOOLP320R1)
    @Test fun coseSign1_BRAINPOOLP384R1() = coseSign1_helper(EcCurve.BRAINPOOLP384R1)
    @Test fun coseSign1_BRAINPOOLP512R1() = coseSign1_helper(EcCurve.BRAINPOOLP512R1)
    @Test fun coseSign1_ED25519() = coseSign1_helper(EcCurve.ED25519)
    @Test fun coseSign1_ED448() = coseSign1_helper(EcCurve.ED448)
}
