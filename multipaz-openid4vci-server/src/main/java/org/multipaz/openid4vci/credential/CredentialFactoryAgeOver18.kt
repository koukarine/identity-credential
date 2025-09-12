package org.multipaz.openid4vci.credential

import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.toDataItem
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseLabel
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.EcPublicKey
import org.multipaz.mdoc.mso.MobileSecurityObjectGenerator
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Instant
import org.multipaz.cbor.RawCbor
import org.multipaz.cbor.Simple
import org.multipaz.cbor.buildCborMap
import org.multipaz.documenttype.knowntypes.AgeOver18Verification
import org.multipaz.mdoc.issuersigned.buildIssuerNamespaces
import kotlin.time.Duration.Companion.days

/**
 * Factory for EU Personal ID in mDoc format.
 */
internal class CredentialFactoryAgeOver18 : CredentialFactoryBase() {
    override val offerId: String
        get() = "mDoc-AgeOver18"

    override val scope: String
        get() = "core"

    override val format: Openid4VciFormat
        get() = openId4VciFormatAV

    override val proofSigningAlgorithms: List<String>
        get() = CredentialFactory.DEFAULT_PROOF_SIGNING_ALGORITHMS

    override val cryptographicBindingMethods: List<String>
        get() = listOf("cose_key")

    override val name: String
        get() = "Age Over 18 (mDoc)"

    override val logo: String
        get() = "av18.png"

    override suspend fun makeCredential(
        data: DataItem,
        authenticationKey: EcPublicKey?
    ): String {
        val now = Clock.System.now()

        val coreData = data["core"]

        // Create AuthKeys and MSOs, make sure they're valid for 30 days. Also make
        // sure to not use fractional seconds as 18013-5 calls for this (clauses 7.1
        // and 9.1.2.4)
        //
        val timeSigned = Instant.fromEpochSeconds(now.epochSeconds, 0)
        val validFrom = Instant.fromEpochSeconds(now.epochSeconds, 0)
        val validUntil = validFrom + 30.days

        // Generate an MSO and issuer-signed data for this authentication key.
        val msoGenerator = MobileSecurityObjectGenerator(
            Algorithm.SHA256,
            AgeOver18Verification.AV_DOCTYPE,
            authenticationKey!!
        )
        msoGenerator.setValidityInfo(timeSigned, validFrom, validUntil, null)

        val mdocType = AgeOver18Verification.getDocumentType()
            .mdocDocumentType!!.namespaces[AgeOver18Verification.AV_NAMESPACE]!!

        val issuerNamespaces = buildIssuerNamespaces {
            addNamespace(AgeOver18Verification.AV_NAMESPACE) {
                addDataElement("age_over_18", Simple.TRUE)
            }
        }

        msoGenerator.addValueDigests(issuerNamespaces)

        val mso = msoGenerator.generate()
        val taggedEncodedMso = Cbor.encode(Tagged(24, Bstr(mso)))

        // IssuerAuth is a COSE_Sign1 where payload is MobileSecurityObjectBytes
        //
        // MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)
        //
        val protectedHeaders = mapOf<CoseLabel, DataItem>(
            Pair(
                CoseNumberLabel(Cose.COSE_LABEL_ALG),
                Algorithm.ES256.coseAlgorithmIdentifier!!.toDataItem()
            )
        )
        val unprotectedHeaders = mapOf<CoseLabel, DataItem>(
            Pair(
                CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN),
                signingCertificateChain.toDataItem()
            )
        )
        val encodedIssuerAuth = Cbor.encode(
            Cose.coseSign1Sign(
                signingKey,
                taggedEncodedMso,
                true,
                signingKey.publicKey.curve.defaultSigningAlgorithm,
                protectedHeaders,
                unprotectedHeaders
            ).toDataItem()
        )
        val issuerProvidedAuthenticationData = Cbor.encode(
            buildCborMap {
                put("nameSpaces", issuerNamespaces.toDataItem())
                put("issuerAuth", RawCbor(encodedIssuerAuth))
            }
        )

        return issuerProvidedAuthenticationData.toBase64Url()
    }

    companion object {
        const val TAG = "CredentialFactoryAgeOver18"
    }
}