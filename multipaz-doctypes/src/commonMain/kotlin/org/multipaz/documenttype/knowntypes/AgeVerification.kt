package org.multipaz.documenttype.knowntypes

import org.multipaz.cbor.toDataItem
import org.multipaz.documenttype.DocumentAttributeType
import org.multipaz.documenttype.DocumentType
import org.multipaz.documenttype.Icon
import org.multipaz.util.fromBase64Url

/**
 * Object containing the metadata of the Age Verification document type.
 * See https://ageverification.dev/ for more details about this document type.
 */
object AgeVerification {
    const val AV_DOCTYPE = "eu.europa.ec.av.1"
    const val AV_NAMESPACE = "eu.europa.ec.av.1"

    /**
     * Build the Age Verification Document Type.
     */
    fun getDocumentType(): DocumentType =
        with(DocumentType.Builder("Age Verification Credential")) {
            addMdocDocumentType(AV_DOCTYPE)

            // Attributes.
            addMdocAttribute(
                type = DocumentAttributeType.Boolean,
                identifier = "age_over_18",
                displayName = "Older Than 18",
                description = "Age over 18?",
                mandatory = true,
                mdocNamespace = AV_NAMESPACE,
                icon = Icon.TODAY,
                sampleValue = SampleData.AGE_OVER_18.toDataItem()
            )
            addMdocAttribute(
                type = DocumentAttributeType.Picture,
                identifier = "portrait",
                displayName = "Photo of Holder",
                description = "A reproduction of the Age Verification Credential holder’s portrait.",
                mandatory = false,
                mdocNamespace = AV_NAMESPACE,
                icon = Icon.ACCOUNT_BOX,
                sampleValue = SampleData.PORTRAIT_BASE64URL.fromBase64Url().toDataItem()
            )
            val actualAge = SampleData.AGE_IN_YEARS
            val additionalAgeThresholds = listOf(13, 15, 16, 21, 23, 25, 27, 28, 40, 60, 65, 67)
            for (age in additionalAgeThresholds) {
                val isOverNN = actualAge > age
                addMdocAttribute(
                    type = DocumentAttributeType.Boolean,
                    identifier = "age_over_$age",
                    displayName = "Older Than $age",
                    description = "Age over $age?",
                    mandatory = false,
                    mdocNamespace = AV_NAMESPACE,
                    icon = Icon.TODAY,
                    sampleValue = isOverNN.toDataItem()
                )
            }
            // Sample requests.
            addSampleRequest(
                id = "age_over_18",
                displayName = "Age Over 18",
                mdocDataElements = mapOf(
                    AV_NAMESPACE to mapOf(
                        "age_over_18" to false,
                    )
                )
            )
            addSampleRequest(
                id = "age_over_18_zkp",
                displayName = "Age Over 18 (ZKP)",
                mdocDataElements = mapOf(
                    AV_NAMESPACE to mapOf(
                        "age_over_18" to false,
                    )
                ),
                mdocUseZkp = true
            )
            addSampleRequest(
                id = "age_over_21",
                displayName = "Age Over 21",
                mdocDataElements = mapOf(
                    AV_NAMESPACE to mapOf(
                        "age_over_21" to false,
                    )
                )
            )
            addSampleRequest(
                id = "age_over_21_zkp",
                displayName = "Age Over 21 (ZKP)",
                mdocDataElements = mapOf(
                    AV_NAMESPACE to mapOf(
                        "age_over_21" to false,
                    )
                ),
                mdocUseZkp = true
            )
            addSampleRequest(
                id = "age_over_18_and_portrait",
                displayName = "Age Over 18 + Portrait",
                mdocDataElements = mapOf(
                    AV_NAMESPACE to mapOf(
                        "age_over_18" to false,
                        "portrait" to false
                    )
                ),
            )
            addSampleRequest(
                id = "age_over_21_and_portrait",
                displayName = "Age Over 21 + Portrait",
                mdocDataElements = mapOf(
                    AV_NAMESPACE to mapOf(
                        "age_over_21" to false,
                        "portrait" to false
                    )
                ),
            )
            addSampleRequest(
                id = "full",
                displayName = "All Data Elements",
                mdocDataElements = mapOf(
                    AV_NAMESPACE to mapOf()
                )
            )
            build()
        }
}

