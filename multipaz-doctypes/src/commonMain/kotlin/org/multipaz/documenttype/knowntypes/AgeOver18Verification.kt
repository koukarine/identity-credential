package org.multipaz.documenttype.knowntypes

import org.multipaz.documenttype.DocumentAttributeType
import org.multipaz.documenttype.DocumentType
import org.multipaz.documenttype.Icon
import org.multipaz.cbor.toDataItem

/**
 * Object containing the metadata of the EUDI Age Over 18 Verification document type.
 */
object AgeOver18Verification {
    const val AV_DOCTYPE = "eu.europa.ec.eudi.pseudonym.age_over_18.1"
    const val AV_NAMESPACE = "eu.europa.ec.av.1"
    const val AV_VCT = "https://example.eudi.ec.europa.eu/cor/1"

    /**
     * Build the EUDI Age Over 18 Document Type.
     */
    fun getDocumentType(): DocumentType {
        val builder = DocumentType.Builder("EUDI Age Over 18")
            .addMdocDocumentType(AV_DOCTYPE)
            .addJsonDocumentType(type = AV_VCT, keyBound = true)
            .addAttribute(
                DocumentAttributeType.Boolean,
                "age_over_18",
                "Older Than 18",
                "Age over 18?",
                true,
                AV_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_OVER_18.toDataItem()
            )
            .addSampleRequest(
                id = "age_over_18",
                displayName = "Age Over 18",
                mdocDataElements = mapOf(
                    AV_NAMESPACE to mapOf(
                        "age_over_18" to false,
                    )
                ),
                jsonClaims = listOf("age_over_18")
            )
            .addSampleRequest(
                id = "mandatory",
                displayName = "Mandatory Data Elements",
                mdocDataElements = mapOf(
                    AV_NAMESPACE to mapOf(
                        "age_over_18" to false,
                    )
                ),
                jsonClaims = listOf(
                    "age_over_18",
                )
            )
            .addSampleRequest(
                id = "full",
                displayName = "All Data Elements",
                mdocDataElements = mapOf(
                    AV_NAMESPACE to mapOf()
                ),
                jsonClaims = listOf()
            )
            val actualAge = 50
            val ages = listOf(13, 15, 16, 21, 23, 25, 27, 28, 40, 60, 65, 67)
            for (age in ages) {
                val isOverNN = actualAge > age
                builder.addAttribute(
                    DocumentAttributeType.Boolean,
                    "age_over_$age",
                    "Older Than $age",
                    "Age over $age?",
                    false,
                    AV_NAMESPACE,
                    Icon.TODAY,
                    isOverNN.toDataItem()
                )
                builder.addSampleRequest(
                    id = "age_over_$age",
                    displayName = "Age Over $age",
                    mdocDataElements = mapOf(
                        AV_NAMESPACE to mapOf(
                            "age_over_$age" to isOverNN,
                        )
                    ),
                    jsonClaims = listOf("age_over_$age")
                )
            }
            return builder.build()
    }
}
