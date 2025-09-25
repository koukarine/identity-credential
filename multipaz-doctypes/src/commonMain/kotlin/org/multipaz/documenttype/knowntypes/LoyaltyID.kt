package org.multipaz.documenttype.knowntypes

import org.multipaz.cbor.toDataItem
import org.multipaz.cbor.toDataItemFullDate
import org.multipaz.documenttype.DocumentAttributeType
import org.multipaz.documenttype.DocumentType
import org.multipaz.documenttype.Icon
import org.multipaz.util.fromBase64Url
import kotlinx.datetime.LocalDate
import org.multipaz.cbor.buildCborMap

object LoyaltyID {
    const val LOYALTY_ID_DOCTYPE = "org.multipaz.loyality.1"
    const val LOYALTY_ID_NAMESPACE = "org.multipaz.loyality.1"

    /**
     * Build the Loyalty ID Document Type.
     */
    fun getDocumentType(): DocumentType {
        return DocumentType.Builder("Loyalty ID")
            .addMdocDocumentType(LOYALTY_ID_DOCTYPE)
            // First the data elements from ISO/IEC 23220-2.
            //
            .addMdocAttribute(
                DocumentAttributeType.String,
                "family_name",
                "Family Name",
                "Last name, surname, or primary identifier, of the document holder",
                true,
                LOYALTY_ID_NAMESPACE,
                Icon.PERSON,
                SampleData.FAMILY_NAME.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "given_name",
                "Given Names",
                "First name(s), other name(s), or secondary identifier, of the document holder",
                true,
                LOYALTY_ID_NAMESPACE,
                Icon.PERSON,
                SampleData.GIVEN_NAME.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Date,   // TODO: this is a more complex type
                "birth_date",
                "Date of Birth",
                "Day, month and year on which the document holder was born. If unknown, approximate date of birth",
                true,
                LOYALTY_ID_NAMESPACE,
                Icon.TODAY,
                buildCborMap {
                    put("birth_date", LocalDate.parse(SampleData.BIRTH_DATE).toDataItemFullDate())
                }
            )
            .addMdocAttribute(
                DocumentAttributeType.Picture,
                "portrait",
                "Photo of Holder",
                "A reproduction of the document holder’s portrait.",
                true,
                LOYALTY_ID_NAMESPACE,
                Icon.ACCOUNT_BOX,
                SampleData.PORTRAIT_BASE64URL.fromBase64Url().toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Boolean,
                "age_over_16",
                "Older Than 16 Years",
                "Indication whether the document holder is as old or older than 16",
                false,
                LOYALTY_ID_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_OVER_16.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Boolean,
                "age_over_18",
                "Older Than 18 Years",
                "Indication whether the document holder is as old or older than 18",
                false,
                LOYALTY_ID_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_OVER_18.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Boolean,
                "age_over_21",
                "Older Than 21 Years",
                "Indication whether the document holder is as old or older than 21",
                false,
                LOYALTY_ID_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_OVER_21.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.IntegerOptions(Options.SEX_ISO_IEC_5218),
                "sex",
                "Sex",
                "document holder’s sex",
                false,
                LOYALTY_ID_NAMESPACE,
                Icon.EMERGENCY,
                SampleData.SEX_ISO_5218.toDataItem()
            )
            // Then the LoyaltyID specific data elements.
            //
            .addMdocAttribute(
                DocumentAttributeType.String,
                "membership_number",
                "Membership ID",
                "Person identifier of the Loyalty ID holder.",
                false,
                LOYALTY_ID_NAMESPACE,
                Icon.NUMBERS,
                SampleData.PERSON_ID.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Date,
                "issue_date",
                "Date of Issue",
                "Date when document was issued",
                true,
                LOYALTY_ID_NAMESPACE,
                Icon.CALENDAR_CLOCK,
                LocalDate.parse(SampleData.ISSUE_DATE).toDataItemFullDate()
            )
            .addMdocAttribute(
                DocumentAttributeType.Date,
                "expiry_date",
                "Date of Expiry",
                "Date when document expires",
                true,
                LOYALTY_ID_NAMESPACE,
                Icon.CALENDAR_CLOCK,
                LocalDate.parse(SampleData.EXPIRY_DATE).toDataItemFullDate()
            )
            // Finally for the sample requests.
            //
            .addSampleRequest(
                id = "age_over_18",
                displayName ="Age Over 18",
                mdocDataElements = mapOf(
                    LOYALTY_ID_NAMESPACE to mapOf(
                        "age_over_18" to false,
                    )
                ),
            )
            .addSampleRequest(
                id = "age_over_18_zkp",
                displayName ="Age Over 18 (ZKP)",
                mdocDataElements = mapOf(
                    LOYALTY_ID_NAMESPACE to mapOf(
                        "age_over_18" to false,
                    )
                ),
                mdocUseZkp = true
            )
            .addSampleRequest(
                id = "age_over_18_and_portrait",
                displayName ="Age Over 18 + Portrait",
                mdocDataElements = mapOf(
                    LOYALTY_ID_NAMESPACE to mapOf(
                        "age_over_18" to false,
                        "portrait" to false
                    )
                ),
            )
            .addSampleRequest(
                id = "mandatory",
                displayName = "Mandatory Data Elements",
                mdocDataElements = mapOf(
                    LOYALTY_ID_NAMESPACE to mapOf(
                            "family_name" to false,
                            "given_name" to false,
                            "birth_date" to false,
                            "portrait" to false,
                            "age_over_18" to false,
                            "membership_number" to false,
                            "issue_date" to false,
                            "expiry_date" to false,
                    )
                )
            )
            .addSampleRequest(
                id = "full",
                displayName ="All Data Elements",
                mdocDataElements = mapOf(
                    LOYALTY_ID_NAMESPACE to mapOf()
                )
            )
            .build()
    }
}
