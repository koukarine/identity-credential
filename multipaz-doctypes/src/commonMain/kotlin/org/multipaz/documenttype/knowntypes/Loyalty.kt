package org.multipaz.documenttype.knowntypes

import org.multipaz.cbor.toDataItem
import org.multipaz.cbor.toDataItemFullDate
import org.multipaz.documenttype.DocumentAttributeType
import org.multipaz.documenttype.DocumentType
import org.multipaz.documenttype.Icon
import org.multipaz.util.fromBase64Url
import kotlinx.datetime.LocalDate

object Loyalty {
    const val LOYALTY_DOCTYPE = "org.multipaz.loyalty.1"
    const val LOYALTY_NAMESPACE = "org.multipaz.loyalty.1"

    /**
     * Build the Loyalty ID Document Type.
     */
    fun getDocumentType(): DocumentType {
        return DocumentType.Builder("Loyalty")
            .addMdocDocumentType(LOYALTY_DOCTYPE)
            // Core holder data relevant for a loyalty card
            //
            .addMdocAttribute(
                DocumentAttributeType.String,
                "family_name",
                "Family Name",
                "Last name, surname, or primary identifier, of the document holder",
                true,
                LOYALTY_NAMESPACE,
                Icon.PERSON,
                SampleData.FAMILY_NAME.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "given_name",
                "Given Names",
                "First name(s), other name(s), or secondary identifier, of the document holder",
                true,
                LOYALTY_NAMESPACE,
                Icon.PERSON,
                SampleData.GIVEN_NAME.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Picture,
                "portrait",
                "Photo of Holder",
                "A reproduction of the document holder’s portrait.",
                true,
                LOYALTY_NAMESPACE,
                Icon.ACCOUNT_BOX,
                SampleData.PORTRAIT_BASE64URL.fromBase64Url().toDataItem()
            )
            // Then the LoyaltyID specific data elements.
            //
            .addMdocAttribute(
                DocumentAttributeType.String,
                "membership_number",
                "Membership ID",
                "Person identifier of the Loyalty ID holder.",
                false,
                LOYALTY_NAMESPACE,
                Icon.NUMBERS,
                SampleData.PERSON_ID.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "tier",
                "Tier",
                "Membership tier (basic, silver, gold, platinum, elite)",
                false,
                LOYALTY_NAMESPACE,
                Icon.STARS,
                "basic".toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Date,
                "issue_date",
                "Date of Issue",
                "Date when document was issued",
                true,
                LOYALTY_NAMESPACE,
                Icon.CALENDAR_CLOCK,
                LocalDate.parse(SampleData.ISSUE_DATE).toDataItemFullDate()
            )
            .addMdocAttribute(
                DocumentAttributeType.Date,
                "expiry_date",
                "Date of Expiry",
                "Date when document expires",
                true,
                LOYALTY_NAMESPACE,
                Icon.CALENDAR_CLOCK,
                LocalDate.parse(SampleData.EXPIRY_DATE).toDataItemFullDate()
            )
            // Finally for the sample requests.
            //
            .addSampleRequest(
                id = "mandatory",
                displayName = "Mandatory Data Elements",
                mdocDataElements = mapOf(
                    LOYALTY_NAMESPACE to mapOf(
                            "family_name" to false,
                            "given_name" to false,
                            "portrait" to false,
                            "membership_number" to false,
                            "tier" to false,
                            "issue_date" to false,
                            "expiry_date" to false,
                    )
                )
            )
            .addSampleRequest(
                id = "full",
                displayName ="All Data Elements",
                mdocDataElements = mapOf(
                    LOYALTY_NAMESPACE to mapOf()
                )
            )
            .build()
    }
}
