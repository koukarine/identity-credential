package com.android.identity.issuance

import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborMap
import com.android.identity.cbor.DataItem
import kotlinx.datetime.Instant
import kotlinx.io.bytestring.ByteString

/**
 * The state of a document, as seen from the issuer's point of view.
 */
data class DocumentState(
    /**
     * The point in time this state object was generated.
     */
    val timestamp: Instant,

    /**
     * The current condition of the document.
     */
    val condition: DocumentCondition,

    /**
     * The number of pending credentials.
     *
     * These are credentials which the application requested but which are not yet ready
     * the be collected.
     */
    val numPendingCredentials: Int,

    /**
     * The number of available credentials.
     *
     * These are credentials which the application requested and which are now ready to
     * be collected
     */
    val numAvailableCredentials: Int,
    ) {
    companion object {
        fun fromCbor(encodedData: ByteString): DocumentState {
            return fromDataItem(Cbor.decode(encodedData))
        }

        fun fromDataItem(dataItem: DataItem): DocumentState {
            return DocumentState(
                Instant.fromEpochMilliseconds(dataItem["timestamp"].asNumber),
                DocumentCondition.fromInt(dataItem["condition"].asNumber.toInt()),
                dataItem["numPendingCredentials"].asNumber.toInt(),
                dataItem["numAvailableCredentials"].asNumber.toInt()
            )
        }
    }

    fun toCbor(): ByteString {
        return Cbor.encode(toDataItem())
    }

    fun toDataItem(): DataItem {
        return CborMap.builder()
            .put("timestamp", timestamp.toEpochMilliseconds())
            .put("condition", condition.value)
            .put("numPendingCredentials", numPendingCredentials)
            .put("numAvailableCredentials", numAvailableCredentials)
            .end()
            .build()
    }
}
