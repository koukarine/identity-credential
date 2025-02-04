package com.android.identity.issuance.evidence

import com.android.identity.cbor.annotation.CborSerializable
import com.android.identity.cbor.Cbor

/**
 * A response to an evidence request.
 */
@CborSerializable
sealed class EvidenceResponse {
    fun encodeToCbor(): ByteArray { // Don't use toCbor here, it will shadow generated extensions.
        return Cbor.encode(toDataItem())
    }

    companion object {
        fun decodeFromCbor(encodedValue: ByteArray): EvidenceResponse {
            return fromDataItem(Cbor.decode(encodedValue))
        }
    }
}
