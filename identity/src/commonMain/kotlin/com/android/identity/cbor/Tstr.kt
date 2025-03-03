package com.android.identity.cbor

import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.ByteStringBuilder
import kotlinx.io.bytestring.decodeToString

/**
 * Unicode String (major type 3).
 *
 * @param value the [String] for the value of the byte string.
 */
class Tstr(val value: String) : DataItem(MajorType.UNICODE_STRING) {
    override fun encode(builder: ByteStringBuilder) {
        val encodedValue = value.encodeToByteArray()
        Cbor.encodeLength(builder, majorType, encodedValue.size)
        builder.append(value.encodeToByteArray())
    }

    companion object {
        internal fun decode(encodedCbor: ByteString, offset: Int): Pair<Int, Tstr> {
            val (payloadBegin, length) = Cbor.decodeLength(encodedCbor, offset)
            val payloadEnd = payloadBegin + length.toInt()
            val slice = encodedCbor.substring(payloadBegin, payloadEnd)
            return Pair(payloadEnd, Tstr(slice.decodeToString()))
        }
    }

    override fun equals(other: Any?): Boolean = other is Tstr && value == other.value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = "Tstr(\"$value\")"
}