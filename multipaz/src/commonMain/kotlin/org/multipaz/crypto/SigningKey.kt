package org.multipaz.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.multipaz.asn1.OID
import org.multipaz.securearea.KeyInfo
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.KeyUnlockInteractive
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository

/**
 * Private key with some kind of identification that can be used to sign messages (typically
 * in JWT format).
 *
 * A private key can either be a software key [EcPrivateKey] or reside in a [SecureArea]. Keys
 * can be identified either by a certificate chain or using a key id. When reading a key from
 * settings, all four possible variants are potentially useful, yet it makes very little
 * difference for the rest of the code which variant is actually used. [SigningKey] class
 * encapsulates these variants so the code can be written in more generic way.
 */
sealed class SigningKey {
    abstract val algorithm: Algorithm
    abstract val publicKey: EcPublicKey
    abstract val subject: String

    abstract suspend fun sign(message: ByteArray): EcSignature
    abstract fun addToJwtHeader(header: JsonObjectBuilder)

    interface Explicit {
        val privateKey: EcPrivateKey
        val algorithm: Algorithm
    }

    interface SecureAreaBased {
        val alias: String
        val secureArea: SecureArea
        val keyUnlockData: KeyUnlockData?
        val keyInfo: KeyInfo
    }

    interface Named {
        val keyId: String
        val algorithm: Algorithm
        val publicKey: EcPublicKey
    }

    interface Certified {
        val certChain: X509CertChain
        val algorithm: Algorithm
        val publicKey: EcPublicKey
    }

    data class CertifiedExplicit(
        override val certChain: X509CertChain,
        override val privateKey: EcPrivateKey,
        override val algorithm: Algorithm = privateKey.curve.defaultSigningAlgorithm
    ): SigningKey(), Certified, Explicit {
        override val publicKey: EcPublicKey get() = privateKey.publicKey
        override val subject: String get() = commonName(certChain)
        override suspend fun sign(message: ByteArray) = sign(this, message)
        override fun addToJwtHeader(header: JsonObjectBuilder) =
            addToJwtHeader(this, header)
    }

    data class NamedExplicit(
        override val keyId: String,
        override val privateKey: EcPrivateKey,
        override val algorithm: Algorithm = privateKey.curve.defaultSigningAlgorithm
    ): SigningKey(), Named, Explicit {
        override val publicKey: EcPublicKey get() = privateKey.publicKey
        override val subject: String get() = keyId
        override suspend fun sign(message: ByteArray) = sign(this, message)
        override fun addToJwtHeader(header: JsonObjectBuilder) =
            addToJwtHeader(this, header)
    }

    data class CertifiedSecureAreaBased(
        override val certChain: X509CertChain,
        override val alias: String,
        override val secureArea: SecureArea,
        override val keyInfo: KeyInfo,
        override val keyUnlockData: KeyUnlockData? = KeyUnlockInteractive(),
    ): SigningKey(), Certified, SecureAreaBased {
        override val algorithm: Algorithm get() = keyInfo.algorithm
        override val publicKey: EcPublicKey get() = keyInfo.publicKey
        override val subject: String get() = commonName(certChain)
        override suspend fun sign(message: ByteArray) = sign(this, message)
        override fun addToJwtHeader(header: JsonObjectBuilder) =
            addToJwtHeader(this, header)
    }

    data class NamedSecureAreaBased(
        override val keyId: String,
        override val alias: String,
        override val secureArea: SecureArea,
        override val keyInfo: KeyInfo,
        override val keyUnlockData: KeyUnlockData? = KeyUnlockInteractive()
    ): SigningKey(), Named, SecureAreaBased {
        override val algorithm: Algorithm get() = keyInfo.algorithm
        override val publicKey: EcPublicKey get() = keyInfo.publicKey
        override val subject: String get() = keyId
        override suspend fun sign(message: ByteArray) = sign(this, message)
        override fun addToJwtHeader(header: JsonObjectBuilder) =
            addToJwtHeader(this, header)
    }

    companion object {
        private fun sign(explicit: Explicit, message: ByteArray): EcSignature =
            Crypto.sign(explicit.privateKey, explicit.algorithm, message)

        private suspend fun sign(
            secureAreaBased: SecureAreaBased,
            message: ByteArray
        ): EcSignature =
            secureAreaBased.secureArea.sign(
                alias = secureAreaBased.alias,
                dataToSign = message,
                keyUnlockData = secureAreaBased.keyUnlockData
            )

        private fun addToJwtHeader(certified: Certified, header: JsonObjectBuilder) {
            header.put(
                key = "alg",
                value = certified.algorithm.joseAlgorithmIdentifier ?:
                    certified.publicKey.curve.defaultSigningAlgorithmFullySpecified.joseAlgorithmIdentifier
            )
            header.put("x5c", certified.certChain.toX5c())
        }

        private fun addToJwtHeader(named: Named, header: JsonObjectBuilder) {
            header.put(
                key = "alg",
                value = named.algorithm.joseAlgorithmIdentifier ?:
                named.publicKey.curve.defaultSigningAlgorithmFullySpecified.joseAlgorithmIdentifier
            )
            header.put("kid", named.keyId)
        }

        /**
         * Parse json string that describes the private key.
         *
         * Private key can either be given as JWK object or as a reference to a
         * [SecureArea]-resident key using `secure_area` and `alias` fields. In either case, key
         * identification must be specified using `kid` or `x5c` fields.
         */
        suspend fun parse(
            json: String,
            secureAreaRepository: SecureAreaRepository,
            keyUnlockData: KeyUnlockData? = KeyUnlockInteractive()
        ): SigningKey = parse(
            json = Json.parseToJsonElement(json),
            secureAreaRepository = secureAreaRepository,
            keyUnlockData = keyUnlockData
        )

        /**
         * Parse json object that describes the private key.
         */
        suspend fun parse(
            json: JsonElement,
            secureAreaRepository: SecureAreaRepository,
            keyUnlockData: KeyUnlockData? = KeyUnlockInteractive()
        ): SigningKey {
            if (json !is JsonObject) {
                throw IllegalArgumentException("expected json object")
            }
            val secureArea = json["secure_area"]?.jsonPrimitive?.content?.let {
                secureAreaRepository.getImplementation(it)
            }
            return if (secureArea != null) {
                val (kid, x5c) = parseIdentifier(json)
                val alias = json["alias"]?.jsonPrimitive?.content ?: throw IllegalArgumentException("'alias' is required")
                val keyInfo = secureArea.getKeyInfo(alias)
                if (kid != null) {
                    NamedSecureAreaBased(kid, alias, secureArea, keyInfo, keyUnlockData)
                } else {
                    CertifiedSecureAreaBased(x5c!!, alias, secureArea, keyInfo, keyUnlockData)
                }
            } else {
                parseExplicit(json)
            }
        }

        /**
         * Parse json string that describes the private key for software-based private key.
         *
         * Similar to [parse], but does not handle [SecureArea]-based keys. It is suitable for
         * calling in non-coroutine contexts.
         */
        fun parseExplicit(json: String): SigningKey =
            parseExplicit(Json.parseToJsonElement(json))

        /**
         * Parse json object that describes the private key for software-based private key.
         *
         * Similar to [parse], but does not handle [SecureArea]-based keys. It is suitable for
         * calling in non-coroutine contexts.
         */
        fun parseExplicit(json: JsonElement): SigningKey {
            if (json !is JsonObject) {
                throw IllegalArgumentException("expected json object")
            }
            val (kid, x5c) = parseIdentifier(json)
            val privateKey = EcPrivateKey.fromJwk(json)
            if (kid != null) {
                return NamedExplicit(kid, privateKey)
            }
            if (x5c!!.certificates.first().ecPublicKey != privateKey.publicKey) {
                throw IllegalArgumentException("certificate chain does not certify the key")
            }
            return CertifiedExplicit(x5c, privateKey)
        }

        private fun parseIdentifier(json: JsonObject): Pair<String?, X509CertChain?> {
            val kid = json["kid"]?.jsonPrimitive?.content
            if (kid != null) {
                return Pair(kid, null)
            }
            val x5c = json["x5c"] ?:
                throw IllegalArgumentException("either 'kid' or 'x5c' must be given")
            return Pair(null, X509CertChain.fromX5c(x5c))
        }

        private fun commonName(certChain: X509CertChain): String =
            certChain.certificates.first().subject.components[OID.COMMON_NAME.oid]?.value
                ?: throw IllegalStateException("No common name in certificate's subject")
    }
}