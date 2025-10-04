package org.multipaz.provisioning.openid4vci

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.SigningKey
import org.multipaz.jwt.buildJwt
import org.multipaz.securearea.KeyAttestation
import org.multipaz.util.toBase64Url
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes

/**
 * Utilities helpful for implementing [OpenID4VCIBackend].
 *
 * In production environments, these are typically run on the server as private keys
 * used for signing should be kept secret and cannot be embedded in a client app.
 *
 * For test environments, these can be invoked directly in the client app for simplicity.
 */
object OpenID4VCIBackendUtil {
    suspend fun createJwtClientAssertion(
        signingKey: SigningKey,
        clientId: String,
        tokenUrl: String,
    ): String = buildJwt(
        type = "JWT",
        key = signingKey,
        expiresIn = 5.minutes
    ) {
        // TODO: figure out what should be passed as `aud`.
        //  per 'https://datatracker.ietf.org/doc/html/rfc7523#page-5' tokenUrl is appropriate,
        //  but Openid validation suite does not seem to take that.
        val aud = if (tokenUrl.endsWith("/token")) {
            // A hack to get authorization url from token url; would not work in general case.
            tokenUrl.substring(0, tokenUrl.length - 5)
        } else {
            tokenUrl
        }
        put("jti", Random.Default.nextBytes(18).toBase64Url())
        put("iss", clientId)
        put("sub", clientId) // RFC 7523 Section 3, item 2.B
        put("aud", aud)
    }

    /**
     * Generates JWT implementing OpenID4VCI Appendix E. Wallet Attestations in JWT format.
     *
     * @param signingKey key to sign JWT
     * @param clientId OpenID client id, used as "sub" claim
     * @param attestationIssuer issuer of the attestation, used as "iss" claim
     * @param attestedKey client's public key that will be attested, stored in "cnf" claim
     * @param nonce nonce if any (not common), used as "nonce" claim if given
     * @param walletName human-readable name of the wallet app, used in "wallet_name" claim
     * @param walletLink link to the wallet app web site, used in "wallet_link" claim
     * @return signed JWT representing Wallet Attestation
     */
    suspend fun createWalletAttestation(
        signingKey: SigningKey,
        clientId: String,
        attestationIssuer: String,
        attestedKey: EcPublicKey,
        nonce: String?,
        walletName: String?,
        walletLink: String?
    ): String = buildJwt(
        type = "oauth-client-attestation+jwt",
        key = signingKey
    ) {
        put("iss", attestationIssuer)
        put("sub", clientId)
        put("cnf", buildJsonObject {
            put("jwk", attestedKey.toJwk())
        })
        nonce?.let { put("nonce", it) }
        walletName?.let { put("wallet_name", it) }
        walletLink?.let { put("wallet_link", it) }
    }

    suspend fun createJwtKeyAttestation(
        signingKey: SigningKey,
        attestationIssuer: String,
        keysToAttest: List<KeyAttestation>,
        challenge: String,
        userAuthentication: List<String>? = null,
        keyStorage: List<String>? = null
    ): String  = buildJwt(
        type = "keyattestation+jwt",  // TODO: it is now key-attestation+jwt in the spec
        key = signingKey,
        expiresIn = 5.minutes
    ) {
        put("iss", attestationIssuer)
        put("attested_keys", JsonArray(
            keysToAttest.map { it.publicKey.toJwk() }
        ))
        put("nonce", challenge)
        userAuthentication?.let {
            putJsonArray("user_authentication") {
                for (item in it) {
                    add(item)
                }
            }
        }
        keyStorage?.let {
            putJsonArray("key_storage") {
                for (item in it) {
                    add(item)
                }
            }
        }
    }
}