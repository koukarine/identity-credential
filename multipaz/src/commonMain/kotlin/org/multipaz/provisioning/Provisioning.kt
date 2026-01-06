package org.multipaz.provisioning

import kotlinx.io.bytestring.ByteString
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.CborMap
import org.multipaz.cbor.Tstr
import org.multipaz.provisioning.openid4vci.OpenID4VCIClientPreferences
import org.multipaz.provisioning.openid4vci.OpenID4VCIProvisioningClient
import org.multipaz.rpc.backend.BackendEnvironment
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.storage.Storage
import org.multipaz.util.Logger

/**
 * Object that dispatches general provisioning-related operations to correct protocol handlers
 * (for Multipaz-implemented protocols).
 */
object Provisioning {
    /**
     * Creates [ProvisioningClient] from authorization data obtained from a previous provisioning
     * session.
     *
     * @param authorizationData authorization data, see [ProvisioningClient.getAuthorizationData]
     */
    suspend fun createClientFromAuthorizationData(
        authorizationData: ByteString
    ): ProvisioningClient {
        val parsedAuthorizationData = parseAuthorizationData(authorizationData)
        return when (val t = parsedAuthorizationData["type"].asTstr) {
            "openid4vci" -> {
                val clientPreferences =
                    BackendEnvironment.getInterface(OpenID4VCIClientPreferences::class)!!
                OpenID4VCIProvisioningClient.createFromAuthorizationData(
                    authorizationData = parsedAuthorizationData,
                    clientPreferences = clientPreferences
                )
            }
            else -> throw IllegalArgumentException("Unknown authorization data type: '$t'")
        }
    }

    /**
     * Cleans up storage and/or private keys that authorization data holds.
     *
     * @param authorizationData authorization data, see [ProvisioningClient.getAuthorizationData]
     * @param secureAreaRepository where to search for the relevant [SecureArea]
     * @param storage interface to persistent storage
     */
    suspend fun cleanupAuthorizationData(
        authorizationData: ByteString,
        secureAreaRepository: SecureAreaRepository,
        storage: Storage
    ) {
        val parsedAuthorizationData = try {
            parseAuthorizationData(authorizationData)
        } catch (err: IllegalArgumentException) {
            Logger.e(TAG, "Failed to clean-up authorization data: could not parse", err)
            return
        }
        return when (val t = parsedAuthorizationData["type"].asTstr) {
            "openid4vci" ->
                OpenID4VCIProvisioningClient.cleanupAuthorizationData(
                    authorizationData = parsedAuthorizationData,
                    secureAreaRepository = secureAreaRepository,
                    storage = storage
                )
            else -> {
                Logger.e(TAG, "Failed to clean-up authorization data of unknown type '$t'")
            }
        }
    }

    private fun parseAuthorizationData(authorizationData: ByteString): CborMap {
        val parsedAuthorizationData = Cbor.decode(authorizationData.toByteArray())
        if (parsedAuthorizationData !is CborMap || !parsedAuthorizationData.hasKey("type")) {
            throw IllegalArgumentException("Not a valid authorization data")
        }
        if (parsedAuthorizationData["type"] !is Tstr) {
            throw IllegalArgumentException("Invalid authorization data type")
        }
        return parsedAuthorizationData
    }

    private const val TAG = "Provisioning"
}