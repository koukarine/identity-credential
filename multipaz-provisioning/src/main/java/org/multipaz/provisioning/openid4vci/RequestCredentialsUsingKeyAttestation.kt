package org.multipaz.provisioning.openid4vci

import org.multipaz.cbor.annotation.CborSerializable
import org.multipaz.device.DeviceAssertion
import org.multipaz.flow.annotation.FlowMethod
import org.multipaz.flow.annotation.FlowState
import org.multipaz.flow.server.FlowEnvironment
import org.multipaz.provisioning.CredentialConfiguration
import org.multipaz.provisioning.CredentialFormat
import org.multipaz.provisioning.CredentialRequest
import org.multipaz.provisioning.KeyPossessionChallenge
import org.multipaz.provisioning.KeyPossessionProof
import org.multipaz.provisioning.RequestCredentialsFlow

@FlowState(
    flowInterface = RequestCredentialsFlow::class
)
@CborSerializable
class RequestCredentialsUsingKeyAttestation(
    val clientId: String,
    documentId: String,
    credentialConfiguration: CredentialConfiguration,
    format: CredentialFormat? = null,
    val credentialRequestSets: MutableList<CredentialRequestSet> = mutableListOf()
) : AbstractRequestCredentials(documentId, credentialConfiguration, format) {
    companion object

    @FlowMethod
    fun getCredentialConfiguration(
        env: FlowEnvironment,
        format: CredentialFormat
    ): CredentialConfiguration {
        this.format = format
        return credentialConfiguration
    }

    @FlowMethod
    fun sendCredentials(
        env: FlowEnvironment,
        credentialRequests: List<CredentialRequest>,
        keysAssertion: DeviceAssertion? // holds AssertionBingingKeys
    ): List<KeyPossessionChallenge> {
        credentialRequestSets.add(CredentialRequestSet(
            format = format!!,
            keyAttestations = credentialRequests.map { it.secureAreaBoundKeyAttestation },
            keysAssertion = keysAssertion!!
        ))
        return emptyList()
    }

    @FlowMethod
    fun sendPossessionProofs(env: FlowEnvironment, keyPossessionProofs: List<KeyPossessionProof>) {
        throw UnsupportedOperationException("Should not be called")
    }
}