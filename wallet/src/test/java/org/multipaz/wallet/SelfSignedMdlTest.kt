package org.multipaz.wallet

import org.multipaz.device.DeviceAssertion
import org.multipaz.provisioning.evidence.EvidenceResponseMessage
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import kotlinx.coroutines.test.runTest
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.security.Security

class SelfSignedMdlTest {
    private fun getProofingQuestions() : List<org.multipaz.provisioning.evidence.EvidenceRequest> {
        return listOf<org.multipaz.provisioning.evidence.EvidenceRequest>(
            org.multipaz.provisioning.evidence.EvidenceRequestMessage(
                "Here's a long string with TOS",
                mapOf(),
                "Accept",
                "Do Not Accept",
            ),
            org.multipaz.provisioning.evidence.EvidenceRequestQuestionString(
                "What first name should be used for the mDL?",
                mapOf(),
                "Erika",
                "Continue",
            ),
            org.multipaz.provisioning.evidence.EvidenceRequestQuestionMultipleChoice(
                "Select the card art for the credential",
                mapOf(),
                mapOf("green" to "Green", "blue" to "Blue", "red" to "Red"),
                "Continue",
            ),
            org.multipaz.provisioning.evidence.EvidenceRequestMessage(
                "Your application is about to be sent the ID issuer for " +
                        "verification. You will get notified when the " +
                        "application is approved.",
                mapOf(),
                "Continue",
                null,
            )
        )
    }

    @Test
    fun happyPath() = runTest {
        val storage = EphemeralStorage()
        val secureArea = SoftwareSecureArea.create(storage)

        val ia = TestIssuingAuthority()

        // Register credential...
        val registerdocumentFlow = ia.register()
        val registrationConfiguration = registerdocumentFlow.getDocumentRegistrationConfiguration()
        val documentId = registrationConfiguration.documentId
        val registrationResponse = org.multipaz.provisioning.RegistrationResponse(true)
        registerdocumentFlow.sendDocumentRegistrationResponse(registrationResponse)
        ia.completeRegistration(registerdocumentFlow)

        // Check we're now in the proofing state.
        Assert.assertEquals(
            org.multipaz.provisioning.DocumentCondition.PROOFING_REQUIRED,
            ia.getState(documentId).condition)

        // Perform proofing
        val proofingFlow = ia.proof(documentId)

        // First piece of evidence to return...
        var evidenceToGet = proofingFlow.getEvidenceRequests()
        Assert.assertEquals(1, evidenceToGet.size)
        Assert.assertTrue(evidenceToGet[0] is org.multipaz.provisioning.evidence.EvidenceRequestMessage)
        Assert.assertEquals("Here's a long string with TOS", (evidenceToGet[0] as org.multipaz.provisioning.evidence.EvidenceRequestMessage).message)
        proofingFlow.sendEvidence(
            org.multipaz.provisioning.evidence.EvidenceResponseMessage(
                true
            )
        )

        // Second piece of evidence to return...
        evidenceToGet = proofingFlow.getEvidenceRequests()
        Assert.assertEquals(1, evidenceToGet.size)
        Assert.assertTrue(evidenceToGet[0] is org.multipaz.provisioning.evidence.EvidenceRequestQuestionString)
        Assert.assertEquals(
            "What first name should be used for the mDL?",
            (evidenceToGet[0] as org.multipaz.provisioning.evidence.EvidenceRequestQuestionString).message)
        Assert.assertEquals(
            "Erika",
            (evidenceToGet[0] as org.multipaz.provisioning.evidence.EvidenceRequestQuestionString).defaultValue)
        proofingFlow.sendEvidence(
            org.multipaz.provisioning.evidence.EvidenceResponseQuestionString(
                "Max"
            )
        )
        Assert.assertEquals(
            org.multipaz.provisioning.DocumentCondition.PROOFING_REQUIRED,
            ia.getState(documentId).condition)

        // Third piece of evidence to return...
        evidenceToGet = proofingFlow.getEvidenceRequests()
        Assert.assertEquals(1, evidenceToGet.size)
        Assert.assertTrue(evidenceToGet[0] is org.multipaz.provisioning.evidence.EvidenceRequestQuestionMultipleChoice)
        Assert.assertEquals(3,
            (evidenceToGet[0] as org.multipaz.provisioning.evidence.EvidenceRequestQuestionMultipleChoice).possibleValues.size)
        proofingFlow.sendEvidence(
            org.multipaz.provisioning.evidence.EvidenceResponseQuestionMultipleChoice(
                (evidenceToGet[0] as org.multipaz.provisioning.evidence.EvidenceRequestQuestionMultipleChoice).possibleValues.keys.iterator()
                    .next()
            )
        )

        // Fourth piece of evidence to return...
        evidenceToGet = proofingFlow.getEvidenceRequests()
        Assert.assertEquals(1, evidenceToGet.size)
        Assert.assertTrue(evidenceToGet[0] is org.multipaz.provisioning.evidence.EvidenceRequestMessage)
        Assert.assertTrue((evidenceToGet[0] as org.multipaz.provisioning.evidence.EvidenceRequestMessage).message
            .startsWith("Your application is about to be sent"))
        proofingFlow.sendEvidence(
            EvidenceResponseMessage(
                true
            )
        )

        // Check there are no more pieces of evidence to return and it's now processing
        // after we signal that proofing is complete
        evidenceToGet = proofingFlow.getEvidenceRequests()
        Assert.assertEquals(0, evidenceToGet.size)
        ia.completeProof(proofingFlow)

        Assert.assertEquals(
            org.multipaz.provisioning.DocumentCondition.PROOFING_PROCESSING,
            ia.getState(documentId).condition)
        // Processing is hard-coded to take three seconds
        Thread.sleep(2100)
        Assert.assertEquals(
            org.multipaz.provisioning.DocumentCondition.PROOFING_PROCESSING,
            ia.getState(documentId).condition)
        Thread.sleep(900)
        Assert.assertEquals(
            org.multipaz.provisioning.DocumentCondition.CONFIGURATION_AVAILABLE,
            ia.getState(documentId).condition)

        // Check we can get the credential configuration
        val configuration = ia.getDocumentConfiguration(documentId)
        Assert.assertEquals("Max's Driving License", configuration.displayName)
        Assert.assertEquals(
            org.multipaz.provisioning.DocumentCondition.READY,
            ia.getState(documentId).condition)

        // Check we can get CPOs, first request them
        val numMso = 5
        val requestCpoFlow = ia.requestCredentials(documentId)
        val authKeyConfiguration = requestCpoFlow.getCredentialConfiguration(org.multipaz.provisioning.CredentialFormat.MDOC_MSO)
        val credentialRequests = mutableListOf<org.multipaz.provisioning.CredentialRequest>()
        for (authKeyNumber in IntRange(0, numMso - 1)) {
            val alias = "AuthKey_$authKeyNumber"
            secureArea.createKey(alias, CreateKeySettings())
            credentialRequests.add(
                org.multipaz.provisioning.CredentialRequest(secureArea.getKeyInfo(alias).attestation)
            )
        }
        requestCpoFlow.sendCredentials(
            credentialRequests,
            DeviceAssertion(ByteString(), ByteString())
        )
        ia.completeRequestCredentials(requestCpoFlow)

        // documentInformation should now reflect that the CPOs are pending and not
        // yet available..
        ia.getState(documentId).let {
            Assert.assertEquals(org.multipaz.provisioning.DocumentCondition.READY, it.condition)
            Assert.assertEquals(5, it.numPendingCredentials)
            Assert.assertEquals(0, it.numAvailableCredentials)
        }
        Assert.assertEquals(0, ia.getCredentials(documentId).size)
        Thread.sleep(100)
        // Still not available...
        ia.getState(documentId).let {
            Assert.assertEquals(org.multipaz.provisioning.DocumentCondition.READY, it.condition)
            Assert.assertEquals(5, it.numPendingCredentials)
            Assert.assertEquals(0, it.numAvailableCredentials)
        }
        Assert.assertEquals(0, ia.getCredentials(documentId).size)
        // But it is available after 3 seconds
        Thread.sleep(2900)
        ia.getState(documentId).let {
            Assert.assertEquals(org.multipaz.provisioning.DocumentCondition.READY, it.condition)
            Assert.assertEquals(0, it.numPendingCredentials)
            Assert.assertEquals(5, it.numAvailableCredentials)
        }
        // Check we get 5 CPOs and that they match the keys we passed in..
        ia.getCredentials(documentId).let {
            Assert.assertEquals(5, it.size)
            for (n in IntRange(0, it.size - 1)) {
                Assert.assertEquals(
                    it[n].secureAreaBoundKey,
                    credentialRequests[n].secureAreaBoundKeyAttestation.publicKey
                )
            }
        }
        // Once we collected them, they are no longer available to be collected
        // and nothing is pending
        ia.getState(documentId).let {
            Assert.assertEquals(org.multipaz.provisioning.DocumentCondition.READY, it.condition)
            Assert.assertEquals(0, it.numPendingCredentials)
            Assert.assertEquals(0, it.numAvailableCredentials)
        }
        Assert.assertEquals(0, ia.getCredentials(documentId).size)
    }

}