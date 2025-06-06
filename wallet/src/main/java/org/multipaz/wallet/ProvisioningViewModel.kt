package org.multipaz.wallet

import android.os.Looper
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import org.multipaz.credential.Credential
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.provisioning.CredentialFormat
import org.multipaz.wallet.provisioning.DocumentExtensions.documentConfiguration
import org.multipaz.wallet.provisioning.DocumentExtensions.walletDocumentMetadata
import org.multipaz.provisioning.Proofing
import org.multipaz.provisioning.RegistrationResponse
import org.multipaz.wallet.provisioning.WalletDocumentMetadata
import org.multipaz.provisioning.evidence.EvidenceRequest
import org.multipaz.provisioning.evidence.EvidenceRequestIcaoNfcTunnel
import org.multipaz.provisioning.evidence.EvidenceRequestOpenid4Vp
import org.multipaz.provisioning.evidence.EvidenceRequestCredentialOffer
import org.multipaz.provisioning.evidence.EvidenceResponse
import org.multipaz.provisioning.evidence.EvidenceResponseIcaoNfcTunnel
import org.multipaz.provisioning.evidence.EvidenceResponseCredentialOffer
import org.multipaz.provisioning.evidence.Openid4VciCredentialOffer
import org.multipaz.provisioning.evidence.Openid4VciCredentialOfferAuthorizationCode
import org.multipaz.wallet.provisioning.remote.WalletServerProvider
import org.multipaz.util.Logger
import org.multipaz.util.fromBase64Url
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.buildByteString
import org.json.JSONObject
import org.multipaz.provisioning.IssuingAuthority
import org.multipaz.rpc.handler.RpcAuthClientSession
import kotlin.coroutines.cancellation.CancellationException

class ProvisioningViewModel : ViewModel() {

    companion object {
        private const val TAG = "ProvisioningViewModel"
    }

    enum class State {
        IDLE,
        CREDENTIAL_REGISTRATION,
        EVIDENCE_REQUESTS_READY,
        SUBMITTING_EVIDENCE,
        PROOFING_COMPLETE,
        FAILED,
    }

    var state = mutableStateOf(State.IDLE)

    var error: Throwable? = null

    private lateinit var walletServerProvider: WalletServerProvider
    private lateinit var documentStore: DocumentStore
    private lateinit var settingsModel: SettingsModel

    private var openid4VciCredentialOffer: Openid4VciCredentialOffer? = null

    fun init(
        walletServerProvider: WalletServerProvider,
        documentStore: DocumentStore,
        settingsModel: SettingsModel,
    ) {
        this.walletServerProvider = walletServerProvider
        this.documentStore = documentStore
        this.settingsModel = settingsModel
    }

    fun reset() {
        state.value = State.IDLE
        error = null
        document = null
        proofing = null
        issuingAuthority = null
        evidenceRequests = null
        currentEvidenceRequestIndex = 0
        nextEvidenceRequest.value = null
        selectedOpenid4VpCredential.value = null
    }

    private var issuingAuthority: IssuingAuthority? = null
    private var proofing: Proofing? = null

    var document: Document? = null
    private var evidenceRequests: List<EvidenceRequest>? = null
    private var currentEvidenceRequestIndex: Int = 0
    private var job: Job? = null

    val nextEvidenceRequest = mutableStateOf<EvidenceRequest?>(null)
    val selectedOpenid4VpCredential = mutableStateOf<Credential?>(null)

    fun start(
        // PID-based mdoc or sd-jwt
        issuerIdentifier: String?,
        openid4VciCredentialOffer: Openid4VciCredentialOffer? = null,
    ) {
        val lastJob = this.job
        if (lastJob != null) {
            this.job = null
            lastJob.cancel(CancellationException("New provisioning started"))
        }
        this.job = viewModelScope.launch(Dispatchers.IO + RpcAuthClientSession()) {
            lastJob?.join()
            reset()
            state.value = State.IDLE
            try {
                val issuer = if (openid4VciCredentialOffer != null) {
                    this@ProvisioningViewModel.openid4VciCredentialOffer = openid4VciCredentialOffer
                    walletServerProvider.createOpenid4VciIssuingAuthorityByUri(
                        openid4VciCredentialOffer.issuerUri,
                        openid4VciCredentialOffer.configurationId
                    )
                } else {
                    walletServerProvider.getIssuingAuthority(issuerIdentifier!!)
                }
                val issuerConfiguration = issuer.getConfiguration()

                state.value = State.CREDENTIAL_REGISTRATION
                val createDocumentKeyFlow = issuer.register()
                val documentRegistrationConfiguration =
                    createDocumentKeyFlow.getDocumentRegistrationConfiguration()
                val issuerDocumentIdentifier = documentRegistrationConfiguration.documentId
                val response = RegistrationResponse(
                    settingsModel.developerModeEnabled.value!!
                )
                createDocumentKeyFlow.sendDocumentRegistrationResponse(response)
                issuer.completeRegistration(createDocumentKeyFlow)

                val pendingDocumentConfiguration = issuerConfiguration.pendingDocumentInformation
                document = documentStore.createDocument { metadata ->
                    val walletMetadata = metadata as WalletDocumentMetadata
                    walletMetadata.initialize(
                        issuingAuthorityIdentifier = issuerConfiguration.identifier,
                        documentIdentifier = issuerDocumentIdentifier,
                        documentConfiguration = pendingDocumentConfiguration,
                        issuingAuthorityConfiguration = issuerConfiguration,
                    )
                    walletMetadata.refreshState(walletServerProvider)
                }

                proofing = issuer.proof(issuerDocumentIdentifier)
                issuingAuthority = issuer
                evidenceRequests = proofing!!.getEvidenceRequests()
                // EvidenceRequestCredentialOffer (if requested at all) is always the first request.
                if (evidenceRequests!!.isNotEmpty() &&
                        evidenceRequests!![0] is EvidenceRequestCredentialOffer) {
                    proofing!!.sendEvidence(
                        EvidenceResponseCredentialOffer(openid4VciCredentialOffer ?:
                                createDefaultCredentialOffer(issuerIdentifier!!))
                    )
                    evidenceRequests = proofing!!.getEvidenceRequests()
                }

                currentEvidenceRequestIndex = 0
                Logger.d(TAG, "ers0 ${evidenceRequests!!.size}")

                if (evidenceRequests!!.size == 0) {
                    state.value = State.PROOFING_COMPLETE
                    val metadata = document!!.walletDocumentMetadata
                    metadata.refreshState(walletServerProvider)
                    metadata.markAsProvisioned()
                    issuer.completeProof(proofing!!)
                } else {
                    selectViableEvidenceRequest()
                    state.value = State.EVIDENCE_REQUESTS_READY
                }
            } catch (e: Throwable) {
                if (document != null) {
                    documentStore.deleteDocument(document!!.identifier)
                }
                Logger.w(TAG, "Error registering Document", e)
                e.printStackTrace()
                error = e
                state.value = State.FAILED
            }
        }
    }

    private fun createDefaultCredentialOffer(issuerIdentifier: String): Openid4VciCredentialOffer {
        val parts = issuerIdentifier.split('#')
        return Openid4VciCredentialOfferAuthorizationCode(
            parts[1], parts[2], null, null)
    }

    suspend fun evidenceCollectionFailed(
        error: Throwable
    ) {
        val nameToDelete = document?.identifier
        if (nameToDelete != null) {
            document = null
            documentStore.deleteDocument(nameToDelete)
        }
        Logger.w(TAG, "Error collecting evidence", error)
        this.error = error
        state.value = State.FAILED
    }

    fun provideEvidence(evidence: EvidenceResponse) {
        this.job = viewModelScope.launch(Dispatchers.IO) {
            try {
                withContext(RpcAuthClientSession()) {
                    state.value = State.SUBMITTING_EVIDENCE

                    proofing!!.sendEvidence(evidence)

                    evidenceRequests = proofing!!.getEvidenceRequests()
                    currentEvidenceRequestIndex = 0

                    Logger.d(TAG, "ers1 ${evidenceRequests!!.size}")
                    if (evidenceRequests!!.isEmpty()) {
                        state.value = State.PROOFING_COMPLETE
                        val metadata = document!!.walletDocumentMetadata
                        metadata.refreshState(walletServerProvider)
                        metadata.markAsProvisioned()
                        issuingAuthority!!.completeProof(proofing!!)
                        metadata.refreshState(walletServerProvider)
                    } else {
                        selectViableEvidenceRequest()
                        state.value = State.EVIDENCE_REQUESTS_READY
                    }
                }
            } catch (e: Throwable) {
                val nameToDelete = document?.identifier
                if (nameToDelete != null) {
                    document = null
                    documentStore.deleteDocument(nameToDelete)
                }
                Logger.w(TAG, "Error submitting evidence", e)
                e.printStackTrace()
                error = e
                state.value = State.FAILED
            }
        }
    }

    /**
     * Handles request/response exchange through NFC tunnel.
     *
     * This must be called on a backround thread and will block until the tunnel is
     * closed.
     *
     * @param handler a handler that communicates to the chip passing in the requests that it
     *     gets as parameter returning responses wrapped in [EvidenceResponseIcaoTunnel].
     */
    fun runIcaoNfcTunnel(handler: (EvidenceRequestIcaoNfcTunnel) -> EvidenceResponseIcaoNfcTunnel) {
        // must run on a background thread
        if (Looper.getMainLooper().isCurrentThread) {
            throw IllegalStateException("Must not be called on main thread")
        }

        runBlocking {
            // handshake
            proofing!!.sendEvidence(EvidenceResponseIcaoNfcTunnel(buildByteString {}))

            while (true) {
                val requests = proofing!!.getEvidenceRequests()
                if (requests.size != 1) {
                    break
                }
                val request = requests[0]
                if (request !is EvidenceRequestIcaoNfcTunnel) {
                    break
                }

                val response = handler(request)
                proofing!!.sendEvidence(response)
            }
        }
    }

    fun finishTunnel() {
        viewModelScope.launch(Dispatchers.IO) {
            // This is a hack needed since evidenceRequests is not a state (and it should be).
            // TODO: remove this once evidenceRequests becomes state
            state.value = State.SUBMITTING_EVIDENCE
            state.value = State.EVIDENCE_REQUESTS_READY
            evidenceRequests = proofing!!.getEvidenceRequests()
            currentEvidenceRequestIndex = 0
            selectViableEvidenceRequest()
        }
    }

    suspend fun moveToNextEvidenceRequest(): Boolean {
        currentEvidenceRequestIndex++
        return selectViableEvidenceRequest()
    }

    private suspend fun selectViableEvidenceRequest(): Boolean {
        val evidenceRequests = this.evidenceRequests!!
        if (currentEvidenceRequestIndex >= evidenceRequests.size) {
            return false
        }
        val request = evidenceRequests[currentEvidenceRequestIndex]
        if (request is EvidenceRequestOpenid4Vp) {
            val openid4VpCredential = selectCredential(request.request)
            if (openid4VpCredential != null) {
                // EvidenceRequestOpenid4Vp must not come by itself
                nextEvidenceRequest.value = request
                selectedOpenid4VpCredential.value = openid4VpCredential
            } else {
                currentEvidenceRequestIndex++
                if (currentEvidenceRequestIndex >= evidenceRequests.size) {
                    return false
                }
                nextEvidenceRequest.value = evidenceRequests[currentEvidenceRequestIndex]
                selectedOpenid4VpCredential.value = null
            }
        } else {
            nextEvidenceRequest.value = request
            selectedOpenid4VpCredential.value = null
        }
        return true
    }

    private suspend fun selectCredential(request: String): Credential? {
        val parts = request.split('.')
        val openid4vpRequest = JSONObject(String(parts[1].fromBase64Url()))

        val presentationDefinition = openid4vpRequest.getJSONObject("presentation_definition")
        val inputDescriptors = presentationDefinition.getJSONArray("input_descriptors")
        if (inputDescriptors.length() != 1) {
            throw IllegalArgumentException("Only support a single input input_descriptor")
        }
        val inputDescriptor = inputDescriptors.getJSONObject(0)!!
        val docType = inputDescriptor.getString("id")

        // For now, we only respond to the first credential being requested.
        //
        // NOTE: openid4vp spec gives a non-normative example of multiple input descriptors
        // as "alternatives credentials", see
        //
        //  https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-6
        //
        // Also note identity.foundation says all input descriptors MUST be satisfied, see
        //
        //  https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor
        //
        val credentialFormat = CredentialFormat.MDOC_MSO
        val document = firstMatchingDocument(credentialFormat, docType)
        return document?.findCredential(WalletApplication.CREDENTIAL_DOMAIN_MDOC, Clock.System.now())
    }

    private suspend fun firstMatchingDocument(
        credentialFormat: CredentialFormat,
        docType: String
    ): Document? {
        // prefer the credential which is on-screen if possible
        val credentialIdFromPager: String? = settingsModel.focusedCardId.value
        if (credentialIdFromPager != null
            && canDocumentSatisfyRequest(credentialIdFromPager, credentialFormat, docType)
        ) {
            return documentStore.lookupDocument(credentialIdFromPager)
        }

        val docId = documentStore.listDocuments().firstOrNull { credentialId ->
            canDocumentSatisfyRequest(credentialId, credentialFormat, docType)
        }
        return docId?.let { documentStore.lookupDocument(it) }
    }

    private suspend fun canDocumentSatisfyRequest(
        credentialId: String,
        credentialFormat: CredentialFormat,
        docType: String
    ): Boolean {
        val document = documentStore.lookupDocument(credentialId) ?: return false
        val documentConfiguration = document.documentConfiguration
        return when (credentialFormat) {
            CredentialFormat.MDOC_MSO -> documentConfiguration.mdocConfiguration?.docType == docType
            CredentialFormat.SD_JWT_VC -> documentConfiguration.sdJwtVcDocumentConfiguration != null
            CredentialFormat.DirectAccess -> documentConfiguration.directAccessConfiguration?.docType == docType
        }
    }
}