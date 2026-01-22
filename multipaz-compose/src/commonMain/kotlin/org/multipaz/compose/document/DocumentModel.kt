package org.multipaz.compose.document

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.multipaz.compose.branding.Branding
import org.multipaz.compose.decodeImage
import org.multipaz.credential.Credential
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.document.Document
import org.multipaz.document.DocumentDeleted
import org.multipaz.document.DocumentEvent
import org.multipaz.document.DocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.util.Logger

/**
 * Model that loads documents from a [DocumentStore] and keeps them updated.
 *
 * It exposes a [StateFlow] of all documents as [DocumentInfo]
 * and listens to live updates from the store. If a [Document] has no cardArt the model
 * creates a default stock cardArt.
 *
 * @param scope launches coroutines
 * @param documentStore the [DocumentStore] which manages [Document] and [Credential] instances.
 * @param documentTypeRepository a [DocumentTypeRepository] with information about document types or `null`.
 */
class DocumentModel(
    val scope: CoroutineScope = CoroutineScope(Dispatchers.Default),
    val documentStore: DocumentStore,
    val documentTypeRepository: DocumentTypeRepository?,
) {
    private val _documentInfos = MutableStateFlow<Map<String, DocumentInfo>>(emptyMap())

    /**
     * A map from [Document] identifier to [DocumentInfo].
     */
    val documentInfos: StateFlow<Map<String, DocumentInfo>> = _documentInfos.asStateFlow()

    init {
        scope.launch {
            val docIds = documentStore.listDocumentIds()
            docIds.forEach { documentId ->
                updateDocumentInfo(documentId)
            }

            documentStore.eventFlow
                .onEach { event ->
                    Logger.i(
                        TAG,
                        "DocumentStore event ${event::class.simpleName} ${event.documentId}"
                    )
                    updateDocumentInfo(event = event)

                }
                .launchIn(scope)
        }
    }

    private suspend fun updateDocumentInfo(
        documentId: String? = null,
        event: DocumentEvent? = null,
    ) {
        val id = event?.documentId ?: documentId ?: return
        if (event is DocumentDeleted) {
            _documentInfos.update { current ->
                current
                    .toMutableMap()
                    .apply { remove(id) }
                    .sortedMap()
            }
        } else {
            documentStore.lookupDocument(id)?.let { document ->
                _documentInfos.update { current ->
                    current
                        .toMutableMap()
                        .apply { this[id] = document.toDocumentInfo() }
                        .sortedMap()
                }
            }
        }
    }

    private suspend fun Document.toDocumentInfo(): DocumentInfo {
        cardArt?.let {
            return DocumentInfo(
                document = this,
                cardArt = decodeImage(it.toByteArray()),
                credentialInfos = buildCredentialInfos(documentTypeRepository)
            )
        }
        return DocumentInfo(
            document = this,
            cardArt = Branding.Current.value.renderFallbackCardArt(this),
            credentialInfos = buildCredentialInfos(documentTypeRepository)
        )
    }

    companion object {
        private const val TAG = "DocumentModel"

        private suspend fun Document.buildCredentialInfos(
            documentTypeRepository: DocumentTypeRepository?
        ): List<CredentialInfo> {
            return getCredentials().map { credential ->
                val keyInfo = if (credential is SecureAreaBoundCredential) {
                    credential.secureArea.getKeyInfo(credential.alias)
                } else {
                    null
                }
                val keyInvalidated = if (credential is SecureAreaBoundCredential) {
                    credential.secureArea.getKeyInvalidated(credential.alias)
                } else {
                    false
                }
                val claims = if (credential.isCertified) {
                    credential.getClaims(documentTypeRepository)
                } else {
                    emptyList()
                }
                CredentialInfo(
                    credential = credential,
                    claims = claims,
                    keyInfo = keyInfo,
                    keyInvalidated = keyInvalidated
                )
            }
        }

        private fun Map<String, DocumentInfo>.sortedMap(): Map<String, DocumentInfo> =
            this.entries
                .sortedWith { a, b ->
                    Document.Comparator.compare(a.value.document, b.value.document)
                }
                .associate { it.toPair() }
    }
}