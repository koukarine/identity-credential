package org.multipaz.directaccess

import org.multipaz.claim.Claim
import org.multipaz.credential.Credential
import org.multipaz.document.Document
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.securearea.KeyAttestation

expect class DirectAccessCredential : Credential {

    constructor(document: Document)

    val attestation: KeyAttestation

    override val credentialType: String

    /**
     * The docType of the credential as defined in
     * [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html).
     */
    var docType: String
        private set

    override fun getClaims(documentTypeRepository: DocumentTypeRepository?): List<Claim>

    companion object {
        val CREDENTIAL_TYPE: String

        /**
         * Creates a new [DirectAccessCredential] and save it to APDU.
         *
         * @param document The document to be signed.
         * @param asReplacementForIdentifier The identifier of the credential to be replaced.
         * @param domain The domain of the credential.
         * @param docType The document type of the credential.
         *
         * @return The created [DirectAccessCredential].
         */
        suspend fun create(
            document: Document,
            asReplacementForIdentifier: String?,
            domain: String,
            documentType: String
        ): DirectAccessCredential

        suspend fun delete(documentType: String)
    }
}