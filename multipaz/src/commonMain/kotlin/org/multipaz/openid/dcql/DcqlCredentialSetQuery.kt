package org.multipaz.openid.dcql

/**
 * DCQL Credential Set.
 *
 * Reference: OpenID4VP 1.0 Section 6.4.2.
 *
 * @property required `true` if this credential set must be satisfied, `false` otherwise.
 * @property options a list of ways the credential set can be satisfied, see [DcqlCredentialSetOption].
 */
data class DcqlCredentialSetQuery(
    val required: Boolean,
    val options: List<DcqlCredentialSetOption>
)
