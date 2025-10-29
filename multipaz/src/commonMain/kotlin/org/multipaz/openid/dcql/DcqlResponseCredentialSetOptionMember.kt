package org.multipaz.openid.dcql

import org.multipaz.presentment.CredentialPresentmentSetOptionMember

/**
 * A member of a credential set which can be returned.
 */
class DcqlResponseCredentialSetOptionMember(
    override val matches: List<DcqlResponseCredentialSetOptionMemberMatch>,
): CredentialPresentmentSetOptionMember
