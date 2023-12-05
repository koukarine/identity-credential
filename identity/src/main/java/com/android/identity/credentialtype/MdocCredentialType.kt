/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.identity.credentialtype

/**
 * Class containing the metadata of an mDoc Credential Type.
 *
 * @param docType the docType of the mDoc Credential Type.
 * @param namespaces the namespaces of the mDoc Credential Type.
 */
class MdocCredentialType private constructor(
    val docType: String,
    val namespaces: List<MdocNamespace>
) {

    /**
     * Builder class for class [MdocCredentialType].
     *
     * @param docType the docType of the mDoc Credential Type.
     * @param namespaces the namespaces of the mDoc Credential Type.
     */
    data class Builder(
        val docType: String,
        val namespaces: MutableMap<String, MdocNamespace.Builder> = mutableMapOf()
    ) {
        /**
         * Add a data element to a namespace in the mDoc Credential Type.
         *
         * @param namespace the namespace of the mDoc attribute.
         * @param type the datatype of this attribute.
         * @param identifier the identifier of this attribute.
         * @param displayName the name suitable for display of the attribute.
         * @param description a description of the attribute.
         * @param mandatory indication whether the mDoc attribute is mandatory.
         */
        fun addDataElement(
            namespace: String,
            type: CredentialAttributeType,
            identifier: String,
            displayName: String,
            description: String,
            mandatory: Boolean
        ) = apply {
            if (!namespaces.containsKey(namespace)) {
                namespaces[namespace] = MdocNamespace.Builder(namespace)
            }
            namespaces[namespace]!!.addDataElement(
                type,
                identifier,
                displayName,
                description,
                mandatory
            )
        }

        /**
         * Build the [MdocCredentialType].
         */
        fun build() = MdocCredentialType(docType, namespaces.values.map { it.build() })
    }
}