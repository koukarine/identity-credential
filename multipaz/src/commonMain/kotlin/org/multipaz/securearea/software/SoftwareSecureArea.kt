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
package org.multipaz.securearea.software

import org.multipaz.cbor.Cbor
import org.multipaz.cbor.CborMap
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.EcSignature
import org.multipaz.prompt.requestPassphrase
import org.multipaz.securearea.KeyUnlockInteractive
import org.multipaz.securearea.KeyAttestation
import org.multipaz.securearea.KeyLockedException
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.PassphraseConstraints
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.fromDataItem
import org.multipaz.securearea.toDataItem
import org.multipaz.storage.Storage
import org.multipaz.storage.StorageTable
import org.multipaz.storage.StorageTableSpec
import kotlinx.io.bytestring.ByteString
import org.multipaz.cbor.buildCborMap
import kotlin.random.Random

/**
 * An implementation of [SecureArea] in software.
 *
 * This implementation supports all the curves and algorithms defined by [SecureArea]
 * and also supports passphrase-protected keys. Key material is stored using the
 * [Storage] abstraction and passphrase-protected keys are encrypted using
 * [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
 * with 256-bit keys with the key derived from the passphrase using
 * [HKDF](https://en.wikipedia.org/wiki/HKDF).
 *
 * This is currently implemented using the
 * [Bouncy Castle](https://www.bouncycastle.org/) library but this implementation
 * detail may change in the future.
 *
 * Use [SoftwareSecureArea.create] to create an instance of SoftwareSecureArea.
 */
class SoftwareSecureArea private constructor(private val storageTable: StorageTable) : SecureArea {
    override val identifier get() = IDENTIFIER

    override val displayName get() = "Software Secure Area"

    private val supportedAlgorithms_: List<Algorithm> by lazy {
        Algorithm.entries.filter {
            it.fullySpecified && Crypto.supportedCurves.contains(it.curve!!)
        }
    }

    override val supportedAlgorithms: List<Algorithm>
        get() = supportedAlgorithms_

    override suspend fun createKey(
        alias: String?,
        createKeySettings: org.multipaz.securearea.CreateKeySettings
    ): SoftwareKeyInfo {
        if (alias != null) {
            // If the key with the given alias exists, it is silently overwritten.
            storageTable.delete(alias)
        }

        val settings = if (createKeySettings is SoftwareCreateKeySettings) {
            createKeySettings
        } else {
            // If user passed in a generic SecureArea.CreateKeySettings, honor them.
            SoftwareCreateKeySettings.Builder()
                .setAlgorithm(createKeySettings.algorithm)
                .build()
        }
        try {
            val privateKey = Crypto.createEcPrivateKey(settings.algorithm.curve!!)
            val map = buildCborMap {
                put("algorithm", settings.algorithm.name)
                put("passphraseRequired", settings.passphraseRequired)
                if (!settings.passphraseRequired) {
                    put("privateKey", privateKey.toCoseKey().toDataItem())
                } else {
                    val encodedPublicKey = Cbor.encode(privateKey.publicKey.toCoseKey().toDataItem())
                    val secretKey = derivePrivateKeyEncryptionKey(encodedPublicKey, settings.passphrase!!)
                    val cleartextPrivateKey = Cbor.encode(privateKey.toCoseKey().toDataItem())
                    val iv = Random.Default.nextBytes(12)
                    val encryptedPrivateKey = Crypto.encrypt(
                        Algorithm.A128GCM,
                        secretKey,
                        iv,
                        cleartextPrivateKey
                    )
                    put("encodedPublicKey", encodedPublicKey)
                    put("encryptedPrivateKey", encryptedPrivateKey)
                    put("encryptedPrivateKeyIv", iv)
                }
                put("publicKey", privateKey.publicKey.toCoseKey().toDataItem())
                if (settings.passphraseConstraints != null) {
                    put("passphraseConstraints", settings.passphraseConstraints.toDataItem())
                }
            }
            val newAlias = storageTable.insert(
                key = alias,
                data = ByteString(Cbor.encode(map))
            )
            return getKeyInfo(newAlias)
        } catch (e: Exception) {
            // such as NoSuchAlgorithmException, CertificateException, InvalidAlgorithmParameterException, OperatorCreationException, IOException, NoSuchProviderException
            throw IllegalStateException("Unexpected exception", e)
        }
    }

    private fun derivePrivateKeyEncryptionKey(
        encodedPublicKey: ByteArray,
        passphrase: String
    ): ByteArray {
        val info = "ICPrivateKeyEncryption1".encodeToByteArray()
        return Crypto.hkdf(
            Algorithm.HMAC_SHA256,
            passphrase.encodeToByteArray(),
            encodedPublicKey,
            info,
            32
        )
    }

    override suspend fun deleteKey(alias: String) {
        storageTable.delete(alias)
    }

    private data class KeyData(
        val algorithm: Algorithm,
        val privateKey: EcPrivateKey,
    )

    private suspend fun loadKey(
        alias: String,
        keyUnlockData: KeyUnlockData?
    ): KeyData {
        var passphrase: String? = null
        if (keyUnlockData != null) {
            val unlockData = keyUnlockData as SoftwareKeyUnlockData
            passphrase = unlockData.passphrase
        }
        val data = storageTable.get(alias)
            ?: throw IllegalArgumentException("No key with given alias")
        val map = Cbor.decode(data.toByteArray())
        val algorithm = Algorithm.fromName(map["algorithm"].asTstr)
        val passphraseRequired = map["passphraseRequired"].asBoolean
        val privateKeyCoseKey = if (passphraseRequired) {
            if (passphrase == null) {
                throw KeyLockedException("No passphrase provided")
            }
            val encodedPublicKey = map["encodedPublicKey"].asBstr
            val encryptedPrivateKey = map["encryptedPrivateKey"].asBstr
            val iv = map["encryptedPrivateKeyIv"].asBstr
            val secretKey = derivePrivateKeyEncryptionKey(encodedPublicKey, passphrase)
            val encodedPrivateKey = try {
                Crypto.decrypt(Algorithm.A128GCM, secretKey, iv, encryptedPrivateKey)
            } catch (e: Exception) {
                throw KeyLockedException("Error decrypting private key - wrong passphrase?", e)
            }
            Cbor.decode(encodedPrivateKey).asCoseKey
        } else {
            map["privateKey"].asCoseKey
        }
        return KeyData(algorithm, privateKeyCoseKey.ecPrivateKey)
    }

    /**
     * Gets the underlying private key.
     *
     * @param alias the alias for the key.
     * @param keyUnlockData unlock data, or `null`.
     * @return a [PrivateKey].
     * @throws KeyLockedException
     */
    suspend fun getPrivateKey(
        alias: String,
        keyUnlockData: KeyUnlockData?
    ): EcPrivateKey = loadKey(alias, keyUnlockData).privateKey

    private suspend fun<T> interactionHelper(
        alias: String,
        keyUnlockData: KeyUnlockData?,
        op: suspend (unlockData: KeyUnlockData?) -> T,
    ): T {
        if (keyUnlockData !is KeyUnlockInteractive) {
            return op(keyUnlockData)
        }
        var softwareKeyUnlockData: SoftwareKeyUnlockData? = null
        do {
            try {
                return op(softwareKeyUnlockData)
            } catch (_: KeyLockedException) {
                val keyInfo = getKeyInfo(alias)
                val constraints = keyInfo.passphraseConstraints ?: PassphraseConstraints.NONE
                // TODO: translations
                val defaultSubtitle = if (constraints.requireNumerical) {
                    "Enter the PIN associated with the document"
                } else {
                    "Enter the passphrase associated with the document"
                }
                val passphrase = requestPassphrase(
                    title = keyUnlockData.title ?: "Verify it's you",
                    subtitle = keyUnlockData.subtitle ?: defaultSubtitle,
                    passphraseConstraints = constraints,
                    passphraseEvaluator = { enteredPassphrase: String ->
                        try {
                            loadKey(alias, SoftwareKeyUnlockData(enteredPassphrase))
                            null
                        } catch (_: Throwable) {
                            // TODO: translations
                            if (constraints.requireNumerical) {
                                "Wrong PIN entered. Try again"
                            } else {
                                "Wrong passphrase entered. Try again"
                            }
                        }
                    }
                )
                if (passphrase == null) {
                    throw KeyLockedException("User canceled passphrase prompt")
                }
                softwareKeyUnlockData = SoftwareKeyUnlockData(passphrase)
            }
        } while (true)
    }

    override suspend fun sign(
        alias: String,
        dataToSign: ByteArray,
        keyUnlockData: KeyUnlockData?
    ): EcSignature {
        return interactionHelper(
            alias,
            keyUnlockData,
            op = { unlockData -> signNonInteractive(alias, dataToSign, unlockData) }
        )
    }

    private suspend fun signNonInteractive(
        alias: String,
        dataToSign: ByteArray,
        keyUnlockData: KeyUnlockData?
    ): EcSignature {
        val keyData = loadKey(alias, keyUnlockData)
        require(keyData.algorithm.isSigning) { "Key algorithm is not for Signing" }
        return Crypto.sign(keyData.privateKey, keyData.algorithm, dataToSign)
    }

    override suspend fun keyAgreement(
        alias: String,
        otherKey: EcPublicKey,
        keyUnlockData: KeyUnlockData?
    ): ByteArray {
        return interactionHelper(
            alias,
            keyUnlockData,
            op = { unlockData -> keyAgreementNonInteractive(alias, otherKey, unlockData) }
        )
    }

    private suspend fun keyAgreementNonInteractive(
        alias: String,
        otherKey: EcPublicKey,
        keyUnlockData: KeyUnlockData?
    ): ByteArray {
        val keyData = loadKey(alias, keyUnlockData)
        require(keyData.algorithm.isKeyAgreement) { "Key algorithm is not for Key Agreement" }
        return Crypto.keyAgreement(keyData.privateKey, otherKey)
    }

    override suspend fun getKeyInfo(alias: String): SoftwareKeyInfo {
        val data = storageTable.get(alias)
            ?: throw IllegalArgumentException("No key with the given alias '$alias'")
        val map = Cbor.decode(data.toByteArray())
        val algorithm = Algorithm.fromName(map["algorithm"].asTstr)
        val passphraseRequired = map["passphraseRequired"].asBoolean
        val publicKey = map["publicKey"].asCoseKey.ecPublicKey
        val passphraseConstraints = map.getOrNull("passphraseConstraints")?.let {
            PassphraseConstraints.fromDataItem(it)
        }
        return SoftwareKeyInfo(
            alias,
            publicKey,
            KeyAttestation(publicKey, null),
            algorithm,
            passphraseRequired,
            passphraseConstraints
        )
    }

    override suspend fun getKeyInvalidated(alias: String): Boolean {
        // Software keys are never invalidated.
        return false
    }

    companion object {
        private const val TAG = "SoftwareSecureArea"

        const val IDENTIFIER = "SoftwareSecureArea"

        /**
         * Creates an instance of SoftwareSecureArea.
         *
         * @param storage the storage engine to use for storing key material.
         */
        suspend fun create(storage: Storage): SoftwareSecureArea {
            return SoftwareSecureArea(storage.getTable(tableSpec))
        }

        private val tableSpec = StorageTableSpec(
            name = "SoftwareSecureArea",
            supportPartitions = false,
            supportExpiration = false
        )
    }
}
