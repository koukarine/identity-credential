package org.multipaz.wallet.server

import org.multipaz.asn1.ASN1Integer
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DiagnosticOption
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tstr
import org.multipaz.cbor.annotation.CborSerializable
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.crypto.JsonWebEncryption
import org.multipaz.crypto.JsonWebSignature
import org.multipaz.crypto.X500Name
import org.multipaz.crypto.X509CertChain
import org.multipaz.crypto.javaPrivateKey
import org.multipaz.crypto.javaPublicKey
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.documenttype.DocumentCannedRequest
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.documenttype.knowntypes.EUCertificateOfResidence
import org.multipaz.documenttype.knowntypes.EUPersonalID
import org.multipaz.documenttype.knowntypes.GermanPersonalID
import org.multipaz.documenttype.knowntypes.PhotoID
import org.multipaz.documenttype.knowntypes.UtopiaMovieTicket
import org.multipaz.documenttype.knowntypes.UtopiaNaturalization
import org.multipaz.rpc.handler.RpcNotifications
import org.multipaz.rpc.backend.Configuration
import org.multipaz.rpc.backend.BackendEnvironment
import org.multipaz.rpc.backend.getTable
import org.multipaz.mdoc.request.DeviceRequestGenerator
import org.multipaz.mdoc.response.DeviceResponseParser
import org.multipaz.mdoc.util.MdocUtil
import org.multipaz.server.BaseHttpServlet
import org.multipaz.storage.StorageTable
import org.multipaz.storage.StorageTableSpec
import org.multipaz.util.Logger
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimePeriod
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
import kotlinx.datetime.plus
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import net.minidev.json.JSONArray
import net.minidev.json.JSONObject
import net.minidev.json.JSONStyle
import org.multipaz.asn1.ASN1
import org.multipaz.asn1.ASN1Encoding
import org.multipaz.asn1.ASN1Sequence
import org.multipaz.asn1.ASN1TagClass
import org.multipaz.asn1.ASN1TaggedObject
import org.multipaz.asn1.OID
import org.multipaz.cbor.addCborArray
import org.multipaz.cbor.addCborMap
import org.multipaz.cbor.buildCborArray
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.putCborMap
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509KeyUsage
import org.multipaz.sdjwt.SdJwt
import org.multipaz.sdjwt.SdJwtKb
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.URLEncoder
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random
import kotlin.time.Duration.Companion.days

private const val TAG = "VerifierServlet"

enum class Protocol {
    W3C_DC_PREVIEW,
    W3C_DC_ARF,
    W3C_DC_MDOC_API,
    W3C_DC_OPENID4VP,
    PLAIN_OPENID4VP,
    EUDI_OPENID4VP,
    MDOC_OPENID4VP,
    CUSTOM_OPENID4VP,
}

@Serializable
private data class OpenID4VPBeginRequest(
    val format: String,
    val docType: String,
    val requestId: String,
    val protocol: String,
    val origin: String,
    val host: String,
    val scheme: String
)

@Serializable
private data class OpenID4VPBeginResponse(
    val uri: String
)

@Serializable
private data class OpenID4VPRedirectUriResponse(
    val redirect_uri: String
)

@Serializable
private data class OpenID4VPGetData(
    val sessionId: String
)

@Serializable
private data class OpenID4VPResultData(
    val lines: List<OpenID4VPResultLine>
)

@Serializable
private data class OpenID4VPResultLine(
    val key: String,
    val value: String
)

@CborSerializable
data class Session(
    val requestFormat: String,      // "mdoc" or "vc"
    val requestDocType: String,     // mdoc DocType or VC vct
    val requestId: String,          // DocumentWellKnownRequest.id
    val protocol: Protocol,
    val nonce: ByteString,
    val origin: String,             // e.g. https://ws.davidz25.net
    val host: String,               // e.g. ws.davidz25.net
    val encryptionKey: EcPrivateKey,
    val signRequest: Boolean = true,
    val encryptResponse: Boolean = true,
    var responseUri: String? = null,
    var deviceResponse: ByteArray? = null,
    var verifiablePresentation: String? = null,
    var sessionTranscript: ByteArray? = null,
    var responseWasEncrypted: Boolean = false,
) {
    companion object
}

@Serializable
private data class AvailableRequests(
    val documentTypesWithRequests: List<DocumentTypeWithRequests>
)

@Serializable
private data class DocumentTypeWithRequests(
    val documentDisplayName: String,
    val mdocDocType: String?,
    val vcVct: String?,
    val sampleRequests: List<SampleRequest>
)

@Serializable
private data class SampleRequest(
    val id: String,
    val displayName: String,
    val supportsMdoc: Boolean,
    val supportsVc: Boolean
)

@Serializable
private data class DCBeginRequest(
    val format: String,
    val docType: String,
    val requestId: String,
    val protocol: String,
    val origin: String,
    val host: String,
    val signRequest: Boolean,
    val encryptResponse: Boolean,
)

@Serializable
private data class DCBeginRawDcqlRequest(
    val rawDcql: String,
    val origin: String,
    val host: String,
    val signRequest: Boolean,
    val encryptResponse: Boolean,
)

@Serializable
private data class DCBeginResponse(
    val sessionId: String,
    val dcRequestString: String
)

@Serializable
private data class DCGetDataRequest(
    val sessionId: String,
    val credentialResponse: String
)

@Serializable
private data class DCPreviewResponse(
    val token: String
)

@Serializable
private data class DCArfResponse(
    val encryptedResponse: String
)

/**
 * Verifier servlet (may trigger warning as unused in the code).
 *
 * This is using the configuration and storage interfaces from
 * [org.multipaz.server.ServerEnvironment].
 */
class VerifierServlet : BaseHttpServlet() {

    data class KeyMaterial(
        val readerRootKey: EcPrivateKey,
        val readerRootKeyCertificates: X509CertChain,
        val readerRootKeySignatureAlgorithm: Algorithm,
        val readerRootKeyIssuer: String,
    ) {
        fun toCbor() = Cbor.encode(
            buildCborArray {
                add(readerRootKey.toCoseKey().toDataItem())
                add(readerRootKeyCertificates.toDataItem())
                add(readerRootKeySignatureAlgorithm.coseAlgorithmIdentifier!!)
                add(readerRootKeyIssuer)
            }
        )

        companion object {
            fun fromCbor(encodedCbor: ByteArray): KeyMaterial {
                val array = Cbor.decode(encodedCbor).asArray
                return KeyMaterial(
                    array[0].asCoseKey.ecPrivateKey,
                    array[1].asX509CertChain,
                    Algorithm.fromCoseAlgorithmIdentifier(array[2].asNumber.toInt()),
                    array[3].asTstr,
                )
            }

            fun createKeyMaterial(): KeyMaterial {
                val now = Clock.System.now()
                val validFrom = now
                val validUntil = now.plus(DateTimePeriod(years = 10), TimeZone.currentSystemDefault())

                // Create Reader Root w/ self-signed certificate.
                //
                // TODO: Migrate to Curve P-384 once we migrate off com.nimbusds.* which
                // only supports Curve P-256.
                //
                val readerRootKey = Crypto.createEcPrivateKey(EcCurve.P256)
                val readerRootKeySignatureAlgorithm = Algorithm.ES256
                val readerRootKeySubject = "CN=OWF Multipaz Online Verifier Reader Root Key"
                val readerRootKeyCertificate = MdocUtil.generateReaderRootCertificate(
                    readerRootKey = readerRootKey,
                    subject = X500Name.fromName(readerRootKeySubject),
                    serial = ASN1Integer(1L),
                    validFrom = validFrom,
                    validUntil = validUntil,
                    crlUrl = "https://github.com/openwallet-foundation-labs/identity-credential/crl"
                )

                return KeyMaterial(
                    readerRootKey,
                    X509CertChain(listOf(readerRootKeyCertificate)),
                    readerRootKeySignatureAlgorithm,
                    readerRootKeySubject,
                )
            }

        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    companion object {

        val prettyJson = Json {
            prettyPrint = true
            prettyPrintIndent = "  "
        }

        val SESSION_EXPIRATION_INTERVAL = 1.days

        private val verifierSessionTableSpec = StorageTableSpec(
            name = "VerifierSessions",
            supportPartitions = false,
            supportExpiration = true
        )

        private val verifierRootStateTableSpec = StorageTableSpec(
            name = "VerifierRootState",
            supportPartitions = false,
            supportExpiration = false
        )

        private lateinit var keyMaterial: KeyMaterial
        private lateinit var configuration: Configuration
        private lateinit var verifierSessionTable: StorageTable
        private lateinit var verifierRootStateTable: StorageTable

        private fun createKeyMaterial(serverEnvironment: BackendEnvironment): KeyMaterial {
            val keyMaterialBlob = runBlocking {
                verifierRootStateTable = serverEnvironment.getTable(verifierRootStateTableSpec)
                verifierSessionTable = serverEnvironment.getTable(verifierSessionTableSpec)
                verifierRootStateTable.get("verifierKeyMaterial")?.toByteArray()
                    ?: let {
                        val blob = KeyMaterial.createKeyMaterial().toCbor()
                        verifierRootStateTable.insert(
                            key = "verifierKeyMaterial",
                            data = ByteString(blob),
                        )
                        blob
                    }
            }
            return KeyMaterial.fromCbor(keyMaterialBlob)
        }

        private val documentTypeRepo: DocumentTypeRepository by lazy {
            val repo =  DocumentTypeRepository()
            repo.addDocumentType(DrivingLicense.getDocumentType())
            repo.addDocumentType(EUPersonalID.getDocumentType())
            repo.addDocumentType(GermanPersonalID.getDocumentType())
            repo.addDocumentType(PhotoID.getDocumentType())
            repo.addDocumentType(EUCertificateOfResidence.getDocumentType())
            repo.addDocumentType(UtopiaNaturalization.getDocumentType())
            repo.addDocumentType(UtopiaMovieTicket.getDocumentType())
            repo
        }
    }

    override fun initializeEnvironment(env: BackendEnvironment): RpcNotifications? {
        configuration = env.getInterface(Configuration::class)!!
        keyMaterial = createKeyMaterial(env)
        return null
    }

    // Helper to get the local IP address used...
    private fun calcLocalAddress(): InetAddress {
        try {
            var candidateAddress: InetAddress? = null
            for (iface in NetworkInterface.getNetworkInterfaces()) {
                for (inetAddress in iface.inetAddresses) {
                    if (!inetAddress.isLoopbackAddress) {
                        if (inetAddress.isSiteLocalAddress) {
                            return inetAddress
                        } else if (candidateAddress == null) {
                            candidateAddress = inetAddress
                        }
                    }
                }
            }
            if (candidateAddress != null) {
                return candidateAddress
            }
            val jdkSuppliedAddress = InetAddress.getLocalHost()
                ?: throw IllegalStateException("Unexpected null from InetAddress.getLocalHost()")
            return jdkSuppliedAddress
        } catch (e: Throwable) {
            Logger.e(TAG, "Failed to determine address", e)
            throw IllegalStateException("Failed to determine address", e)
        }
    }

    private val baseUrl: String by lazy {
        var ret = configuration.getValue("verifierBaseUrl")
        if (ret == null || ret.length == 0) {
            ret = "http://" + calcLocalAddress().toString() + ":8080" + servletContext.contextPath
            Logger.i(TAG, "Using baseUrl calculated from IP address: $ret")
        } else {
            Logger.i(TAG, "Using baseUrl from configuration: $ret")
        }
        ret
    }

    private val clientId: String by lazy {
        var ret = configuration.getValue("verifierClientId")
        if (ret == null || ret.length == 0) {
            // Remove the http:// or https:// from the baseUrl.
            val startIndex = baseUrl.findAnyOf(listOf("://"))?.first
            ret = if (startIndex == null) baseUrl else baseUrl.removeRange(0, startIndex+3)
        }
        "x509_san_dns:$ret"
    }

    private fun createSingleUseReaderKey(dnsName: String): Pair<EcPrivateKey, X509CertChain> {
        val now = Clock.System.now()
        val validFrom = now.plus(DateTimePeriod(minutes = -10), TimeZone.currentSystemDefault())
        val validUntil = now.plus(DateTimePeriod(minutes = 10), TimeZone.currentSystemDefault())
        val readerKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val readerKeySubject = "CN=OWF Multipaz Online Verifier Single-Use Reader Key"

        // TODO: for now, instead of using the per-site Reader Root generated at first run, use the
        //  well-know OWF IC Reader root checked into Git.
        val owfIcReaderRootKeyPub = EcPublicKey.fromPem(
            """
                    -----BEGIN PUBLIC KEY-----
                    MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+QDye70m2O0llPXMjVjxVZz3m5k6agT+
                    wih+L79b7jyqUl99sbeUnpxaLD+cmB3HK3twkA7fmVJSobBc+9CDhkh3mx6n+YoH
                    5RulaSWThWBfMyRjsfVODkosHLCDnbPV
                    -----END PUBLIC KEY-----
                """.trimIndent().trim(),
            EcCurve.P384
        )
        val owfIcReaderRootKey = EcPrivateKey.fromPem(
            """
                    -----BEGIN PRIVATE KEY-----
                    MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCcRuzXW3pW2h9W8pu5
                    /CSR6JSnfnZVATq+408WPoNC3LzXqJEQSMzPsI9U1q+wZ2yhZANiAAT5APJ7vSbY
                    7SWU9cyNWPFVnPebmTpqBP7CKH4vv1vuPKpSX32xt5SenFosP5yYHccre3CQDt+Z
                    UlKhsFz70IOGSHebHqf5igflG6VpJZOFYF8zJGOx9U4OSiwcsIOds9U=
                    -----END PRIVATE KEY-----
                """.trimIndent().trim(),
            owfIcReaderRootKeyPub
        )
        val certsValidFrom = LocalDate.parse("2024-12-01").atStartOfDayIn(TimeZone.UTC)
        val certsValidUntil = LocalDate.parse("2034-12-01").atStartOfDayIn(TimeZone.UTC)
        val owfIcReaderRootCert = MdocUtil.generateReaderRootCertificate(
            readerRootKey = owfIcReaderRootKey,
            subject = X500Name.fromName("CN=OWF Multipaz TestApp Reader Root"),
            serial = ASN1Integer(1L),
            validFrom = certsValidFrom,
            validUntil = certsValidUntil,
            crlUrl = "https://github.com/openwallet-foundation-labs/identity-credential/crl"
        )

        val readerKeyCertificate = X509Cert.Builder(
            publicKey = readerKey.publicKey,
            signingKey = owfIcReaderRootKey,
            signatureAlgorithm = owfIcReaderRootKey.curve.defaultSigningAlgorithm,
            serialNumber = ASN1Integer(1L),
            subject = X500Name.fromName(readerKeySubject),
            issuer = owfIcReaderRootCert.subject,
            validFrom = validFrom,
            validUntil = validUntil
        )
            .includeSubjectKeyIdentifier()
            .setAuthorityKeyIdentifierToCertificate(owfIcReaderRootCert)
            .setKeyUsage(setOf(X509KeyUsage.DIGITAL_SIGNATURE))
            .addExtension(
                OID.X509_EXTENSION_SUBJECT_ALT_NAME.oid,
                false,
                ASN1.encode(
                    ASN1Sequence(listOf(
                        ASN1TaggedObject(
                            ASN1TagClass.CONTEXT_SPECIFIC,
                            ASN1Encoding.PRIMITIVE,
                            2, // dNSName
                            dnsName.encodeToByteArray()
                        )
                    ))
                )
            )
            .build()

        return Pair(
            readerKey,
            X509CertChain(listOf(readerKeyCertificate) + owfIcReaderRootCert)
        )
    }

    override fun doPost(req: HttpServletRequest, resp: HttpServletResponse) {
        val remoteHost = getRemoteHost(req)
        Logger.i(TAG, "$remoteHost: POST ${req.requestURI}")

        val requestLength = req.contentLength
        val requestData = req.inputStream.readNBytes(requestLength)

        if (req.requestURI.endsWith("verifier/getAvailableRequests")) {
            handleGetAvailableRequests(remoteHost, req, resp, requestData)
        } else if (req.requestURI.endsWith("verifier/openid4vpBegin")) {
            handleOpenID4VPBegin(remoteHost, req, resp, requestData)
        } else if (req.requestURI.endsWith("verifier/openid4vpGetData")) {
            handleOpenID4VPGetData(remoteHost, req, resp, requestData)
        } else if (req.requestURI.endsWith("verifier/openid4vpResponse")) {
            return handleOpenID4VPResponse(remoteHost, req, resp, requestData)
        } else if (req.requestURI.endsWith("verifier/dcBegin")) {
            handleDcBegin(remoteHost, req, resp, requestData)
        } else if (req.requestURI.endsWith("verifier/dcBeginRawDcql")) {
            handleDcBeginRawDcql(remoteHost, req, resp, requestData)
        } else if (req.requestURI.endsWith("verifier/dcGetData")) {
            handleDcGetData(remoteHost, req, resp, requestData)
        } else {
            Logger.w(TAG, "$remoteHost: Unexpected URI ${req.requestURI}")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
        }
    }

    override fun doGet(req: HttpServletRequest, resp: HttpServletResponse) {
        val remoteHost = getRemoteHost(req)

        Logger.i(TAG, "$remoteHost: GET ${req.requestURI}")

        if (req.requestURI.endsWith("verifier/openid4vpRequest")) {
            handleOpenID4VPRequest(remoteHost, req, resp)
        } else if (req.requestURI.endsWith("verifier/readerRootCert")) {
            handleGetReaderRootCert(remoteHost, req, resp)
        } else {
            Logger.w(TAG, "$remoteHost: Unexpected URI ${req.requestURI}")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
        }
    }

    private fun handleGetAvailableRequests(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
        requestData: ByteArray
    ) {
        val requests = mutableListOf<DocumentTypeWithRequests>()
        for (dt in documentTypeRepo.documentTypes) {
            if (!dt.cannedRequests.isEmpty()) {
                val sampleRequests = mutableListOf<SampleRequest>()
                var dtSupportsMdoc = false
                var dtSupportsVc = false
                for (sr in dt.cannedRequests) {
                    sampleRequests.add(SampleRequest(
                        sr.id,
                        sr.displayName,
                        sr.mdocRequest != null,
                        sr.vcRequest != null,
                    ))
                    if (sr.mdocRequest != null) {
                        dtSupportsMdoc = true
                    }
                    if (sr.vcRequest != null) {
                        dtSupportsVc = true
                    }
                }
                requests.add(DocumentTypeWithRequests(
                    dt.displayName,
                    if (dtSupportsMdoc) dt.mdocDocumentType!!.docType else null,
                    if (dtSupportsVc) dt.vcDocumentType!!.type else null,
                    sampleRequests
                ))
            }
        }

        val json = Json { ignoreUnknownKeys = true }
        val responseString = json.encodeToString(AvailableRequests(requests))
        resp.status = HttpServletResponse.SC_OK
        resp.outputStream.write(responseString.encodeToByteArray())
        resp.contentType = "application/json"
    }

    private fun lookupWellknownRequest(
        format: String,
        docType: String,
        requestId: String
    ): DocumentCannedRequest {
        return when (format) {
            "mdoc" -> documentTypeRepo.getDocumentTypeForMdoc(docType)!!.cannedRequests.first { it.id == requestId}
            "vc" -> documentTypeRepo.getDocumentTypeForVc(docType)!!.cannedRequests.first { it.id == requestId}
            else -> throw IllegalArgumentException("Unknown format $format")
        }
    }

    private fun handleDcBegin(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
        requestData: ByteArray
    ) {
        val requestString = String(requestData, 0, requestData.size, Charsets.UTF_8)
        val request = Json.decodeFromString<DCBeginRequest>(requestString)
        Logger.i(TAG, "format ${request.format} protocol ${request.protocol}")

        val protocol = when (request.protocol) {
            // Keep in sync with verifier.html
            "w3c_dc_preview" -> Protocol.W3C_DC_PREVIEW
            "w3c_dc_arf" -> Protocol.W3C_DC_ARF
            "w3c_dc_mdoc_api" -> Protocol.W3C_DC_MDOC_API
            "w3c_dc_openid4vp" -> Protocol.W3C_DC_OPENID4VP
            "openid4vp_plain" -> Protocol.PLAIN_OPENID4VP
            "openid4vp_eudi" -> Protocol.EUDI_OPENID4VP
            "openid4vp_mdoc" -> Protocol.MDOC_OPENID4VP
            "openid4vp_custom" -> Protocol.CUSTOM_OPENID4VP
            else -> {
                Logger.w(TAG, "$remoteHost: Unknown protocol '$request.protocol'")
                resp.status = HttpServletResponse.SC_BAD_REQUEST
                return
            }
        }

        // Create a new session
        val session = Session(
            nonce = ByteString(Random.Default.nextBytes(16)),
            origin = request.origin,
            host = request.host,
            encryptionKey = Crypto.createEcPrivateKey(EcCurve.P256),
            requestFormat = request.format,
            requestDocType = request.docType,
            requestId = request.requestId,
            protocol = protocol,
            signRequest = request.signRequest,
            encryptResponse = request.encryptResponse,
        )
        val sessionId = runBlocking {
            verifierSessionTable.insert(
                key = null,
                data = ByteString(session.toCbor()),
                expiration = Clock.System.now() + SESSION_EXPIRATION_INTERVAL
            )
        }

        val (readerAuthKey, readerAuthKeyCertification) = createSingleUseReaderKey(session.host)

        // Uncomment when making test vectors...
        //Logger.iCbor(TAG, "readerKey: ", Cbor.encode(session.encryptionKey.toCoseKey().toDataItem()))

        val dcRequestString = calcDcRequestString(
            documentTypeRepo,
            request.format,
            session,
            lookupWellknownRequest(session.requestFormat, session.requestDocType, session.requestId),
            session.protocol,
            session.nonce,
            session.origin,
            session.encryptionKey,
            session.encryptionKey.publicKey as EcPublicKeyDoubleCoordinate,
            readerAuthKey,
            readerAuthKeyCertification,
            request.signRequest,
            request.encryptResponse,
        )
        Logger.i(TAG, "dcRequestString: $dcRequestString")
        val json = Json { ignoreUnknownKeys = true }
        val responseString = json.encodeToString(DCBeginResponse(sessionId, dcRequestString))
        resp.status = HttpServletResponse.SC_OK
        resp.outputStream.write(responseString.encodeToByteArray())
        resp.contentType = "application/json"
    }

    private fun handleDcBeginRawDcql(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
        requestData: ByteArray
    ) {
        val requestString = String(requestData, 0, requestData.size, Charsets.UTF_8)
        val request = Json.decodeFromString<DCBeginRawDcqlRequest>(requestString)
        Logger.i(TAG, "rawDcql ${request.rawDcql}")

        val protocol = Protocol.W3C_DC_OPENID4VP

        // Create a new session
        val session = Session(
            nonce = ByteString(Random.Default.nextBytes(16)),
            origin = request.origin,
            host = request.host,
            encryptionKey = Crypto.createEcPrivateKey(EcCurve.P256),
            requestFormat = "",
            requestDocType = "",
            requestId = "",
            protocol = protocol,
            signRequest = request.signRequest,
            encryptResponse = request.encryptResponse,
        )
        val sessionId = runBlocking {
            verifierSessionTable.insert(
                key = null,
                data = ByteString(session.toCbor()),
                expiration = Clock.System.now() + SESSION_EXPIRATION_INTERVAL
            )
        }

        val (readerAuthKey, readerAuthKeyCertification) = createSingleUseReaderKey(session.host)

        val dcRequestString = calcDcRequestStringOpenID4VPforDCQL(
            session = session,
            nonce = session.nonce,
            readerPublicKey = session.encryptionKey.publicKey as EcPublicKeyDoubleCoordinate,
            readerAuthKey = readerAuthKey,
            readerAuthKeyCertification = readerAuthKeyCertification,
            signRequest = request.signRequest,
            encryptResponse = request.encryptResponse,
            dcql = Json.decodeFromString(JsonObject.serializer(), request.rawDcql)
        )
        Logger.i(TAG, "dcRequestString: $dcRequestString")
        val json = Json { ignoreUnknownKeys = true }
        val responseString = json.encodeToString(DCBeginResponse(sessionId, dcRequestString))
        resp.status = HttpServletResponse.SC_OK
        resp.outputStream.write(responseString.encodeToByteArray())
        resp.contentType = "application/json"
    }

    private fun handleDcGetData(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
        requestData: ByteArray
    ) {
        val requestString = String(requestData, 0, requestData.size, Charsets.UTF_8)
        val request = Json.decodeFromString<DCGetDataRequest>(requestString)

        val encodedSession = runBlocking {
            verifierSessionTable.get(request.sessionId)
        }
        if (encodedSession == null) {
            Logger.e(TAG, "$remoteHost: No session for sessionId ${request.sessionId}")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }
        val session = Session.fromCbor(encodedSession.toByteArray())

        Logger.i(TAG, "Data received from WC3 DC API: ${request.credentialResponse}")

        try {
            when (session.protocol) {
                Protocol.W3C_DC_PREVIEW ->handleDcGetDataPreview(session, request.credentialResponse)
                Protocol.W3C_DC_ARF -> handleDcGetDataArf(session, request.credentialResponse)
                Protocol.W3C_DC_MDOC_API -> handleDcGetDataMdocApi(session, request.credentialResponse)
                Protocol.W3C_DC_OPENID4VP -> handleDcGetDataOpenID4VP(session, request.credentialResponse)
                else -> throw IllegalArgumentException("unsupported protocol ${session.protocol}")
            }
        } catch (e: Throwable) {
            Logger.e(TAG, "$remoteHost: failed with", e)
            e.printStackTrace()
            resp.status = HttpServletResponse.SC_BAD_REQUEST
        }

        try {
            if (session.sessionTranscript != null) {
                handleGetDataMdoc(session, resp)
            } else {
                val clientIdToUse = if (session.signRequest) {
                    "x509_san_dns:${session.host}"
                } else {
                    "web-origin:${session.origin}"
                }
                handleGetDataSdJwt(session, resp, clientIdToUse)
            }
        } catch (e: Throwable) {
            Logger.e(TAG, "$remoteHost: Error validating response", e)
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }

        resp.contentType = "application/json"
        resp.status = HttpServletResponse.SC_OK
    }

    private fun handleDcGetDataPreview(
        session: Session,
        credentialResponse: String
    ) {
        val tokenBase64 = Json.decodeFromString<DCPreviewResponse>(credentialResponse).token

        val (cipherText, encapsulatedPublicKey) = parseCredentialDocument(tokenBase64.fromBase64Url())
        val uncompressed = (session.encryptionKey.publicKey as EcPublicKeyDoubleCoordinate).asUncompressedPointEncoding
        session.sessionTranscript = generateBrowserSessionTranscript(
            session.nonce,
            session.origin,
            Crypto.digest(Algorithm.SHA256, uncompressed)
        )
        session.responseWasEncrypted = true
        session.deviceResponse = Crypto.hpkeDecrypt(
            Algorithm.HPKE_BASE_P256_SHA256_AES128GCM,
            session.encryptionKey,
            cipherText,
            session.sessionTranscript!!,
            encapsulatedPublicKey)
    }

    private fun handleDcGetDataArf(
        session: Session,
        credentialResponse: String
    ) {
        val encryptedResponseBase64 = Json.decodeFromString<DCArfResponse>(credentialResponse).encryptedResponse

        val array = Cbor.decode(encryptedResponseBase64.fromBase64Url()).asArray
        if (array.get(0).asTstr != "ARFencryptionv2") {
            throw IllegalArgumentException("Excepted ARFencryptionv2 as first array element")
        }
        val encryptionParameters = array.get(1).asMap
        val encapsulatedPublicKey = encryptionParameters[Tstr("pkEM")]!!.asCoseKey.ecPublicKey
        val cipherText = encryptionParameters[Tstr("cipherText")]!!.asBstr

        val arfEncryptionInfo = buildCborMap {
            put("nonce", session.nonce.toByteArray())
            put("readerPublicKey", session.encryptionKey.publicKey.toCoseKey().toDataItem())
        }
        val encryptionInfo = buildCborArray {
            add("ARFEncryptionv2")
            add(arfEncryptionInfo)
        }
        val base64EncryptionInfo = Cbor.encode(encryptionInfo).toBase64Url()

        session.sessionTranscript =
            Cbor.encode(
                buildCborArray {
                    add(Simple.NULL) // DeviceEngagementBytes
                    add(Simple.NULL) // EReaderKeyBytes
                    addCborArray {
                        add("ARFHandoverv2")
                        add(base64EncryptionInfo)
                        add(session.origin)
                    }
                }
            )

        session.responseWasEncrypted = true
        session.deviceResponse = Crypto.hpkeDecrypt(
            Algorithm.HPKE_BASE_P256_SHA256_AES128GCM,
            session.encryptionKey,
            cipherText,
            session.sessionTranscript!!,
            encapsulatedPublicKey)

        Logger.iCbor(TAG, "decrypted DeviceResponse", session.deviceResponse!!)
        Logger.iCbor(TAG, "SessionTranscript", session.sessionTranscript!!)
    }

    private fun handleDcGetDataMdocApi(
        session: Session,
        credentialResponse: String
    ) {
        val response = Json.parseToJsonElement(credentialResponse).jsonObject
        val encryptedResponseBase64 = response["Response"]!!.jsonPrimitive.content

        val array = Cbor.decode(encryptedResponseBase64.fromBase64Url()).asArray
        if (array.get(0).asTstr != "dcapi") {
            throw IllegalArgumentException("Excepted dcapi as first array element")
        }
        val encryptionParameters = array.get(1).asMap
        val enc = encryptionParameters[Tstr("enc")]!!.asBstr
        val encapsulatedPublicKey = EcPublicKeyDoubleCoordinate.fromUncompressedPointEncoding(
            EcCurve.P256,
            enc
        )
        val cipherText = encryptionParameters[Tstr("cipherText")]!!.asBstr

        val arfEncryptionInfo = buildCborMap {
            put("nonce", session.nonce.toByteArray())
            put("recipientPublicKey", session.encryptionKey.publicKey.toCoseKey().toDataItem())
        }
        val encryptionInfo = buildCborArray {
            add("dcapi")
            add(arfEncryptionInfo)
        }
        val base64EncryptionInfo = Cbor.encode(encryptionInfo).toBase64Url()

        val dcapiInfo = buildCborArray {
            add(base64EncryptionInfo)
            add(session.origin)
        }

        session.sessionTranscript = Cbor.encode(
            buildCborArray {
                add(Simple.NULL) // DeviceEngagementBytes
                add(Simple.NULL) // EReaderKeyBytes
                addCborArray {
                    add("dcapi")
                    add(Crypto.digest(Algorithm.SHA256, Cbor.encode(dcapiInfo)))
                }
            }
        )

        session.responseWasEncrypted = true
        session.deviceResponse = Crypto.hpkeDecrypt(
            Algorithm.HPKE_BASE_P256_SHA256_AES128GCM,
            session.encryptionKey,
            cipherText,
            session.sessionTranscript!!,
            encapsulatedPublicKey)

        Logger.iCbor(TAG, "decrypted DeviceResponse", session.deviceResponse!!)
        Logger.iCbor(TAG, "SessionTranscript", session.sessionTranscript!!)
    }

    private fun handleDcGetDataOpenID4VP(
        session: Session,
        credentialResponse: String
    ) {
        val response = Json.parseToJsonElement(credentialResponse).jsonObject

        val encryptedResponse = response["response"]
        val vpToken = if (encryptedResponse != null) {
            session.responseWasEncrypted = true
            val decryptedResponse = JsonWebEncryption.decrypt(
                encryptedResponse.jsonPrimitive.content,
                session.encryptionKey
            ).jsonObject
            decryptedResponse["vp_token"]!!.jsonObject
        } else {
            response["vp_token"]!!.jsonObject
        }
        Logger.iJson(TAG, "vpToken", vpToken)

        // TODO: handle multiple vpTokens being returned
        val vpTokenForCred = vpToken.values.first().jsonPrimitive.content

        // This is a total hack but in case of Raw DCQL we actually don't really
        // know what was requested. This heuristic to determine if the token is
        // for an ISO mdoc or IETF SD-JWT VC works for now...
        //
        val isMdoc = try {
            val decodedCbor = Cbor.decode(vpTokenForCred.fromBase64Url())
            true
        } catch (e: Throwable) {
            false
        }
        Logger.i(TAG, "isMdoc: $isMdoc")

        if (isMdoc) {
            val effectiveClientId = if (session.signRequest) {
                "x509_san_dns:${session.host}"
            } else {
                "web-origin:${session.origin}"
            }
            val handoverInfo = Cbor.encode(
                buildCborArray {
                    add(session.origin)
                    add(effectiveClientId)
                    add(session.nonce.toByteArray().toBase64Url())
                }
            )
            session.sessionTranscript = Cbor.encode(
                buildCborArray {
                    add(Simple.NULL) // DeviceEngagementBytes
                    add(Simple.NULL) // EReaderKeyBytes
                    addCborArray {
                        add("OpenID4VPDCAPIHandover")
                        add(Crypto.digest(Algorithm.SHA256, handoverInfo))
                    }
                }
            )
            Logger.iCbor(TAG, "handoverInfo", handoverInfo)
            Logger.iCbor(TAG, "sessionTranscript", session.sessionTranscript!!)
            session.deviceResponse = vpTokenForCred.fromBase64Url()
        } else {
            session.verifiablePresentation = vpTokenForCred
        }
    }

    private fun handleOpenID4VPBegin(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
        requestData: ByteArray
    ) {
        val requestString = String(requestData, 0, requestData.size, Charsets.UTF_8)
        val request = Json.decodeFromString<OpenID4VPBeginRequest>(requestString)

        val protocol = when (request.protocol) {
            // Keep in sync with verifier.html
            "w3c_dc_preview" -> Protocol.W3C_DC_PREVIEW
            "w3c_dc_arf" -> Protocol.W3C_DC_ARF
            "w3c_dc_mdoc_api" -> Protocol.W3C_DC_MDOC_API
            "w3c_dc_openid4vp" -> Protocol.W3C_DC_OPENID4VP
            "openid4vp_plain" -> Protocol.PLAIN_OPENID4VP
            "openid4vp_eudi" -> Protocol.EUDI_OPENID4VP
            "openid4vp_mdoc" -> Protocol.MDOC_OPENID4VP
            "openid4vp_custom" -> Protocol.CUSTOM_OPENID4VP
            else -> {
                Logger.w(TAG, "$remoteHost: Unknown protocol '$request.protocol'")
                resp.status = HttpServletResponse.SC_BAD_REQUEST
                return
            }
        }

        // Create a new session
        val session = Session(
            nonce = ByteString(Random.Default.nextBytes(16)),
            origin = request.origin,
            host = request.host,
            encryptionKey = Crypto.createEcPrivateKey(EcCurve.P256),
            requestFormat = request.format,
            requestDocType = request.docType,
            requestId = request.requestId,
            protocol = protocol
        )
        val sessionId = runBlocking {
            verifierSessionTable.insert(
                key = null,
                data = ByteString(session.toCbor()),
                expiration = Clock.System.now() + SESSION_EXPIRATION_INTERVAL
            )
        }

        val uriScheme = when (session.protocol) {
            Protocol.PLAIN_OPENID4VP -> "openid4vp://"
            Protocol.EUDI_OPENID4VP -> "eudi-openid4vp://"
            Protocol.MDOC_OPENID4VP -> "mdoc-openid4vp://"
            Protocol.CUSTOM_OPENID4VP -> request.scheme
            else -> {
                Logger.w(TAG, "$remoteHost: Unknown protocol '${session.protocol}'")
                resp.status = HttpServletResponse.SC_BAD_REQUEST
                return
            }
        }
        val requestUri = baseUrl + "/verifier/openid4vpRequest?sessionId=${sessionId}"
        val uri = uriScheme +
                "?client_id=" + URLEncoder.encode(clientId, Charsets.UTF_8) +
                "&request_uri=" + URLEncoder.encode(requestUri, Charsets.UTF_8)

        val json = Json { ignoreUnknownKeys = true }
        val responseString = json.encodeToString(OpenID4VPBeginResponse(uri))
        resp.status = HttpServletResponse.SC_OK
        resp.outputStream.write(responseString.encodeToByteArray())
        resp.contentType = "application/json"
        Logger.i(TAG, "Sending handleOpenID4VPBegin response: $responseString")
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun handleOpenID4VPRequest(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
    ) {
        val sessionId = req.getParameter("sessionId")
        if (sessionId == null) {
            Logger.e(TAG, "$remoteHost: No session parameter ${req.requestURI}")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }
        val encodedSession = runBlocking {
            verifierSessionTable.get(sessionId)
        }
        if (encodedSession == null) {
            Logger.e(TAG, "$remoteHost: No session for sessionId $sessionId")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }
        val session = Session.fromCbor(encodedSession.toByteArray())

        val responseUri = baseUrl + "/verifier/openid4vpResponse?sessionId=${sessionId}"

        val (singleUseReaderKeyPriv, singleUseReaderKeyCertChain) = createSingleUseReaderKey(session.host)

        val readerPublic = singleUseReaderKeyPriv.publicKey.javaPublicKey as ECPublicKey
        val readerPrivate = singleUseReaderKeyPriv.javaPrivateKey as ECPrivateKey

        // TODO: b/393388152: ECKey is deprecated, but might be current library dependency.
        @Suppress("DEPRECATION")
        val readerKey = ECKey(
            Curve.P_256,
            readerPublic,
            readerPrivate,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null
        )

        val readerX5c = singleUseReaderKeyCertChain.certificates.map { cert ->
            Base64.from(kotlin.io.encoding.Base64.Default.encode(cert.encodedCertificate))
        }

        val request = lookupWellknownRequest(session.requestFormat, session.requestDocType, session.requestId)
        val presentationDefinition = when (session.requestFormat) {
            "mdoc" -> mdocCalcPresentationDefinition(documentTypeRepo, request)
            "vc" -> sdjwtCalcPresentationDefinition(documentTypeRepo, request)
            else -> throw IllegalArgumentException("Unknown format ${session.requestFormat}")
        }

        val claimsSet = JWTClaimsSet.Builder()
            .claim("client_id", clientId)
            .claim("client_id_scheme", "x509_san_dns")
            .claim("response_uri", responseUri)
            .claim("response_type", "vp_token")
            .claim("response_mode", "direct_post.jwt")
            .claim("nonce", session.nonce.toByteArray().toBase64Url())
            .claim("state", sessionId)
            .claim("presentation_definition", presentationDefinition)
            .claim("client_metadata", calcClientMetadata(session, session.requestFormat))
            .build()
        Logger.i(TAG, "Sending OpenID4VPRequest claims set: $claimsSet")

        val signedJWT = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(readerKey.getKeyID())
                .x509CertChain(readerX5c)
                .type(JOSEObjectType("oauth-authz-req+jwt"))
                .build(),
            claimsSet
        )

        val signer: JWSSigner = ECDSASigner(readerKey)
        signedJWT.sign(signer)

        val s = signedJWT.serialize()
        Logger.i(TAG, "Signed JWT: $s")
        resp.contentType = "application/oauth-authz-req+jwt"
        resp.outputStream.write(s.encodeToByteArray())
        resp.status = HttpServletResponse.SC_OK

        // We'll need responseUri later (to calculate sessionTranscript)
        session.responseUri = responseUri
        runBlocking {
            verifierSessionTable.update(
                key = sessionId,
                data = ByteString(session.toCbor()),
                expiration = Clock.System.now() + SESSION_EXPIRATION_INTERVAL
            )
        }

    }

    private fun handleGetReaderRootCert(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
    ) {
        val readerCertPem = keyMaterial.readerRootKeyCertificates.certificates[0].toPem()
        resp.outputStream.write(readerCertPem.encodeToByteArray())
        resp.contentType = "text/plain"
        resp.status = HttpServletResponse.SC_OK
    }

    private fun handleOpenID4VPResponse(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
        requestData: ByteArray
    ) {
        val sessionId = req.getParameter("sessionId")
        if (sessionId == null) {
            Logger.e(TAG, "$remoteHost: No session parameter ${req.requestURI}")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }
        val encodedSession = runBlocking {
            verifierSessionTable.get(sessionId)
        }
        if (encodedSession == null) {
            Logger.e(TAG, "$remoteHost: No session for sessionId $sessionId")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }
        val session = Session.fromCbor(encodedSession.toByteArray())

        val responseString = String(requestData, 0, requestData.size, Charsets.UTF_8)
        try {
            val kvPairs = mutableMapOf<String, String>()
            for (part in responseString.split("&")) {
                val parts = part.split("=", limit = 2)
                kvPairs[parts[0]] = parts[1]
            }

            val response = kvPairs["response"]
            val encryptedJWT = EncryptedJWT.parse(response)

            val encPublic = session.encryptionKey.publicKey.javaPublicKey as ECPublicKey
            val encPrivate = session.encryptionKey.javaPrivateKey as ECPrivateKey

            // TODO: b/393388152: ECKey is deprecated, but might be current library dependency.
            @Suppress("DEPRECATION")
            val encKey = ECKey(
                Curve.P_256,
                encPublic,
                encPrivate,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
            )

            val decrypter = ECDHDecrypter(encKey)
            encryptedJWT.decrypt(decrypter)

            val vpToken = encryptedJWT.jwtClaimsSet.getClaim("vp_token") as String
            session.responseWasEncrypted = true
            if (session.requestFormat == "mdoc") {
                session.deviceResponse = vpToken.fromBase64Url()
            } else {
                session.verifiablePresentation = vpToken
            }

            // According to ISO 23220-4, the mdoc profile is required to have the apv and apu params
            // set in the JWE header. However, there is no such requirement for the sd-jwt profile.
            val apv = encryptedJWT.header.agreementPartyVInfo
            val apu = encryptedJWT.header.agreementPartyUInfo
            if (session.requestFormat == "mdoc") {
                if ((apu == null) or (apv == null)) {
                    // Log a warning here instead of throwing an error since apu + apv are not req
                    // for functionality.
                    Logger.w(TAG, "Mdoc wallet did not provide both apu and apv JWE headers as expected.")
                }
            }
            session.sessionTranscript = createSessionTranscriptOpenID4VP(
                clientId = clientId,
                responseUri = session.responseUri!!,
                authorizationRequestNonce = apv?.toString(),
                mdocGeneratedNonce = apu?.toString()
            )

            // Save `deviceResponse` and `sessionTranscript`, for later
            runBlocking {
                verifierSessionTable.update(
                    key = sessionId,
                    data = ByteString(session.toCbor()),
                    expiration = Clock.System.now() + SESSION_EXPIRATION_INTERVAL
                )
            }

        } catch (e: Throwable) {
            Logger.w(TAG, "$remoteHost: handleResponse: Error getting response", e)
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }

        val redirectUri = baseUrl + "/verifier_redirect.html?sessionId=${sessionId}"
        val json = Json { ignoreUnknownKeys = true }
        resp.outputStream.write(
            json.encodeToString(OpenID4VPRedirectUriResponse(redirectUri))
                .encodeToByteArray()
        )
        resp.contentType = "application/json"
        resp.status = HttpServletResponse.SC_OK
    }

    private fun handleOpenID4VPGetData(
        remoteHost: String,
        req: HttpServletRequest,
        resp: HttpServletResponse,
        requestData: ByteArray
    ) {
        val requestString = String(requestData, 0, requestData.size, Charsets.UTF_8)
        val request = Json.decodeFromString<OpenID4VPGetData>(requestString)

        val encodedSession = runBlocking {
            verifierSessionTable.get(request.sessionId)
        }
        if (encodedSession == null) {
            Logger.e(TAG, "$remoteHost: No session for sessionId ${request.sessionId}")
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }
        val session = Session.fromCbor(encodedSession.toByteArray())

        try {
            when (session.requestFormat) {
                "mdoc" -> handleGetDataMdoc(session, resp)
                "vc" -> handleGetDataSdJwt(session, resp, clientId)
            }
        } catch (e: Throwable) {
            Logger.e(TAG, "$remoteHost: Error validating DeviceResponse", e)
            resp.status = HttpServletResponse.SC_BAD_REQUEST
            return
        }

        resp.contentType = "application/json"
        resp.status = HttpServletResponse.SC_OK
    }

    private fun handleGetDataMdoc(
        session: Session,
        resp: HttpServletResponse
    ) {
        val parser = DeviceResponseParser(session.deviceResponse!!, session.sessionTranscript!!)
        val deviceResponse = parser.parse()
        Logger.i(TAG, "Validated DeviceResponse!")

        // TODO: Add more sophistication in how we convey the result to the webpage, for example
        //  support the following value types
        //  - textual string
        //  - images
        //  - etc/
        //
        // TODO: Also check whether IssuerSigned and DeviceSigned validates and whether we trust
        //  the IACA certificate. Also include a check/fail for every data element to convey if
        //  the IssuerSignedItem digest matches the expected value.
        //
        val lines = mutableListOf<OpenID4VPResultLine>()
        for (document in deviceResponse.documents) {
            lines.add(OpenID4VPResultLine("DocType", document.docType))
            for (namespaceName in document.issuerNamespaces) {
                lines.add(OpenID4VPResultLine("NameSpace", namespaceName))
                for (dataElementName in document.getIssuerEntryNames(namespaceName)) {
                    val value = document.getIssuerEntryData(namespaceName, dataElementName)
                    val dataItem = Cbor.decode(value)
                    val renderedValue = Cbor.toDiagnostics(
                        dataItem,
                        setOf(
                            DiagnosticOption.PRETTY_PRINT,
                            DiagnosticOption.BSTR_PRINT_LENGTH
                        )
                    )
                    lines.add(OpenID4VPResultLine(dataElementName, renderedValue))
                }
            }
            lines.add(OpenID4VPResultLine("Response end-to-end encrypted", "${session.responseWasEncrypted}"))
            lines.add(OpenID4VPResultLine("DeviceSigned Authenticated", "${document.deviceSignedAuthenticated}"))
            lines.add(OpenID4VPResultLine("IssuerSigned Authenticated", "${document.issuerSignedAuthenticated}"))
            lines.add(OpenID4VPResultLine("Number of Digest Failures", "${document.numIssuerEntryDigestMatchFailures}"))
        }

        val json = Json { ignoreUnknownKeys = true }
        resp.outputStream.write(json.encodeToString(OpenID4VPResultData(lines)).encodeToByteArray())
    }

    private fun handleGetDataSdJwt(
        session: Session,
        resp: HttpServletResponse,
        clientIdToUse: String,
    ) {
        val lines = mutableListOf<OpenID4VPResultLine>()

        val presentationString = session.verifiablePresentation!!
        Logger.d(TAG, "Handling SD-JWT: $presentationString")
        val (sdJwt, sdJwtKb) = if (presentationString.endsWith("~")) {
            Pair(SdJwt(presentationString), null)
        } else {
            val sdJwtKb = SdJwtKb(presentationString)
            Pair(sdJwtKb.sdJwt, sdJwtKb)
        }
        val issuerCert = sdJwt.x5c?.certificates?.first()
        if (issuerCert == null) {
            lines.add(OpenID4VPResultLine("Error", "Issuer-signed key not in `x5c` in header"))
            return
        }
        if (sdJwtKb == null && sdJwt.jwtBody["cnf"] != null) {
            lines.add(OpenID4VPResultLine("Error", "`cnf` claim present but we got a SD-JWT, not a SD-JWT+KB"))
            return
        }

        val processedJwt = if (sdJwtKb != null) {
            // TODO: actually check nonce, audience, and creationTime
            try {
                val payload = sdJwtKb.verify(
                    issuerKey = issuerCert.ecPublicKey,
                    checkNonce = { nonce -> true },
                    checkAudience = { audience -> true },
                    checkCreationTime = { creationTime -> true },
                )
                lines.add(OpenID4VPResultLine("Key-Binding", "Verified"))
                payload
            } catch (e: Throwable) {
                lines.add(OpenID4VPResultLine("Key-Binding", "Error validating: $e"))
                return
            }
        } else {
            try {
                sdJwt.verify(issuerCert.ecPublicKey)
            } catch (e: Throwable) {
                lines.add(OpenID4VPResultLine("Error", "Error validating signature: $e"))
                return
            }
        }

        for ((claimName, claimValue) in processedJwt) {
            val claimValueStr = prettyJson.encodeToString(claimValue)
            lines.add(OpenID4VPResultLine(claimName, claimValueStr))
        }

        val json = Json { ignoreUnknownKeys = true }
        resp.outputStream.write(json.encodeToString(OpenID4VPResultData(lines)).encodeToByteArray())
    }
}

// defined in ISO 18013-7 Annex B
private fun createSessionTranscriptOpenID4VP(
    clientId: String,
    responseUri: String,
    authorizationRequestNonce: String?,
    mdocGeneratedNonce: String?
): ByteArray {
    val clientIdHash = Crypto.digest(
        Algorithm.SHA256,
        Cbor.encode(
            buildCborArray {
                add(clientId)
                mdocGeneratedNonce?.let { add(it) }
            }
        )
    )

    val responseUriHash = Crypto.digest(
        Algorithm.SHA256,
        Cbor.encode(
            buildCborArray {
                add(responseUri)
                mdocGeneratedNonce?.let { add(it) }
            }
        )
    )

    return Cbor.encode(
        buildCborArray {
            add(Simple.NULL)
            add(Simple.NULL)
            addCborArray {
                add(clientIdHash)
                add(responseUriHash)
                authorizationRequestNonce?.let { add(it) }
            }
        }
    )
}

private fun calcDcRequestString(
    documentTypeRepository: DocumentTypeRepository,
    format: String,
    session: Session,
    request: DocumentCannedRequest,
    protocol: Protocol,
    nonce: ByteString,
    origin: String,
    readerKey: EcPrivateKey,
    readerPublicKey: EcPublicKeyDoubleCoordinate,
    readerAuthKey: EcPrivateKey,
    readerAuthKeyCertification: X509CertChain,
    signRequest: Boolean,
    encryptResponse: Boolean,
): String {
    when (protocol) {
        Protocol.W3C_DC_PREVIEW -> {
            return mdocCalcDcRequestStringPreview(
                documentTypeRepository,
                request,
                nonce,
                origin,
                readerPublicKey
            )
        }
        Protocol.W3C_DC_ARF -> {
            return mdocCalcDcRequestStringArf(
                documentTypeRepository,
                request,
                nonce,
                origin,
                readerKey,
                readerPublicKey,
                readerAuthKey,
                readerAuthKeyCertification
            )
        }
        Protocol.W3C_DC_MDOC_API -> {
            return mdocCalcDcRequestStringMdocApi(
                documentTypeRepository,
                request,
                nonce,
                origin,
                readerKey,
                readerPublicKey,
                readerAuthKey,
                readerAuthKeyCertification
            )
        }
        Protocol.W3C_DC_OPENID4VP -> {
            return calcDcRequestStringOpenID4VP(
                documentTypeRepository,
                format,
                session,
                request,
                nonce,
                origin,
                readerKey,
                readerPublicKey,
                readerAuthKey,
                readerAuthKeyCertification,
                signRequest,
                encryptResponse,
            )
        }
        else -> {
            throw IllegalStateException("Unsupported protocol $protocol")
        }
    }
}

private fun mdocCalcDcRequestStringPreview(
    documentTypeRepository: DocumentTypeRepository,
    request: DocumentCannedRequest,
    nonce: ByteString,
    origin: String,
    readerPublicKey: EcPublicKeyDoubleCoordinate
    ): String {
    val top = JSONObject()

    val selector = JSONObject()
    val format = JSONArray()
    format.add("mdoc")
    selector.put("format", format)
    top.put("selector", selector)

    selector.put("doctype", request.mdocRequest!!.docType)

    val fields = JSONArray()
    for (ns in request.mdocRequest!!.namespacesToRequest) {
        for ((de, intentToRetain) in ns.dataElementsToRequest) {
            val field = JSONObject()
            field.put("namespace", ns.namespace)
            field.put("name", de.attribute.identifier)
            field.put("intentToRetain", intentToRetain)
            fields.add(field)
        }
    }
    selector.put("fields", fields)

    top.put("nonce", nonce.toByteArray().toBase64Url())
    top.put("readerPublicKey", readerPublicKey.asUncompressedPointEncoding.toBase64Url())

    return top.toString(JSONStyle.NO_COMPRESS)
}

private fun calcDcRequestStringOpenID4VPforDCQL(
    session: Session,
    nonce: ByteString,
    readerPublicKey: EcPublicKeyDoubleCoordinate,
    readerAuthKey: EcPrivateKey,
    readerAuthKeyCertification: X509CertChain,
    signRequest: Boolean,
    encryptResponse: Boolean,
    dcql: JsonObject,
): String {
    val responseMode = if (encryptResponse) {
        Logger.i(TAG, "readerPublicKey is ${readerPublicKey}")
        "dc_api.jwt"
    } else {
        "dc_api"
    }

    val clientMetadata = buildJsonObject {
        put("vp_formats", buildJsonObject {
            putJsonObject("mso_mdoc") {
                putJsonArray("alg") {
                    add(JsonPrimitive("ES256"))
                }
            }
            putJsonObject("dc+sd-jwt") {
                putJsonArray("sd-jwt_alg_values") {
                    add(JsonPrimitive("ES256"))
                }
                putJsonArray("kb-jwt_alg_values") {
                    add(JsonPrimitive("ES256"))
                }
            }
        })
        // TODO:  "require_signed_request_object": true
        if (encryptResponse) {
            put("authorization_encrypted_response_alg", JsonPrimitive("ECDH-ES"))
            put("authorization_encrypted_response_enc", JsonPrimitive("A128GCM"))
        }
        putJsonObject("jwks") {
            putJsonArray("keys") {
                if (encryptResponse) {
                    addJsonObject {
                        put("kty", JsonPrimitive("EC"))
                        put("use", JsonPrimitive("enc"))
                        put("crv", JsonPrimitive("P-256"))
                        put("alg", JsonPrimitive("ECDH-ES"))
                        put("kid", JsonPrimitive("reader-auth-key"))
                        put("x", JsonPrimitive(readerPublicKey.x.toBase64Url()))
                        put("y", JsonPrimitive(readerPublicKey.y.toBase64Url()))
                    }
                }
            }
        }
    }

    val unsignedRequest = buildJsonObject {
        put("response_type", JsonPrimitive("vp_token"))
        put("response_mode", JsonPrimitive(responseMode))
        put("client_metadata", clientMetadata)
        // Only include client_id for signed requests
        if (signRequest) {
            put("client_id", JsonPrimitive("x509_san_dns:${session.host}"))
            putJsonArray("expected_origins") {
                add(JsonPrimitive(session.origin))
            }
        }
        put("nonce", JsonPrimitive(nonce.toByteArray().toBase64Url()))
        put("dcql_query", dcql)
    }

    if (!signRequest) {
        return unsignedRequest.toString()
    }
    val signedRequestElement = JsonWebSignature.sign(
        key = readerAuthKey,
        signatureAlgorithm = readerAuthKey.curve.defaultSigningAlgorithmFullySpecified,
        claimsSet = unsignedRequest,
        type = "oauth-authz-req+jwt",
        x5c = readerAuthKeyCertification
    )
    val signedRequest = buildJsonObject {
        put("request", JsonPrimitive(signedRequestElement))
    }
    return signedRequest.toString()
}

private fun calcDcRequestStringOpenID4VP(
    documentTypeRepository: DocumentTypeRepository,
    format: String,
    session: Session,
    request: DocumentCannedRequest,
    nonce: ByteString,
    origin: String,
    readerKey: EcPrivateKey,
    readerPublicKey: EcPublicKeyDoubleCoordinate,
    readerAuthKey: EcPrivateKey,
    readerAuthKeyCertification: X509CertChain,
    signRequest: Boolean,
    encryptResponse: Boolean
): String {
    val dcql = buildJsonObject {
        putJsonArray("credentials") {
            if (format == "vc") {
                addJsonObject {
                    put("id", JsonPrimitive("cred1"))
                    put("format", JsonPrimitive("dc+sd-jwt"))
                    putJsonObject("meta") {
                        put(
                            "vct_values",
                            buildJsonArray {
                                add(JsonPrimitive(request.vcRequest!!.vct))
                            }
                        )
                    }
                    putJsonArray("claims") {
                        for (claim in request.vcRequest!!.claimsToRequest) {
                            addJsonObject {
                                putJsonArray("path") {
                                    for (pathElement in claim.identifier.split(".")) {
                                        add(JsonPrimitive(pathElement))
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                addJsonObject {
                    put("id", JsonPrimitive("cred1"))
                    put("format", JsonPrimitive("mso_mdoc"))
                    putJsonObject("meta") {
                        put("doctype_value", JsonPrimitive(request.mdocRequest!!.docType))
                    }
                    putJsonArray("claims") {
                        for (ns in request.mdocRequest!!.namespacesToRequest) {
                            for ((de, intentToRetain) in ns.dataElementsToRequest) {
                                addJsonObject {
                                    putJsonArray("path") {
                                        add(JsonPrimitive(ns.namespace))
                                        add(JsonPrimitive(de.attribute.identifier))
                                    }
                                    put("intent_to_retain", JsonPrimitive(intentToRetain))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return calcDcRequestStringOpenID4VPforDCQL(
        session = session,
        nonce = nonce,
        readerPublicKey = readerPublicKey,
        readerAuthKey = readerAuthKey,
        readerAuthKeyCertification = readerAuthKeyCertification,
        signRequest = signRequest,
        encryptResponse = encryptResponse,
        dcql = dcql
    )
}

private fun mdocCalcDcRequestStringArf(
    documentTypeRepository: DocumentTypeRepository,
    request: DocumentCannedRequest,
    nonce: ByteString,
    origin: String,
    readerKey: EcPrivateKey,
    readerPublicKey: EcPublicKeyDoubleCoordinate,
    readerAuthKey: EcPrivateKey,
    readerAuthKeyCertification: X509CertChain
): String {
    val encryptionInfo = buildCborArray {
        add("ARFEncryptionv2")
        addCborMap {
            put("nonce", nonce.toByteArray())
            put("readerPublicKey", readerPublicKey.toCoseKey().toDataItem())
        }
    }
    val base64EncryptionInfo = Cbor.encode(encryptionInfo).toBase64Url()

    val sessionTranscript = Cbor.encode(
        buildCborArray {
            add(Simple.NULL) // DeviceEngagementBytes
            add(Simple.NULL) // EReaderKeyBytes
            addCborArray {
                add("ARFHandoverv2")
                add(base64EncryptionInfo)
                add(origin)
            }
        }
    )

    val itemsToRequest = mutableMapOf<String, MutableMap<String, Boolean>>()
    for (ns in request.mdocRequest!!.namespacesToRequest) {
        for ((de, intentToRetain) in ns.dataElementsToRequest) {
            itemsToRequest.getOrPut(ns.namespace) { mutableMapOf() }
                .put(de.attribute.identifier, intentToRetain)
        }
    }
    val generator = DeviceRequestGenerator(sessionTranscript)
    generator.addDocumentRequest(
        docType = request.mdocRequest!!.docType,
        itemsToRequest = itemsToRequest,
        requestInfo = null,
        readerKey = readerAuthKey,
        signatureAlgorithm = Algorithm.ES256,
        readerKeyCertificateChain = readerAuthKeyCertification,
    )
    val deviceRequest = generator.generate()
    val base64DeviceRequest = deviceRequest.toBase64Url()

    val top = JSONObject()
    top.put("deviceRequest", base64DeviceRequest)
    top.put("encryptionInfo", base64EncryptionInfo)
    return top.toString(JSONStyle.NO_COMPRESS)
}

private fun mdocCalcDcRequestStringMdocApi(
    documentTypeRepository: DocumentTypeRepository,
    request: DocumentCannedRequest,
    nonce: ByteString,
    origin: String,
    readerKey: EcPrivateKey,
    readerPublicKey: EcPublicKeyDoubleCoordinate,
    readerAuthKey: EcPrivateKey,
    readerAuthKeyCertification: X509CertChain
): String {
    val encryptionInfo = buildCborArray {
        add("dcapi")
        addCborMap {
            put("nonce", nonce.toByteArray())
            put("recipientPublicKey", readerPublicKey.toCoseKey().toDataItem())
        }
    }
    val base64EncryptionInfo = Cbor.encode(encryptionInfo).toBase64Url()
    val dcapiInfo = buildCborArray {
        add(base64EncryptionInfo)
        add(origin)
    }

    val sessionTranscript = Cbor.encode(
        buildCborArray {
            add(Simple.NULL) // DeviceEngagementBytes
            add(Simple.NULL) // EReaderKeyBytes
            addCborArray {
                add("dcapi")
                add(Crypto.digest(Algorithm.SHA256, Cbor.encode(dcapiInfo)))
            }
        }
    )

    val itemsToRequest = mutableMapOf<String, MutableMap<String, Boolean>>()
    for (ns in request.mdocRequest!!.namespacesToRequest) {
        for ((de, intentToRetain) in ns.dataElementsToRequest) {
            itemsToRequest.getOrPut(ns.namespace) { mutableMapOf() }
                .put(de.attribute.identifier, intentToRetain)
        }
    }
    val generator = DeviceRequestGenerator(sessionTranscript)
    generator.addDocumentRequest(
        docType = request.mdocRequest!!.docType,
        itemsToRequest = itemsToRequest,
        requestInfo = null,
        readerKey = readerAuthKey,
        signatureAlgorithm = Algorithm.ES256,
        readerKeyCertificateChain = readerAuthKeyCertification,
    )
    val deviceRequest = generator.generate()
    val base64DeviceRequest = deviceRequest.toBase64Url()

    val top = JSONObject()
    top.put("deviceRequest", base64DeviceRequest)
    top.put("encryptionInfo", base64EncryptionInfo)
    return top.toString(JSONStyle.NO_COMPRESS)
}

private fun mdocCalcPresentationDefinition(
    documentTypeRepository: DocumentTypeRepository,
    request: DocumentCannedRequest
): JSONObject {
    val alg = JSONArray()
    alg.addAll(listOf("ES256"))
    val mso_mdoc = JSONObject()
    mso_mdoc.put("alg", alg)
    val format = JSONObject()
    format.put("mso_mdoc", mso_mdoc)

    val fields = JSONArray()
    for (ns in request.mdocRequest!!.namespacesToRequest) {
        for ((de, intentToRetain) in ns.dataElementsToRequest) {
            var array = JSONArray()
            array.add("\$['${ns.namespace}']['${de.attribute.identifier}']")
            val field = JSONObject()
            field.put("path", array)
            field.put("intent_to_retain", intentToRetain)
            fields.add(field)
        }
    }
    val constraints = JSONObject()
    constraints.put("limit_disclosure", "required")
    constraints.put("fields", fields)

    val input_descriptor_0 = JSONObject()
    input_descriptor_0.put("id", request.mdocRequest!!.docType)
    input_descriptor_0.put("format", format)
    input_descriptor_0.put("constraints", constraints)
    val input_descriptors = JSONArray()
    input_descriptors.add(input_descriptor_0)

    val presentation_definition = JSONObject()
    // TODO: Fill in a unique ID.
    presentation_definition.put("id", "request-TODO-id")
    presentation_definition.put("input_descriptors", input_descriptors)

    return presentation_definition
}

private fun sdjwtCalcPresentationDefinition(
    documentTypeRepository: DocumentTypeRepository,
    request: DocumentCannedRequest
): JSONObject {
    val alg = JSONArray()
    alg.addAll(listOf("ES256"))
    val algContainer = JSONObject()
    algContainer.put("alg", alg)
    val format = JSONObject()
    format.put("jwt_vc", algContainer)

    val fields = JSONArray()
    val vctArray = JSONArray()
    vctArray.add("\$.vct")
    val vctFilter = JSONObject()
    vctFilter.put("const", request.vcRequest!!.vct)
    val vctField = JSONObject()
    vctField.put("path", vctArray)
    vctField.put("filter", vctFilter)
    fields.add(vctField)
    for (claim in request.vcRequest!!.claimsToRequest) {
        var array = JSONArray()
        array.add("\$.${claim.identifier}")
        val field = JSONObject()
        field.put("path", array)
        fields.add(field)
    }
    val constraints = JSONObject()
    constraints.put("limit_disclosure", "required")
    constraints.put("fields", fields)

    val input_descriptor_0 = JSONObject()
    input_descriptor_0.put("id", "Example PID")
    input_descriptor_0.put("format", format)
    input_descriptor_0.put("constraints", constraints)
    val input_descriptors = JSONArray()
    input_descriptors.add(input_descriptor_0)

    val presentation_definition = JSONObject()
    // TODO: Fill in a unique ID.
    presentation_definition.put("id", "request-TODO-id")
    presentation_definition.put("input_descriptors", input_descriptors)

    return presentation_definition
}

private fun calcClientMetadata(session: Session, format: String): JSONObject {
    val encPub = session.encryptionKey.publicKey as EcPublicKeyDoubleCoordinate

    val client_metadata = JSONObject()
    client_metadata.put("authorization_encrypted_response_alg", "ECDH-ES")
    client_metadata.put("authorization_encrypted_response_enc", "A128CBC-HS256")
    client_metadata.put("response_mode", "direct_post.jwt")

    val vpFormats = when (format) {
        "vc" -> {
            val vpFormats = JSONObject()
            val algList = JSONArray()
            algList.addAll(listOf("ES256"))
            val algObj = JSONObject()
            algObj.put("alg", algList)
            vpFormats.put("jwt_vc", algObj)
            vpFormats
        }
        "mdoc" -> {
            val vpFormats = JSONObject()
            val algList = JSONArray()
            algList.addAll(listOf("ES256"))
            val algObj = JSONObject()
            algObj.put("alg", algList)
            vpFormats.put("mso_mdoc", algObj)
            vpFormats
        }

        else -> throw IllegalArgumentException("Unknown format $format")
    }
    client_metadata.put("vp_formats", vpFormats)
    client_metadata.put("vp_formats_supported", vpFormats)

    val key = JSONObject()
    key.put("kty", "EC")
    key.put("use", "enc")
    key.put("crv", "P-256")
    key.put("alg", "ECDH-ES")
    key.put("x", encPub.x.toBase64Url())
    key.put("y", encPub.y.toBase64Url())

    val keys = JSONArray()
    keys.add(key)

    val keys_map = JSONObject()
    keys_map.put("keys", keys)

    client_metadata.put("jwks", keys_map)

    return client_metadata
}

private const val BROWSER_HANDOVER_V1 = "BrowserHandoverv1"
private const val ANDROID_CREDENTIAL_DOCUMENT_VERSION = "ANDROID-HPKE-v1"

private fun parseCredentialDocument(encodedCredentialDocument: ByteArray
): Pair<ByteArray, EcPublicKey> {
    val map = Cbor.decode(encodedCredentialDocument)
    val version = map["version"].asTstr
    if (!version.equals(ANDROID_CREDENTIAL_DOCUMENT_VERSION)) {
        throw IllegalArgumentException("Unexpected version $version")
    }
    val encryptionParameters = map["encryptionParameters"]
    val pkEm = encryptionParameters["pkEm"].asBstr
    val encapsulatedPublicKey =
        EcPublicKeyDoubleCoordinate.fromUncompressedPointEncoding(EcCurve.P256, pkEm)
    val cipherText = map["cipherText"].asBstr
    return Pair(cipherText, encapsulatedPublicKey)
}

//    SessionTranscript = [
//      null, // DeviceEngagementBytes not available
//      null, // EReaderKeyBytes not available
//      AndroidHandover // defined below
//    ]
//
//    From https://github.com/WICG/mobile-document-request-api
//
//    BrowserHandover = [
//      "BrowserHandoverv1",
//      nonce,
//      OriginInfoBytes, // origin of the request as defined in ISO/IEC 18013-7
//      RequesterIdentity, // ? (omitting)
//      pkRHash
//    ]
private fun generateBrowserSessionTranscript(
    nonce: ByteString,
    origin: String,
    requesterIdHash: ByteArray
): ByteArray {
    // TODO: Instead of hand-rolling this, we should use OriginInfoDomain which
    //   uses `domain` instead of `baseUrl` which is what the latest version of 18013-7
    //   calls for.
    val originInfoBytes = Cbor.encode(
        buildCborMap {
            put("cat", 1)
            put("type", 1)
            putCborMap("details") {
                put("baseUrl", origin)
            }
        }
    )
    return Cbor.encode(
        buildCborArray {
            add(Simple.NULL) // DeviceEngagementBytes
            add(Simple.NULL) // EReaderKeyBytes
            addCborArray {
                add(BROWSER_HANDOVER_V1)
                add(nonce.toByteArray())
                add(originInfoBytes)
                add(requesterIdHash)
            }
        }
    )
}
