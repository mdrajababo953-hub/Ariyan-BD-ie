package com.example.vpn

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.security.KeyChain
import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.net.InetAddress
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.security.auth.x500.X500Principal

class MitmCertificateManager(private val context: Context) {

    private val caDir = File(context.filesDir, "mitm_ca")
    private val caKeyFile = File(caDir, "ca_key.pk8")
    private val caCertFile = File(caDir, "ca_cert.der")

    private val lock = Any()
    @Volatile
    private var caKeyPair: KeyPair? = null
    @Volatile
    private var caCert: X509Certificate? = null
    private val hostSslContexts = ConcurrentHashMap<String, SSLContext>()
    private val random = SecureRandom()

    fun isCaReady(): Boolean = caCertFile.exists() && caKeyFile.exists()

    fun isCaTrustedByAndroid(): Boolean {
        return runCatching {
            val ks = KeyStore.getInstance("AndroidCAStore")
            ks.load(null, null)
            val aliases = ks.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                val cert = ks.getCertificate(alias) as? X509Certificate ?: continue
                val subject = cert.subjectX500Principal?.name.orEmpty()
                if (subject.contains("NetTrace Local Proxy CA", ignoreCase = true)) {
                    return@runCatching true
                }
            }
            false
        }.getOrDefault(false)
    }

    fun ensureCa(): Pair<X509Certificate, KeyPair> {
        val existingCert = caCert
        val existingKey = caKeyPair
        if (existingCert != null && existingKey != null) {
            return existingCert to existingKey
        }
        synchronized(lock) {
            caCert?.let { c ->
                caKeyPair?.let { k -> return c to k }
            }
            if (!caDir.exists()) caDir.mkdirs()

            if (caCertFile.exists() && caKeyFile.exists()) {
                val loaded = runCatching {
                    val certBytes = caCertFile.readBytes()
                    val keyBytes = caKeyFile.readBytes()
                    val cf = CertificateFactory.getInstance("X.509")
                    val cert = cf.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
                    val kf = KeyFactory.getInstance("RSA")
                    val priv = kf.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
                    cert to KeyPair(cert.publicKey, priv)
                }.getOrNull()
                if (loaded != null) {
                    caCert = loaded.first
                    caKeyPair = loaded.second
                    return loaded
                }
            }

            val kpGen = KeyPairGenerator.getInstance("RSA")
            kpGen.initialize(2048, random)
            val kp = kpGen.generateKeyPair()
            val caPrincipal = X500Principal("CN=NetTrace Local Proxy CA, O=NetTrace, C=US")
            val cert = generateCaCertificate(kp, caPrincipal)

            caKeyFile.writeBytes(kp.private.encoded)
            caCertFile.writeBytes(cert.encoded)
            caCert = cert
            caKeyPair = kp
            return cert to kp
        }
    }

    fun getSslContextForHost(hostname: String): SSLContext {
        val cleanHost = hostname.trim().lowercase(Locale.US).ifBlank { "localhost" }
        hostSslContexts[cleanHost]?.let { return it }

        val (rootCert, rootKp) = ensureCa()
        synchronized(lock) {
            hostSslContexts[cleanHost]?.let { return it }

            val kpGen = KeyPairGenerator.getInstance("RSA")
            kpGen.initialize(2048, random)
            val leafKp = kpGen.generateKeyPair()
            val leafCert = generateLeafCertificate(
                hostname = cleanHost,
                leafKp = leafKp,
                caCert = rootCert,
                caPrivateKey = rootKp.private
            )

            val ks = KeyStore.getInstance(KeyStore.getDefaultType())
            ks.load(null, null)
            val pwd = "nettrace".toCharArray()
            ks.setKeyEntry("server", leafKp.private, pwd, arrayOf(leafCert, rootCert))

            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(ks, pwd)
            val sslCtx = SSLContext.getInstance("TLS")
            sslCtx.init(kmf.keyManagers, null, random)

            if (hostSslContexts.size > 128) {
                hostSslContexts.clear()
            }
            hostSslContexts[cleanHost] = sslCtx
            return sslCtx
        }
    }

    fun getCaDerBytes(): ByteArray = ensureCa().first.encoded

    fun getCaPemString(): String {
        val b64 = Base64.encodeToString(getCaDerBytes(), Base64.NO_WRAP)
        val wrapped = b64.chunked(64).joinToString("\n")
        return "-----BEGIN CERTIFICATE-----\n$wrapped\n-----END CERTIFICATE-----\n"
    }

    fun createInstallCaIntent(): Intent {
        val der = getCaDerBytes()
        return KeyChain.createInstallIntent().apply {
            putExtra(KeyChain.EXTRA_CERTIFICATE, der)
            putExtra(KeyChain.EXTRA_NAME, "NetTrace Proxy CA")
        }
    }

    fun saveCaCertToAryanFolder(): String {
        val pemBytes = getCaPemString().toByteArray(Charsets.UTF_8)
        val fileName = "NetTrace_Proxy_CA.crt"

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val resolver = context.contentResolver
            val values = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                put(MediaStore.MediaColumns.MIME_TYPE, "application/x-x509-ca-cert")
                put(MediaStore.MediaColumns.RELATIVE_PATH, "${Environment.DIRECTORY_DOCUMENTS}/Aryan")
            }
            val uri = resolver.insert(MediaStore.Files.getContentUri("external"), values)
            if (uri != null) {
                resolver.openOutputStream(uri)?.use { out ->
                    out.write(pemBytes)
                    out.flush()
                }
                return "Documents/Aryan/$fileName"
            }
        }

        @Suppress("DEPRECATION")
        val publicDocs = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)
        val publicAryan = File(publicDocs, "Aryan")
        val targetFile = runCatching {
            if (!publicAryan.exists()) publicAryan.mkdirs()
            File(publicAryan, fileName).apply { writeBytes(pemBytes) }
        }.getOrElse {
            val appDocs = context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS) ?: context.filesDir
            val appAryan = File(appDocs, "Aryan")
            if (!appAryan.exists()) appAryan.mkdirs()
            File(appAryan, fileName).apply { writeBytes(pemBytes) }
        }
        return targetFile.absolutePath
    }

    private fun generateCaCertificate(kp: KeyPair, principal: X500Principal): X509Certificate {
        val now = System.currentTimeMillis()
        val notBefore = Date(now - 24L * 3600L * 1000L)
        val notAfter = Date(now + 3650L * 24L * 3600L * 1000L)
        val serial = BigInteger(63, random).abs().max(BigInteger.ONE)

        val basicConstraints = derExtension(
            oid = byteArrayOf(0x55, 0x1D, 0x13), // 2.5.29.19
            critical = true,
            value = derSequence(derBoolean(true))
        )
        val keyUsage = derExtension(
            oid = byteArrayOf(0x55, 0x1D, 0x0F), // 2.5.29.15
            critical = true,
            value = derBitString(byteArrayOf(0x86.toByte()), unusedBits = 1)
        )
        val skiHash = MessageDigest.getInstance("SHA-1").digest(kp.public.encoded)
        val ski = derExtension(
            oid = byteArrayOf(0x55, 0x1D, 0x0E), // 2.5.29.14
            critical = false,
            value = derOctetString(skiHash)
        )

        val tbs = buildTbsCertificate(
            serial = serial,
            issuer = principal,
            subject = principal,
            notBefore = notBefore,
            notAfter = notAfter,
            subjectPublicKeyInfo = kp.public.encoded,
            extensions = listOf(basicConstraints, keyUsage, ski)
        )
        return signTbsCertificate(tbs, kp.private)
    }

    private fun generateLeafCertificate(
        hostname: String,
        leafKp: KeyPair,
        caCert: X509Certificate,
        caPrivateKey: PrivateKey
    ): X509Certificate {
        val now = System.currentTimeMillis()
        val notBefore = Date(now - 24L * 3600L * 1000L)
        val notAfter = Date(now + 365L * 24L * 3600L * 1000L)
        val serial = BigInteger(63, random).abs().max(BigInteger.ONE)

        val subject = X500Principal("CN=${sanitizeCn(hostname)}, O=NetTrace, C=US")
        val basicConstraints = derExtension(
            oid = byteArrayOf(0x55, 0x1D, 0x13),
            critical = true,
            value = derSequence()
        )
        val keyUsage = derExtension(
            oid = byteArrayOf(0x55, 0x1D, 0x0F),
            critical = true,
            value = derBitString(byteArrayOf(0xA0.toByte()), unusedBits = 5)
        )
        val extKeyUsage = derExtension(
            oid = byteArrayOf(0x55, 0x1D, 0x25), // 2.5.29.37
            critical = false,
            value = derSequence(derOid(byteArrayOf(0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01)))
        )

        val isIpLiteral = hostname.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))
        val sanEntry = if (isIpLiteral) {
            val ipBytes = InetAddress.getByName(hostname).address
            derTag(0x87, ipBytes) // [7] iPAddress
        } else {
            derTag(0x82, hostname.toByteArray(Charsets.US_ASCII)) // [2] dNSName
        }
        val sanExt = derExtension(
            oid = byteArrayOf(0x55, 0x1D, 0x11), // 2.5.29.17
            critical = false,
            value = derSequence(sanEntry)
        )

        val tbs = buildTbsCertificate(
            serial = serial,
            issuer = caCert.subjectX500Principal,
            subject = subject,
            notBefore = notBefore,
            notAfter = notAfter,
            subjectPublicKeyInfo = leafKp.public.encoded,
            extensions = listOf(basicConstraints, keyUsage, extKeyUsage, sanExt)
        )
        return signTbsCertificate(tbs, caPrivateKey)
    }

    private fun sanitizeCn(host: String): String {
        return host.replace(",", "").replace("=", "").replace("/", "").take(64).ifBlank { "localhost" }
    }

    private fun buildTbsCertificate(
        serial: BigInteger,
        issuer: X500Principal,
        subject: X500Principal,
        notBefore: Date,
        notAfter: Date,
        subjectPublicKeyInfo: ByteArray,
        extensions: List<ByteArray>
    ): ByteArray {
        val sha256WithRsaAlgId = derSequence(
            derOid(SHA256_WITH_RSA_OID),
            derNull()
        )
        val version = derTag(0xA0, derInteger(BigInteger.valueOf(2)))
        val validity = derSequence(derUtcTime(notBefore), derUtcTime(notAfter))
        val extSeq = derTag(0xA3, derSequence(*extensions.toTypedArray()))

        return derSequence(
            version,
            derInteger(serial),
            sha256WithRsaAlgId,
            issuer.encoded,
            validity,
            subject.encoded,
            subjectPublicKeyInfo,
            extSeq
        )
    }

    private fun signTbsCertificate(tbs: ByteArray, signingKey: PrivateKey): X509Certificate {
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(signingKey)
        sig.update(tbs)
        val signatureBytes = sig.sign()

        val sha256WithRsaAlgId = derSequence(
            derOid(SHA256_WITH_RSA_OID),
            derNull()
        )
        val certDer = derSequence(
            tbs,
            sha256WithRsaAlgId,
            derBitString(signatureBytes, unusedBits = 0)
        )
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(certDer)) as X509Certificate
    }

    private fun derExtension(oid: ByteArray, critical: Boolean, value: ByteArray): ByteArray {
        return if (critical) {
            derSequence(derOid(oid), derBoolean(true), derOctetString(value))
        } else {
            derSequence(derOid(oid), derOctetString(value))
        }
    }

    private fun derSequence(vararg elements: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        for (el in elements) out.write(el)
        return derTag(0x30, out.toByteArray())
    }

    private fun derInteger(value: BigInteger): ByteArray = derTag(0x02, value.toByteArray())
    private fun derBoolean(value: Boolean): ByteArray = derTag(0x01, byteArrayOf(if (value) 0xFF.toByte() else 0x00))
    private fun derOctetString(bytes: ByteArray): ByteArray = derTag(0x04, bytes)
    private fun derNull(): ByteArray = byteArrayOf(0x05, 0x00)
    private fun derOid(encodedOidBytes: ByteArray): ByteArray = derTag(0x06, encodedOidBytes)

    private fun derBitString(bytes: ByteArray, unusedBits: Int): ByteArray {
        val payload = ByteArray(bytes.size + 1)
        payload[0] = unusedBits.toByte()
        System.arraycopy(bytes, 0, payload, 1, bytes.size)
        return derTag(0x03, payload)
    }

    private fun derUtcTime(date: Date): ByteArray {
        val fmt = SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        return derTag(0x17, fmt.format(date).toByteArray(Charsets.US_ASCII))
    }

    private fun derTag(tag: Int, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)
        val len = content.size
        when {
            len < 128 -> out.write(len)
            len < 256 -> {
                out.write(0x81)
                out.write(len)
            }
            len < 65536 -> {
                out.write(0x82)
                out.write((len ushr 8) and 0xFF)
                out.write(len and 0xFF)
            }
            else -> {
                out.write(0x83)
                out.write((len ushr 16) and 0xFF)
                out.write((len ushr 8) and 0xFF)
                out.write(len and 0xFF)
            }
        }
        out.write(content)
        return out.toByteArray()
    }

    companion object {
        // 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
        private val SHA256_WITH_RSA_OID = byteArrayOf(
            0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x0B
        )
    }
}
