package com.github.giorgioazzinnaro.keycloak.x509

import org.jboss.logging.Logger
import org.jboss.resteasy.spi.HttpRequest
import org.keycloak.common.util.PemUtils
import org.keycloak.services.x509.X509ClientCertificateLookup
import java.lang.IllegalArgumentException
import java.security.cert.X509Certificate

/**
 * EnvoyProxySslClientCertificateLookup is based on this documentation from Envoy:
 * https://www.envoyproxy.io/docs/envoy/v1.12.2/configuration/http/http_conn_man/headers#x-forwarded-client-cert
 */
open class EnvoyProxySslClientCertificateLookup(certificateChainLength: Int) : X509ClientCertificateLookup {

    protected val logger: Logger = Logger.getLogger(javaClass)

    private val HEADER = "x-forwarded-client-cert"

    init {
        if (certificateChainLength < 0) {
            throw IllegalArgumentException("certificateChainLength must be greater or equal to zero")
        }
    }

    /**
     * Here we can get the header `x-forwarded-client-cert` which has a `;` separated list of values,
     * of these values we want to extract that with key "Chain", separated by an `=` from the URL-encoded PEM-encoded
     * client certificate chain.
     *
     * Decoding of the PEM chain happens elsewhere.
     */
    override fun getCertificateChain(httpRequest: HttpRequest): Array<X509Certificate> {
        val header = getHeaderFromRequest(httpRequest)
        if (header.isEmpty()) {
            logger.warnf("HTTP header `%s` is empty", HEADER)
        }

        val rawChain = getRawChainFromHeader(header)
        if (rawChain.isNullOrEmpty()) {
            logger.warnf("Chain could not be extracted from `%s`", HEADER)
        }
        
    }

    /**
     * Get the semicolon-delimited header "x-forwarded-client-cert"
     */
    private fun getHeaderFromRequest(httpRequest: HttpRequest): String {
        return httpRequest.httpHeaders.requestHeaders.getFirst(HEADER)
    }

    /**
     * From the semicolon-delimited header "x-forwarded-client-cert",
     * create a map with each key-value pair,
     * and retrieve the string with key "Chain"
     */
    private fun getRawChainFromHeader(header: String): String? {
        return header
                .splitToSequence(';')
                .map { it.split('=') }
                .map { it[0] to it[1] }
                .toMap()
                .get("Chain")
    }

}
