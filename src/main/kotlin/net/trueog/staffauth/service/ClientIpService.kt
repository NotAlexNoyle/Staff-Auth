package net.trueog.staffauth.service

import io.micronaut.context.annotation.Value
import io.micronaut.http.HttpRequest
import jakarta.inject.Singleton

/**
 * Resolves the client IP used for the Minecraft IP check.
 *
 * When `micronaut.server.client-address-header` is configured (Staff-Auth behind a reverse proxy that
 * sets e.g. `X-Forwarded-For`), that header is used. Otherwise the socket peer address is used, as before.
 * `Forwarded`/`X-Forwarded-For` are deliberately *not* parsed: without a trusted proxy they are
 * client-controlled and would let an attacker spoof the IP check.
 */
@Singleton
class ClientIpService(
    @Value($$"${micronaut.server.client-address-header:}") private val clientAddressHeader: String?
) {
    fun resolve(request: HttpRequest<*>): String {
        if (!clientAddressHeader.isNullOrBlank()) {
            // X-Forwarded-For may be a list; the proxy in front of us puts the client first
            request.headers.get(clientAddressHeader)?.substringBefore(',')?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
        }
        return request.remoteAddress.address.hostAddress
    }
}
