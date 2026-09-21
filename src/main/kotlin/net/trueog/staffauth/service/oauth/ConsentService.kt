package net.trueog.staffauth.service.oauth

import io.micronaut.context.annotation.Value
import jakarta.inject.Singleton
import net.trueog.staffauth.client.MinecraftClient
import net.trueog.staffauth.repository.UserRepository
import net.trueog.staffauth.service.ClientAccessService
import sh.ory.hydra.api.OAuth2Api
import sh.ory.hydra.model.AcceptOAuth2ConsentRequest
import sh.ory.hydra.model.AcceptOAuth2ConsentRequestSession
import sh.ory.hydra.model.OAuth2ConsentRequest
import sh.ory.hydra.model.RejectOAuth2Request
import java.net.URI
import java.time.Duration
import java.util.*

@Singleton
class ConsentService(
    private val oAuth2Api: OAuth2Api,
    private val userRepository: UserRepository,
    private val minecraftClient: MinecraftClient,
    private val clientAccessService: ClientAccessService
) {
    @Value($$"${hydra.remember-duration}")
    lateinit var rememberDuration: Duration

    fun getConsentRequest(consentChallenge: String): OAuth2ConsentRequest {
        return oAuth2Api.getOAuth2ConsentRequest(consentChallenge)
    }

    /** Whether the user behind [consentRequest] has a role that may use the requesting client. */
    suspend fun isAllowed(consentRequest: OAuth2ConsentRequest): Boolean {
        val subject = consentRequest.subject ?: throw IllegalStateException()
        val user = userRepository.findByUuid(UUID.fromString(subject)) ?: return false
        return clientAccessService.isAllowed(consentRequest.client?.clientId, user.role)
    }

    suspend fun accept(consentRequest: OAuth2ConsentRequest): URI {
        val subject = consentRequest.subject ?: throw IllegalStateException()
        val user = userRepository.findByUuid(UUID.fromString(subject))
        if (user == null || !user.isSetUp || user.deactivated) {
            return reject(consentRequest)
        }
        // Refuse consent (also remembered consents) when the user's role may not use this client
        if (!clientAccessService.isAllowed(consentRequest.client?.clientId, user.role)) {
            return reject(consentRequest, "access_denied", "Your role does not have access to this application")
        }

        val claims = buildMap {
            if (consentRequest.requestedScope?.contains("email") == true) put("email", user.email)
            if (consentRequest.requestedScope?.contains("roles") == true) put("roles", arrayOf(user.role))
            if (consentRequest.requestedScope?.contains("profile") == true) {
                val minecraftName = minecraftClient.getByUuid(user.minecraftUuid)?.name ?: "Unknown username"
                put("name", minecraftName)
                // OIDC standard claim; Gitea derives the username from it (nickname/preferred_username).
                put("preferred_username", minecraftName)
                put("picture", "https://minotar.net/helm/${user.minecraftUuid.toString().replace("-", "")}.png")
            }
        }
        val response = oAuth2Api.acceptOAuth2ConsentRequest(
            consentRequest.challenge, AcceptOAuth2ConsentRequest().grantScope(consentRequest.requestedScope).session(
                AcceptOAuth2ConsentRequestSession().idToken(claims)
            ).remember(true).rememberFor(rememberDuration.seconds)
        )
        return URI.create(response.redirectTo)
    }

    fun reject(consentRequest: OAuth2ConsentRequest, error: String? = null, description: String? = null): URI {
        val response = oAuth2Api.rejectOAuth2ConsentRequest(
            consentRequest.challenge,
            RejectOAuth2Request().error(error).errorDescription(description)
        )
        return URI.create(response.redirectTo)
    }
}