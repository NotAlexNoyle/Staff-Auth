package net.trueog.staffauth.controller.oauth

import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.*
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import net.trueog.staffauth.dto.ErrorDto
import net.trueog.staffauth.dto.logout.LogoutDto
import net.trueog.staffauth.service.oauth.SessionRevocationService
import sh.ory.hydra.ApiException
import sh.ory.hydra.api.OAuth2Api

/**
 * Hydra's logout UI (urls.logout = the frontend's /logout, which calls this). An app's sign-out (for example Gitea's)
 * goes to Hydra's /oauth2/sessions/logout, Hydra sends the browser here with a logout challenge, the person confirms,
 * and accepting it lets Hydra end the single sign-on session. The consent sessions are revoked as well, so every other
 * app signs the person out too. Confirmation is asked because such a request carries no proof of who sent it.
 */
@Controller("/logout-request")
@Secured(SecurityRule.IS_ANONYMOUS)
class LogoutRequestController(
    private val oAuth2Api: OAuth2Api,
    private val sessionRevocationService: SessionRevocationService
) {
    @Get
    fun index(@QueryValue("logout_challenge") logoutChallenge: String): Map<String, Any?> {
        val logoutRequest = oAuth2Api.getOAuth2LogoutRequest(logoutChallenge)
        return mapOf(
            "clientName" to logoutRequest.client?.run { clientName?.takeIf { it.isNotBlank() } ?: clientId }
        )
    }

    /** @return where the browser goes next */
    @Post
    fun indexSubmit(@Body logoutDto: LogoutDto): String {
        val logoutRequest = oAuth2Api.getOAuth2LogoutRequest(logoutDto.logoutChallenge)
        if (!logoutDto.logout) {
            oAuth2Api.rejectOAuth2LogoutRequest(logoutDto.logoutChallenge)
            return "/"
        }
        logoutRequest.subject?.takeIf { it.isNotBlank() }?.let { sessionRevocationService.revokeConsent(it) }
        return oAuth2Api.acceptOAuth2LogoutRequest(logoutDto.logoutChallenge).redirectTo
    }

    @Error(exception = ApiException::class)
    fun onHydraApiException(exception: ApiException): HttpResponse<ErrorDto> {
        return when (exception.code) {
            401, 404 -> HttpResponse.unauthorized<Unit>().body(ErrorDto.Default("INVALID_LOGOUT_CHALLENGE"))
            410 -> HttpResponse.unauthorized<Unit>().body(ErrorDto.Default("LOGOUT_REQUEST_USED"))
            else -> HttpResponse.status<Unit>(HttpStatus.valueOf(exception.code.takeIf { it != 0 } ?: 500))
                .body(ErrorDto.Default("HYDRA"))
        }
    }
}
