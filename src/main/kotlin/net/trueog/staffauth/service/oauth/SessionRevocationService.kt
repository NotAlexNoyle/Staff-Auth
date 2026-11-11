package net.trueog.staffauth.service.oauth

import jakarta.inject.Singleton
import sh.ory.hydra.api.OAuth2Api

/**
 * Ends a subject's Staff-Auth sign-ins at Hydra. Used on role change, deactivation and deletion (UserService) and on
 * logout (LogoutListener, LogoutRequestController).
 *
 * Revoking the consent sessions revokes every token the apps hold for the subject; Gitea (its user sync and
 * trueog-authwatch) and WeKan (trueog-wekan-authwatch) notice that and sign the person out, and the next sign-in goes
 * through Staff-Auth again.
 */
@Singleton
class SessionRevocationService(private val oAuth2Api: OAuth2Api) {
    /** Login sessions (single sign-on) and consent sessions (the apps' tokens). */
    fun revokeAll(subject: String) {
        oAuth2Api.revokeOAuth2LoginSessions(subject, null)
        revokeConsent(subject)
    }

    /** Consent sessions only: for a logout Hydra itself is completing, which ends the login session. */
    fun revokeConsent(subject: String) {
        oAuth2Api.revokeOAuth2ConsentSessions(subject, null, null, true)
    }
}
