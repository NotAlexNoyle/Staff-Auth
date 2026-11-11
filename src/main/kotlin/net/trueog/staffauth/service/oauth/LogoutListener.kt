package net.trueog.staffauth.service.oauth

import io.micronaut.context.event.ApplicationEventListener
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.event.LogoutEvent
import jakarta.inject.Singleton

/**
 * The panel's logout (Micronaut Security's /logout) only cleared the panel's own cookie, so the Hydra single sign-on
 * session lived on and every app signed the person straight back in. Micronaut publishes a LogoutEvent with the
 * authentication before it redirects; end the subject's Hydra sessions there. Listeners run synchronously, so a Hydra
 * failure fails the logout request instead of pretending the person was signed out.
 */
@Singleton
class LogoutListener(private val sessionRevocationService: SessionRevocationService) :
    ApplicationEventListener<LogoutEvent> {
    override fun onApplicationEvent(event: LogoutEvent) {
        val authentication = event.source as? Authentication ?: return
        val subject = authentication.attributes["sub"] as? String ?: return
        sessionRevocationService.revokeAll(subject)
    }
}
