package net.trueog.staffauth.security

import io.micronaut.http.HttpRequest
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecuredAnnotationRule
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.rules.SecurityRuleResult
import io.micronaut.web.router.RouteAttributes
import jakarta.inject.Singleton
import kotlinx.coroutines.reactor.mono
import net.trueog.staffauth.repository.UserRepository
import org.reactivestreams.Publisher
import java.util.*

// Re-checks the database on every request to a role-protected route so demotions take effect at once
// The panel session is Hydra's ID token in a cookie, whose roles stay frozen until it expires
@Singleton
class CurrentRoleRule(private val userRepository: UserRepository) : SecurityRule<HttpRequest<*>> {
    // Run just before Micronaut's @Secured rule, which still checks the roles in the token afterwards
    override fun getOrder(): Int = SecuredAnnotationRule.ORDER - 1

    override fun check(request: HttpRequest<*>?, authentication: Authentication?): Publisher<SecurityRuleResult> = mono {
        // Roles the matched route requires, from its @Secured annotation
        val roles = Optional.ofNullable(request).flatMap { RouteAttributes.getRouteMatch(it) }
            .map { it.annotationMetadata.stringValues(Secured::class.java).toList() }.orElse(emptyList())
            .filter { it !in NOT_ROLES }
        // Not role-protected, or nobody signed in: leave the decision to the other rules
        if (roles.isEmpty() || authentication == null) return@mono SecurityRuleResult.UNKNOWN
        // The token's subject is the user's Staff-Auth UUID
        val uuid = runCatching { UUID.fromString(authentication.attributes["sub"] as? String) }.getOrNull()
        // Load the user fresh instead of trusting the token
        val user = uuid?.let { userRepository.findByUuid(it) }
        // Deleted, deactivated or no longer holding a required role: reject, otherwise let @Secured decide
        if (user == null || user.deactivated || user.role.name !in roles) SecurityRuleResult.REJECTED
        else SecurityRuleResult.UNKNOWN
    }

    companion object {
        // Values @Secured accepts that are not roles
        private val NOT_ROLES = setOf(SecurityRule.IS_ANONYMOUS, SecurityRule.IS_AUTHENTICATED, SecurityRule.DENY_ALL)
    }
}
