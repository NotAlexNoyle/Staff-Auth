package net.trueog.staffauth.service

import io.micronaut.context.annotation.Property
import io.micronaut.core.annotation.Nullable
import jakarta.inject.Singleton
import net.trueog.staffauth.model.Role

/**
 * Restricts which roles may use an OAuth2 client. Configure per Hydra client id:
 * ```yaml
 * access:
 *   clients:
 *     <client-id>:
 *       roles: [ADMIN, DEVELOPER]
 * ```
 * Clients without an entry are open to every role.
 */
@Singleton
class ClientAccessService(
    @Nullable @Property(name = "access.clients") clients: Map<String, Map<String, List<String>>>?
) {
    private val allowedRoles: Map<String, Set<Role>> = clients.orEmpty().mapValues { (_, config) ->
        (config["roles"] ?: emptyList()).map { Role.valueOf(it.toString()) }.toSet()
    }

    /** True if [role] may use the client, i.e. no restriction is configured for it or the role is listed. */
    fun isAllowed(clientId: String?, role: Role): Boolean {
        val roles = allowedRoles[clientId] ?: return true
        return role in roles
    }
}
