package net.trueog.staffauth.dto.logout

import io.micronaut.serde.annotation.Serdeable

@Serdeable
data class LogoutDto(val logout: Boolean, val logoutChallenge: String)
