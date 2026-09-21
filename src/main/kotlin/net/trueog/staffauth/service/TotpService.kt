package net.trueog.staffauth.service

import dev.samstevens.totp.code.CodeVerifier
import dev.samstevens.totp.code.HashingAlgorithm
import dev.samstevens.totp.qr.QrData
import dev.samstevens.totp.qr.ZxingPngQrGenerator
import dev.samstevens.totp.util.Utils.getDataUriForImage
import jakarta.inject.Singleton

@Singleton
class TotpService(
    private val codeVerifier: CodeVerifier
) {
    /** Build the QR code (data URI) for an existing [secret]; the caller owns the secret's lifecycle. */
    fun generateTotp(username: String, secret: String): String {
        val qrCodeData = QrData.Builder()
            .label(username)
            .secret(secret)
            .issuer("Staff-OG")
            .algorithm(HashingAlgorithm.SHA1)
            .digits(6)
            .period(30)
            .build()

        val generator = ZxingPngQrGenerator()
        val imageData = generator.generate(qrCodeData)

        return getDataUriForImage(imageData, generator.imageMimeType)
    }

    fun isValid(secret: String, code: String) = codeVerifier.isValidCode(secret, code)
}