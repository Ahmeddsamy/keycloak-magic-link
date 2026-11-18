package io.phasetwo.keycloak.magic.otp;

/**
 * A code to send.
 *
 * @param recipient normalized E.164 phone
 * @param channel channel to send over (no fallback at this level; see {@link PhoneOtpSender})
 * @param locale {@code en} or {@code ar}
 * @param codeLength digits in the code
 * @param expiryMinutes code lifetime
 */
public record OtpSendRequest(
    String recipient, OtpChannel channel, String locale, int codeLength, int expiryMinutes) {}
