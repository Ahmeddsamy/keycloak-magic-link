package io.phasetwo.keycloak.magic.otp;

/**
 * Vendor-neutral one-time-password verification.
 *
 * <p>Mirrors the parcelo-backend {@code OtpVerificationService} so the same managed-OTP contract is
 * shared by both runtimes that send agent/address OTPs (this Keycloak SPI for agent login, NestJS
 * for address verify): the provider owns code generation, delivery, expiry and checking — we never
 * store codes.
 */
public interface OtpService {

  /**
   * Starts a verification — sends a code to {@code phoneNumber} (E.164) over {@code channel} (e.g.
   * {@code whatsapp}, {@code sms}). Provider-managed fallback (WhatsApp&rarr;SMS) is handled by the
   * provider, not here.
   */
  void start(String phoneNumber, String channel);

  /**
   * @return {@code true} if {@code code} is the valid, unexpired code for {@code phoneNumber};
   *     {@code false} for an invalid/expired code. Throws only on transport/provider failure
   *     (caller treats as "try again").
   */
  boolean check(String phoneNumber, String code);
}
