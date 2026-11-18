package io.phasetwo.keycloak.magic.otp;

/**
 * Managed one-time-password verification: the provider generates, delivers, expires and checks the
 * code; Keycloak only keeps the provider's check code in the (server-side) auth session.
 *
 * <p>Same contract as the parcelo-backend {@code OtpVerificationProvider}; both adapters are tested
 * against the shared {@code cequens-mfa-responses.json} fixtures.
 */
public interface OtpService {

  /** Sends a code over exactly {@code request.channel()}. */
  OtpSendResult send(OtpSendRequest request) throws OtpProviderException;

  /**
   * Checks {@code code} against the code behind {@code checkCode}. Fails closed: anything not
   * clearly verified is {@link OtpCheckOutcome#INVALID}.
   *
   * @throws OtpProviderException only when the provider could not answer (outage, credentials)
   */
  OtpCheckOutcome check(String checkCode, String code) throws OtpProviderException;
}
