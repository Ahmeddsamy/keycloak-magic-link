package io.phasetwo.keycloak.magic.otp;

import java.util.EnumSet;
import java.util.Set;
import lombok.extern.jbosslog.JBossLog;

/**
 * Channel policy (same as the backend facade): the first code goes over the primary channel
 * (WhatsApp), every resend over the resend channel (SMS), and a send rejected because the channel
 * isn't available falls back to SMS silently. The page then shows the channel actually used.
 */
@JBossLog
public final class PhoneOtpSender {

  /** Failures where SMS may still work. INVALID_RECIPIENT is excluded: SMS would fail the same. */
  private static final Set<OtpProviderFailure> FALLBACK_FAILURES =
      EnumSet.of(OtpProviderFailure.CHANNEL_UNAVAILABLE, OtpProviderFailure.MISCONFIGURED);

  private final OtpService service;
  private final boolean whatsappReady;

  /**
   * @param whatsappReady false while no WhatsApp template is configured: WhatsApp is then replaced
   *     by SMS up front
   */
  public PhoneOtpSender(OtpService service, boolean whatsappReady) {
    this.service = service;
    this.whatsappReady = whatsappReady;
  }

  public OtpSendResult send(
      String phone,
      OtpChannel primary,
      OtpChannel resendChannel,
      boolean isResend,
      String locale,
      int codeLength,
      int expiryMinutes)
      throws OtpProviderException {
    OtpChannel channel = isResend ? resendChannel : primary;
    if (channel == OtpChannel.WHATSAPP && !whatsappReady) channel = OtpChannel.SMS;
    try {
      return service.send(new OtpSendRequest(phone, channel, locale, codeLength, expiryMinutes));
    } catch (OtpProviderException e) {
      if (channel == OtpChannel.SMS || !FALLBACK_FAILURES.contains(e.failure())) throw e;
      log.warnf(
          "ext-phone-otp: %s send rejected (%s) for %s, falling back to SMS",
          channel.configValue(), e.failure(), PhoneMasking.mask(phone));
      return service.send(
          new OtpSendRequest(phone, OtpChannel.SMS, locale, codeLength, expiryMinutes));
    }
  }
}
