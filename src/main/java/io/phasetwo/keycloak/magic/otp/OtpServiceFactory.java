package io.phasetwo.keycloak.magic.otp;

import lombok.extern.jbosslog.JBossLog;

/**
 * Selects the {@link OtpService} implementation from {@code OTP_PROVIDER} (default {@code mock}). A
 * fresh instance per call is fine — providers are cheap and stateless (the Cequens HTTP client is
 * created lazily per use).
 */
@JBossLog
public final class OtpServiceFactory {

  private OtpServiceFactory() {}

  public static OtpService create() {
    OtpConfig config = OtpConfig.fromEnv();
    if ("cequens".equalsIgnoreCase(config.provider)) {
      log.debug("Using Cequens OTP provider");
      return new CequensOtpProvider(config);
    }
    log.warn("Using Mock OTP provider (OTP_PROVIDER != 'cequens') — accepts a fixed code");
    return new MockOtpProvider(config.mockCode);
  }
}
