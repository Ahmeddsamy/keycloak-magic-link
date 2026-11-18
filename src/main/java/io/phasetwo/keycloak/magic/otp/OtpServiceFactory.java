package io.phasetwo.keycloak.magic.otp;

import java.util.List;
import lombok.extern.jbosslog.JBossLog;

/**
 * The JVM-wide {@link OtpService}, chosen by {@code OTP_PROVIDER}. A single Cequens instance keeps
 * one HTTP client and one token cache for all logins.
 */
@JBossLog
public final class OtpServiceFactory {

  private static volatile OtpService instance;

  private OtpServiceFactory() {}

  /**
   * @throws IllegalStateException when Cequens is selected but misconfigured (logged once per call;
   *     the authenticator shows "provider unavailable")
   */
  public static OtpService get() {
    OtpService current = instance;
    if (current != null) return current;
    synchronized (OtpServiceFactory.class) {
      if (instance == null) instance = create(OtpConfig.fromEnv());
      return instance;
    }
  }

  static OtpService create(OtpConfig config) {
    List<String> problems = config.problems();
    if (!problems.isEmpty()) {
      log.errorf(
          "ext-phone-otp: OTP provider misconfigured (alert=otp_provider_critical): %s", problems);
      throw new IllegalStateException("OTP provider misconfigured: " + problems);
    }
    if (config.isCequens()) {
      log.info("ext-phone-otp: using the Cequens OTP provider");
      return new CequensOtpProvider(config);
    }
    log.warn("ext-phone-otp: using the MOCK OTP provider — never enable in production");
    return new MockOtpProvider(config.mockCode);
  }
}
