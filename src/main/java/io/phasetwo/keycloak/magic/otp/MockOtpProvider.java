package io.phasetwo.keycloak.magic.otp;

import lombok.extern.jbosslog.JBossLog;

/**
 * Dev/CI OTP provider. Sends nothing; {@link #check} accepts a single fixed code (from {@code
 * OTP_MOCK_CODE}, default {@code 000000}). Used until Cequens credentials + IP whitelisting are
 * provisioned (CR-03).
 */
@JBossLog
public class MockOtpProvider implements OtpService {

  private final String fixedCode;

  public MockOtpProvider(String fixedCode) {
    this.fixedCode = fixedCode;
  }

  @Override
  public void start(String phoneNumber, String channel) {
    log.infof(
        "[MockOtp] pretending to send a code over %s to %s (accept code: <OTP_MOCK_CODE>)",
        channel, PhoneMasking.mask(phoneNumber));
  }

  @Override
  public boolean check(String phoneNumber, String code) {
    boolean ok = fixedCode.equals(code);
    log.debugf("[MockOtp] check for %s -> %s", PhoneMasking.mask(phoneNumber), ok);
    return ok;
  }
}
