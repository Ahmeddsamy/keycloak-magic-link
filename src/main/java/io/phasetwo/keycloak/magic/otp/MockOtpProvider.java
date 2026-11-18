package io.phasetwo.keycloak.magic.otp;

import java.util.UUID;
import lombok.extern.jbosslog.JBossLog;

/**
 * Dev-only provider. Sends nothing and is stateless, like the backend mock: {@code OTP_MOCK_CODE}
 * (default {@code 0000}) is valid, {@code 9999} is expired, anything else is invalid; a check code
 * it did not issue is expired.
 */
@JBossLog
public final class MockOtpProvider implements OtpService {

  static final String CHECK_CODE_PREFIX = "mock-";
  static final String EXPIRED_CODE = "9999";

  private final String validCode;

  public MockOtpProvider(String validCode) {
    this.validCode = validCode;
  }

  @Override
  public OtpSendResult send(OtpSendRequest request) {
    log.infof(
        "[MockOtp] not sending a code over %s to %s",
        request.channel().configValue(), PhoneMasking.mask(request.recipient()));
    return new OtpSendResult(CHECK_CODE_PREFIX + UUID.randomUUID(), request.channel(), null);
  }

  @Override
  public OtpCheckOutcome check(String checkCode, String code) {
    if (checkCode == null || !checkCode.startsWith(CHECK_CODE_PREFIX)) {
      return OtpCheckOutcome.EXPIRED;
    }
    if (EXPIRED_CODE.equals(code)) return OtpCheckOutcome.EXPIRED;
    return validCode.equals(code) ? OtpCheckOutcome.VALID : OtpCheckOutcome.INVALID;
  }
}
