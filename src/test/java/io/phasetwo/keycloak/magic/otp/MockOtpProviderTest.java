package io.phasetwo.keycloak.magic.otp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class MockOtpProviderTest {

  private final MockOtpProvider provider = new MockOtpProvider("0000");

  @Test
  void issuesAMockCheckCodeOnTheRequestedChannel() {
    OtpSendResult sent =
        provider.send(new OtpSendRequest("+966501234567", OtpChannel.WHATSAPP, "en", 4, 5));
    assertTrue(sent.checkCode().startsWith(MockOtpProvider.CHECK_CODE_PREFIX));
    assertEquals(OtpChannel.WHATSAPP, sent.channel());
  }

  @Test
  void acceptsOnlyTheConfiguredCode() {
    String checkCode =
        provider.send(new OtpSendRequest("+966501234567", OtpChannel.SMS, "en", 4, 5)).checkCode();
    assertEquals(OtpCheckOutcome.VALID, provider.check(checkCode, "0000"));
    assertEquals(OtpCheckOutcome.INVALID, provider.check(checkCode, "1234"));
    assertEquals(OtpCheckOutcome.EXPIRED, provider.check(checkCode, "9999"));
  }

  @Test
  void aCheckCodeItDidNotIssueIsExpired() {
    assertEquals(OtpCheckOutcome.EXPIRED, provider.check("REAL-CEQUENS-CODE", "0000"));
  }
}
