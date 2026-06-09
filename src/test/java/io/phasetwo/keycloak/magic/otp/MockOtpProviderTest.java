package io.phasetwo.keycloak.magic.otp;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Pure-logic tests for {@link MockOtpProvider} — no Keycloak/Docker. */
class MockOtpProviderTest {

  private static final String PHONE = "+966500000000";

  @Test
  void startNeverThrows() {
    MockOtpProvider provider = new MockOtpProvider("000000");
    assertDoesNotThrow(() -> provider.start(PHONE, "whatsapp"));
  }

  @Test
  void checkAcceptsOnlyTheFixedCode() {
    MockOtpProvider provider = new MockOtpProvider("000000");
    assertTrue(provider.check(PHONE, "000000"));
    assertFalse(provider.check(PHONE, "111111"));
  }

  @Test
  void checkRejectsNullCodeWithoutThrowing() {
    MockOtpProvider provider = new MockOtpProvider("000000");
    assertFalse(provider.check(PHONE, null));
  }
}
