package io.phasetwo.keycloak.magic.otp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class OtpConfigTest {

  @Test
  void defaultsToTheMockWithTheFourDigitCode() {
    OtpConfig config = new OtpConfig(Map.<String, String>of()::get);
    assertFalse(config.isCequens());
    assertEquals("0000", config.mockCode);
    assertTrue(config.problems().isEmpty());
  }

  @Test
  void cequensNeedsCredentialsHttpsAndAVerifyTemplate() {
    OtpConfig config =
        new OtpConfig(
            Map.of(
                    "OTP_PROVIDER", "cequens",
                    "CEQUENS_BASE_URL", "http://apis.cequens.com",
                    "CEQUENS_WHATSAPP_TEMPLATE_NAME", "parcelo_otp")
                ::get);
    assertEquals(4, config.problems().size());
    assertThrows(IllegalStateException.class, () -> OtpServiceFactory.create(config));
  }

  @Test
  void aCompleteCequensConfigIsUsable() {
    OtpConfig config =
        new OtpConfig(
            Map.of(
                    "OTP_PROVIDER", "cequens",
                    "CEQUENS_USERNAME", "u",
                    "CEQUENS_API_KEY", "k",
                    "CEQUENS_WHATSAPP_TEMPLATE_NAME", "verify_parcelo_otp")
                ::get);
    assertTrue(config.problems().isEmpty());
    assertTrue(OtpServiceFactory.create(config) instanceof CequensOtpProvider);
  }

  @Test
  void cequensWithoutAWhatsappTemplateIsUsableBySmsOnly() {
    OtpConfig config =
        new OtpConfig(
            Map.of("OTP_PROVIDER", "cequens", "CEQUENS_USERNAME", "u", "CEQUENS_API_KEY", "k")
                ::get);
    assertTrue(config.problems().isEmpty());
    assertFalse(config.whatsappReady());
  }

  @Test
  void rejectsAnUnknownProvider() {
    assertFalse(new OtpConfig(Map.of("OTP_PROVIDER", "twilio")::get).problems().isEmpty());
  }
}
