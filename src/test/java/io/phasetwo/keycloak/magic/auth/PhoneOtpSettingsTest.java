package io.phasetwo.keycloak.magic.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.phasetwo.keycloak.magic.auth.util.SupportedMobile;
import io.phasetwo.keycloak.magic.otp.OtpChannel;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatorConfigModel;

class PhoneOtpSettingsTest {

  private static PhoneOtpSettings settings(Map<String, String> values) {
    AuthenticatorConfigModel model = new AuthenticatorConfigModel();
    model.setConfig(values);
    return PhoneOtpSettings.from(model);
  }

  @Test
  void defaultsMatchThePlan() {
    PhoneOtpSettings s = PhoneOtpSettings.from(null);
    assertEquals(4, s.codeLength());
    assertEquals(3, s.maxAttempts());
    assertEquals(3, s.maxSendsPerPhoneHour());
    assertEquals(5, s.maxSendsPerPhoneDay());
    assertEquals(OtpChannel.WHATSAPP, s.primaryChannel());
    assertEquals(OtpChannel.SMS, s.resendChannel());
    assertEquals(
        Set.of(SupportedMobile.Country.SA, SupportedMobile.Country.EG), s.allowedCountries());
    assertEquals(SupportedMobile.Country.SA, s.defaultCountry());
    assertEquals(List.of("SA", "EG"), s.allowedCountryCodes());
  }

  @Test
  void cooldownEscalatesAndTheLastValueRepeats() {
    PhoneOtpSettings s = PhoneOtpSettings.from(null);
    assertEquals(0, s.cooldownAfter(0));
    assertEquals(30, s.cooldownAfter(1));
    assertEquals(60, s.cooldownAfter(2));
    assertEquals(120, s.cooldownAfter(3));
    assertEquals(120, s.cooldownAfter(7));
  }

  @Test
  void ignoresUnsafeValues() {
    PhoneOtpSettings s =
        settings(
            Map.of(
                PhoneOtpSettings.CODE_LENGTH, "2",
                PhoneOtpSettings.RESEND_COOLDOWNS, "x,,",
                PhoneOtpSettings.ALLOWED_COUNTRIES, "US",
                PhoneOtpSettings.MAX_ATTEMPTS, "-1"));
    assertEquals(4, s.codeLength());
    assertEquals(30, s.cooldownAfter(1));
    assertEquals(2, s.allowedCountries().size());
    assertEquals(3, s.maxAttempts());
  }

  @Test
  void defaultCountryMustBeAllowed() {
    PhoneOtpSettings s =
        settings(
            Map.of(
                PhoneOtpSettings.ALLOWED_COUNTRIES, "EG",
                PhoneOtpSettings.DEFAULT_COUNTRY, "SA"));
    assertEquals(SupportedMobile.Country.EG, s.defaultCountry());
  }
}
