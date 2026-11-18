package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;

import io.phasetwo.keycloak.magic.auth.util.SupportedMobile;
import io.phasetwo.keycloak.magic.otp.OtpChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.models.AuthenticatorConfigModel;

/** The {@code ext-phone-otp-*} authenticator config, parsed with safe defaults. */
record PhoneOtpSettings(
    boolean createUsers,
    String role,
    OtpChannel primaryChannel,
    OtpChannel resendChannel,
    int codeLength,
    int maxAttempts,
    List<Integer> resendCooldownsSeconds,
    int maxSendsPerPhoneHour,
    int maxSendsPerPhoneDay,
    Set<SupportedMobile.Country> allowedCountries,
    SupportedMobile.Country defaultCountry) {

  static final String ROLE = "ext-phone-otp-role";
  static final String CHANNEL = "ext-phone-otp-channel";
  static final String RESEND_CHANNEL = "ext-phone-otp-resend-channel";
  static final String CODE_LENGTH = "ext-phone-otp-code-length";
  static final String MAX_ATTEMPTS = "ext-phone-otp-max-attempts";
  static final String RESEND_COOLDOWNS = "ext-phone-otp-resend-cooldowns";
  static final String MAX_SENDS_PER_PHONE_HOUR = "ext-phone-otp-max-sends-per-phone-hour";
  static final String MAX_SENDS_PER_PHONE_DAY = "ext-phone-otp-max-sends-per-phone-day";
  static final String ALLOWED_COUNTRIES = "ext-phone-otp-allowed-countries";
  static final String DEFAULT_COUNTRY = "ext-phone-otp-default-country";

  static final String DEFAULT_ROLE = "agent";
  static final int DEFAULT_CODE_LENGTH = 4;
  static final int MIN_CODE_LENGTH = 4;
  static final int MAX_CODE_LENGTH = 8;
  static final int DEFAULT_MAX_ATTEMPTS = 3;
  static final String DEFAULT_RESEND_COOLDOWNS = "30,60,120";
  static final int DEFAULT_MAX_SENDS_PER_PHONE_HOUR = 3;
  static final int DEFAULT_MAX_SENDS_PER_PHONE_DAY = 5;
  static final String DEFAULT_ALLOWED_COUNTRIES = "EG,SA";

  static PhoneOtpSettings from(AuthenticatorConfigModel model) {
    Map<String, String> config =
        model == null || model.getConfig() == null ? Map.of() : model.getConfig();
    int codeLength = intValue(config, CODE_LENGTH, DEFAULT_CODE_LENGTH);
    if (codeLength < MIN_CODE_LENGTH || codeLength > MAX_CODE_LENGTH) {
      codeLength = DEFAULT_CODE_LENGTH;
    }
    Set<SupportedMobile.Country> allowed = countries(config.get(ALLOWED_COUNTRIES));
    SupportedMobile.Country defaultCountry =
        SupportedMobile.Country.fromIso(config.get(DEFAULT_COUNTRY));
    if (defaultCountry == null || !allowed.contains(defaultCountry)) {
      defaultCountry =
          allowed.contains(SupportedMobile.Country.SA)
              ? SupportedMobile.Country.SA
              : allowed.iterator().next();
    }
    return new PhoneOtpSettings(
        Boolean.parseBoolean(config.getOrDefault(CREATE_NONEXISTENT_USER_CONFIG_PROPERTY, "false")),
        text(config, ROLE, DEFAULT_ROLE),
        OtpChannel.fromConfig(config.get(CHANNEL), OtpChannel.WHATSAPP),
        OtpChannel.fromConfig(config.get(RESEND_CHANNEL), OtpChannel.SMS),
        codeLength,
        intValue(config, MAX_ATTEMPTS, DEFAULT_MAX_ATTEMPTS),
        cooldowns(text(config, RESEND_COOLDOWNS, DEFAULT_RESEND_COOLDOWNS)),
        intValue(config, MAX_SENDS_PER_PHONE_HOUR, DEFAULT_MAX_SENDS_PER_PHONE_HOUR),
        intValue(config, MAX_SENDS_PER_PHONE_DAY, DEFAULT_MAX_SENDS_PER_PHONE_DAY),
        allowed,
        defaultCountry);
  }

  /**
   * Cooldown before the next send after {@code sendCount} sends (escalating, last value sticks).
   */
  int cooldownAfter(int sendCount) {
    if (sendCount <= 0) return 0;
    return resendCooldownsSeconds.get(Math.min(sendCount, resendCooldownsSeconds.size()) - 1);
  }

  /** Allowed countries as ISO codes in a stable order, for the phone form. */
  List<String> allowedCountryCodes() {
    return allowedCountries.stream().map(Enum::name).sorted(Collections.reverseOrder()).toList();
  }

  private static Set<SupportedMobile.Country> countries(String value) {
    Set<SupportedMobile.Country> result = EnumSet.noneOf(SupportedMobile.Country.class);
    String source = value == null || value.isBlank() ? DEFAULT_ALLOWED_COUNTRIES : value;
    for (String part : source.split(",")) {
      SupportedMobile.Country country = SupportedMobile.Country.fromIso(part);
      if (country != null) result.add(country);
    }
    return result.isEmpty() ? EnumSet.allOf(SupportedMobile.Country.class) : result;
  }

  private static List<Integer> cooldowns(String value) {
    List<Integer> result = new ArrayList<>();
    for (String part : value.split(",")) {
      try {
        int seconds = Integer.parseInt(part.trim());
        if (seconds > 0) result.add(seconds);
      } catch (NumberFormatException ignored) {
        // skip malformed entries
      }
    }
    if (result.isEmpty()) {
      return Arrays.stream(DEFAULT_RESEND_COOLDOWNS.split(",")).map(Integer::valueOf).toList();
    }
    return List.copyOf(result);
  }

  private static String text(Map<String, String> config, String key, String def) {
    String v = config.get(key);
    return v == null || v.isBlank() ? def : v.trim();
  }

  private static int intValue(Map<String, String> config, String key, int def) {
    try {
      int v = Integer.parseInt(text(config, key, String.valueOf(def)));
      return v > 0 ? v : def;
    } catch (NumberFormatException e) {
      return def;
    }
  }
}
