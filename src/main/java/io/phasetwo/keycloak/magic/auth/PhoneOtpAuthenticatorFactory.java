package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.otp.OtpConfig;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Factory for {@code ext-phone-otp} — phone number + OTP sign-in (agents). Bind it to the agent
 * client only, through a per-client browser-flow override. Provider credentials come from env
 * ({@code OTP_PROVIDER}, {@code CEQUENS_*}); flow behaviour from the config below.
 */
@JBossLog
@AutoService(AuthenticatorFactory.class)
public class PhoneOtpAuthenticatorFactory implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "ext-phone-otp";

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
    AuthenticationExecutionModel.Requirement.REQUIRED,
    AuthenticationExecutionModel.Requirement.ALTERNATIVE,
    AuthenticationExecutionModel.Requirement.DISABLED
  };

  @Override
  public Authenticator create(KeycloakSession session) {
    return new PhoneOtpAuthenticator();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getReferenceCategory() {
    return "alternate-auth";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return true;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public String getDisplayType() {
    return "Phone OTP";
  }

  @Override
  public String getHelpText() {
    return "Sign in with a code sent to a Saudi or Egyptian mobile (WhatsApp, SMS fallback).";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return List.of(
        property(
            CREATE_NONEXISTENT_USER_CONFIG_PROPERTY,
            ProviderConfigProperty.BOOLEAN_TYPE,
            "Create users",
            "Create an account for a new number once its code is verified.",
            "false"),
        property(
            PhoneOtpSettings.ROLE,
            ProviderConfigProperty.STRING_TYPE,
            "Created-user role",
            "Realm role granted to a newly created user.",
            PhoneOtpSettings.DEFAULT_ROLE),
        list(
            PhoneOtpSettings.CHANNEL,
            "Primary channel",
            "Channel for the first code. WhatsApp falls back to SMS if rejected.",
            "whatsapp"),
        list(PhoneOtpSettings.RESEND_CHANNEL, "Resend channel", "Channel for every resend.", "sms"),
        property(
            PhoneOtpSettings.CODE_LENGTH,
            ProviderConfigProperty.STRING_TYPE,
            "Code length",
            "Digits in the code (4-8).",
            String.valueOf(PhoneOtpSettings.DEFAULT_CODE_LENGTH)),
        property(
            PhoneOtpSettings.MAX_ATTEMPTS,
            ProviderConfigProperty.STRING_TYPE,
            "Attempts per code",
            "Wrong entries allowed before the code is burned.",
            String.valueOf(PhoneOtpSettings.DEFAULT_MAX_ATTEMPTS)),
        property(
            PhoneOtpSettings.RESEND_COOLDOWNS,
            ProviderConfigProperty.STRING_TYPE,
            "Resend cooldowns (s)",
            "Comma-separated wait before each resend; the last value repeats.",
            PhoneOtpSettings.DEFAULT_RESEND_COOLDOWNS),
        property(
            PhoneOtpSettings.MAX_SENDS_PER_PHONE_HOUR,
            ProviderConfigProperty.STRING_TYPE,
            "Codes per number per hour",
            "Across browsers and nodes.",
            String.valueOf(PhoneOtpSettings.DEFAULT_MAX_SENDS_PER_PHONE_HOUR)),
        property(
            PhoneOtpSettings.MAX_SENDS_PER_PHONE_DAY,
            ProviderConfigProperty.STRING_TYPE,
            "Codes per number per day",
            "Across browsers and nodes.",
            String.valueOf(PhoneOtpSettings.DEFAULT_MAX_SENDS_PER_PHONE_DAY)),
        property(
            PhoneOtpSettings.ALLOWED_COUNTRIES,
            ProviderConfigProperty.STRING_TYPE,
            "Allowed countries",
            "Comma-separated ISO codes; only SA and EG are supported.",
            PhoneOtpSettings.DEFAULT_ALLOWED_COUNTRIES),
        property(
            PhoneOtpSettings.DEFAULT_COUNTRY,
            ProviderConfigProperty.STRING_TYPE,
            "Default country",
            "Country preselected on the phone page.",
            "SA"));
  }

  private static ProviderConfigProperty property(
      String name, String type, String label, String help, String defaultValue) {
    ProviderConfigProperty property = new ProviderConfigProperty();
    property.setName(name);
    property.setType(type);
    property.setLabel(label);
    property.setHelpText(help);
    property.setDefaultValue(defaultValue);
    return property;
  }

  private static ProviderConfigProperty list(
      String name, String label, String help, String defaultValue) {
    ProviderConfigProperty property =
        property(name, ProviderConfigProperty.LIST_TYPE, label, help, defaultValue);
    property.setOptions(List.of("whatsapp", "sms"));
    return property;
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // Surface a misconfiguration at boot instead of at the first login.
    List<String> problems = OtpConfig.fromEnv().problems();
    if (!problems.isEmpty()) {
      log.errorf(
          "ext-phone-otp: OTP provider misconfigured (alert=otp_provider_critical): %s", problems);
    }
  }

  @Override
  public void close() {}
}
