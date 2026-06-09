package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;

import com.google.auto.service.AutoService;
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
 * Factory for the {@code ext-phone-otp} authenticator — phone-number + OTP sign-in (agents).
 * Mirrors {@link EmailOtpAuthenticatorFactory}; bind it to the agent client only via a per-client
 * browser-flow override.
 */
@JBossLog
@AutoService(AuthenticatorFactory.class)
public class PhoneOtpAuthenticatorFactory implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "ext-phone-otp";

  /** Realm role granted to a JIT-created agent (default {@code agent}). */
  public static final String ROLE_CONFIG_PROPERTY = "ext-phone-otp-role";

  /** Delivery channel for the OTP (default {@code whatsapp}). */
  public static final String CHANNEL_CONFIG_PROPERTY = "ext-phone-otp-channel";

  /** Informational fallback channel; the managed provider drives the actual fallback. */
  public static final String FALLBACK_CHANNEL_CONFIG_PROPERTY = "ext-phone-otp-fallback-channel";

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
    return "Sign in with a one-time-password sent to your phone (WhatsApp/SMS via the OTP provider).";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    ProviderConfigProperty createUser = new ProviderConfigProperty();
    createUser.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    createUser.setName(CREATE_NONEXISTENT_USER_CONFIG_PROPERTY);
    createUser.setLabel("Force create user");
    createUser.setHelpText(
        "Creates a new user when a phone number is provided that does not match an existing user.");
    createUser.setDefaultValue(false);

    ProviderConfigProperty role = new ProviderConfigProperty();
    role.setType(ProviderConfigProperty.STRING_TYPE);
    role.setName(ROLE_CONFIG_PROPERTY);
    role.setLabel("Created-user role");
    role.setHelpText("Realm role granted to a newly created user (e.g. agent).");
    role.setDefaultValue("agent");

    ProviderConfigProperty channel = new ProviderConfigProperty();
    channel.setType(ProviderConfigProperty.LIST_TYPE);
    channel.setName(CHANNEL_CONFIG_PROPERTY);
    channel.setLabel("OTP channel");
    channel.setHelpText("Primary delivery channel for the OTP.");
    channel.setOptions(List.of("whatsapp", "sms", "voice"));
    channel.setDefaultValue("whatsapp");

    ProviderConfigProperty fallback = new ProviderConfigProperty();
    fallback.setType(ProviderConfigProperty.LIST_TYPE);
    fallback.setName(FALLBACK_CHANNEL_CONFIG_PROPERTY);
    fallback.setLabel("Fallback channel");
    fallback.setHelpText("Informational — the managed provider performs the actual fallback.");
    fallback.setOptions(List.of("sms", "voice", "whatsapp"));
    fallback.setDefaultValue("sms");

    return List.of(createUser, role, channel, fallback);
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
