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

@JBossLog
@AutoService(AuthenticatorFactory.class)
public class DirectGrantEmailOtpAuthenticatorFactory implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "ext-direct-grant-email-otp";

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
    AuthenticationExecutionModel.Requirement.REQUIRED,
    AuthenticationExecutionModel.Requirement.DISABLED
  };

  @Override
  public Authenticator create(KeycloakSession session) {
    return new DirectGrantEmailOtpAuthenticator();
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
    return false;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public String getDisplayType() {
    return "Direct Grant Email OTP";
  }

  @Override
  public String getHelpText() {
    return "Validates an email OTP in the direct grant flow for native (non-browser) login. "
        + "First token request with only a username sends the code; second request with the "
        + "otp parameter exchanges it for tokens.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    ProviderConfigProperty createUser = new ProviderConfigProperty();
    createUser.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    createUser.setName(CREATE_NONEXISTENT_USER_CONFIG_PROPERTY);
    createUser.setLabel("Force create user");
    createUser.setHelpText(
        "Creates a new user when an email is provided that does not match an existing user.");
    createUser.setDefaultValue(false);

    ProviderConfigProperty ttl = new ProviderConfigProperty();
    ttl.setType(ProviderConfigProperty.STRING_TYPE);
    ttl.setName(DirectGrantEmailOtpAuthenticator.CONFIG_OTP_TTL_SECONDS);
    ttl.setLabel("OTP time-to-live (seconds)");
    ttl.setHelpText("How long a generated OTP code remains valid.");
    ttl.setDefaultValue(String.valueOf(DirectGrantEmailOtpAuthenticator.DEFAULT_OTP_TTL_SECONDS));

    ProviderConfigProperty maxAttempts = new ProviderConfigProperty();
    maxAttempts.setType(ProviderConfigProperty.STRING_TYPE);
    maxAttempts.setName(DirectGrantEmailOtpAuthenticator.CONFIG_OTP_MAX_ATTEMPTS);
    maxAttempts.setLabel("Max verification attempts");
    maxAttempts.setHelpText(
        "Number of incorrect codes allowed before the OTP is invalidated.");
    maxAttempts.setDefaultValue(
        String.valueOf(DirectGrantEmailOtpAuthenticator.DEFAULT_OTP_MAX_ATTEMPTS));

    ProviderConfigProperty resendCooldown = new ProviderConfigProperty();
    resendCooldown.setType(ProviderConfigProperty.STRING_TYPE);
    resendCooldown.setName(
        DirectGrantEmailOtpAuthenticator.CONFIG_OTP_RESEND_COOLDOWN_SECONDS);
    resendCooldown.setLabel("Resend cooldown (seconds)");
    resendCooldown.setHelpText(
        "Minimum time between OTP emails for the same user; throttles resend abuse.");
    resendCooldown.setDefaultValue(
        String.valueOf(DirectGrantEmailOtpAuthenticator.DEFAULT_OTP_RESEND_COOLDOWN_SECONDS));

    return List.of(createUser, ttl, maxAttempts, resendCooldown);
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
