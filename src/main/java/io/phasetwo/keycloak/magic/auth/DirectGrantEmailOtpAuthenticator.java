package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;
import static io.phasetwo.keycloak.magic.MagicLink.EMAIL_OTP;
import static io.phasetwo.keycloak.magic.auth.util.Authenticators.is;

import io.phasetwo.keycloak.magic.MagicLink;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

/**
 * Email OTP authenticator for the Direct Grant (Resource Owner Password Credentials) flow,
 * enabling fully native (non-browser) email OTP login for first-party mobile apps.
 *
 * <p>Protocol (two calls to the token endpoint, both with {@code grant_type=password}):
 *
 * <ol>
 *   <li>{@code username=<email>} and no {@code otp} parameter: generates a one-time code,
 *       emails it to the user (creating the user first when force-create is enabled) and
 *       responds {@code 401} with OAuth error {@code otp_sent}.
 *   <li>{@code username=<email>&otp=<code>}: validates the code and, on success, issues
 *       tokens as a normal direct grant response.
 * </ol>
 *
 * <p>Unlike the browser {@link EmailOtpAuthenticator}, the two requests share no
 * authentication session, so the code is kept in the {@link SingleUseObjectProvider}
 * (cluster-safe, TTL-bound) keyed by realm and user. Codes expire after a configurable
 * TTL, allow a bounded number of verification attempts, and resends are throttled by a
 * configurable cooldown.
 */
@JBossLog
public class DirectGrantEmailOtpAuthenticator implements Authenticator {

  public static final String FORM_PARAM_USERNAME = "username";
  public static final String FORM_PARAM_OTP_CODE = "otp";

  /** OAuth error code returned after a code has been generated and emailed. */
  public static final String ERROR_OTP_SENT = "otp_sent";

  /** OAuth error code returned when no valid code exists (expired, consumed, or never sent). */
  public static final String ERROR_OTP_EXPIRED = "otp_expired";

  /** OAuth error code returned for a wrong code (attempts remaining). */
  public static final String ERROR_INVALID_OTP = "invalid_otp";

  /** OAuth error code returned when the attempt limit is exhausted (code invalidated). */
  public static final String ERROR_OTP_MAX_ATTEMPTS = "otp_max_attempts";

  static final String CONFIG_OTP_TTL_SECONDS = "ext-direct-grant-otp-ttl";
  static final String CONFIG_OTP_MAX_ATTEMPTS = "ext-direct-grant-otp-max-attempts";
  static final String CONFIG_OTP_RESEND_COOLDOWN_SECONDS = "ext-direct-grant-otp-resend-cooldown";

  static final int DEFAULT_OTP_TTL_SECONDS = 300;
  static final int DEFAULT_OTP_MAX_ATTEMPTS = 5;
  static final int DEFAULT_OTP_RESEND_COOLDOWN_SECONDS = 60;

  private static final int OTP_LENGTH = 6;

  private static final String NOTE_CODE = "code";
  private static final String NOTE_ATTEMPTS = "attempts";
  private static final String NOTE_CREATED_AT = "createdAt";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
    String email = MagicLink.trimToNull(params.getFirst(FORM_PARAM_USERNAME));

    if (email == null || !MagicLink.isValidEmail(email)) {
      context.getEvent().event(EventType.LOGIN_ERROR).error(Errors.INVALID_EMAIL);
      failure(
          context,
          AuthenticationFlowError.INVALID_USER,
          Response.Status.BAD_REQUEST,
          "invalid_request",
          "A valid email is required in the username parameter.");
      return;
    }

    EventBuilder event = context.newEvent();
    UserModel user =
        MagicLink.getOrCreate(
            context.getSession(),
            context.getRealm(),
            email,
            isForceCreate(context),
            false,
            false,
            MagicLink.registerEvent(event, EMAIL_OTP));

    if (user == null || MagicLink.trimToNull(user.getEmail()) == null) {
      // Same response as otp_sent would leak nothing, but with force-create enabled the
      // only way to get here is a non-creatable identifier — report it as invalid.
      context.getEvent().event(EventType.LOGIN_ERROR).error(Errors.USER_NOT_FOUND);
      failure(
          context,
          AuthenticationFlowError.INVALID_USER,
          Response.Status.UNAUTHORIZED,
          "invalid_grant",
          "Invalid user credentials.");
      return;
    }

    context.getEvent().user(user).event(EventType.LOGIN);

    if (!user.isEnabled()) {
      context.getEvent().error(Errors.USER_DISABLED);
      failure(
          context,
          AuthenticationFlowError.INVALID_USER,
          Response.Status.UNAUTHORIZED,
          "invalid_grant",
          "Invalid user credentials.");
      return;
    }

    String bruteForceError = AuthenticatorUtils.getDisabledByBruteForceEventError(context, user);
    if (bruteForceError != null) {
      context.getEvent().error(bruteForceError);
      failure(
          context,
          AuthenticationFlowError.INVALID_USER,
          Response.Status.UNAUTHORIZED,
          "invalid_grant",
          "Invalid user credentials.");
      return;
    }

    String otp = MagicLink.trimToNull(params.getFirst(FORM_PARAM_OTP_CODE));
    if (otp == null) {
      sendOtp(context, user);
    } else {
      validateOtp(context, user, otp);
    }
  }

  private void sendOtp(AuthenticationFlowContext context, UserModel user) {
    SingleUseObjectProvider store = context.getSession().singleUseObjects();
    String key = storeKey(context.getRealm(), user);

    Map<String, String> existing = store.get(key);
    if (existing != null && withinResendCooldown(context, existing)) {
      log.debugf("OTP resend throttled for user %s", user.getId());
      challenge(
          context,
          ERROR_OTP_SENT,
          "A code was recently sent to your email. Wait before requesting another.");
      return;
    }

    String code = SecretGenerator.getInstance().randomString(OTP_LENGTH, SecretGenerator.DIGITS);

    Map<String, String> notes = new HashMap<>();
    notes.put(NOTE_CODE, code);
    notes.put(NOTE_ATTEMPTS, "0");
    notes.put(NOTE_CREATED_AT, Integer.toString(Time.currentTime()));

    if (existing != null) {
      store.remove(key);
    }
    store.put(key, otpTtlSeconds(context), notes);

    boolean sent = MagicLink.sendOtpEmail(context.getSession(), user, code);
    if (!sent) {
      store.remove(key);
      log.errorf("Failed to send OTP email for user %s", user.getId());
      context.getEvent().error(Errors.EMAIL_SEND_FAILED);
      failure(
          context,
          AuthenticationFlowError.INTERNAL_ERROR,
          Response.Status.INTERNAL_SERVER_ERROR,
          "server_error",
          "Failed to send the OTP email.");
      return;
    }

    log.debugf("Sent direct grant OTP code to email for user %s", user.getId());
    challenge(context, ERROR_OTP_SENT, "An OTP code has been sent to your email.");
  }

  private void validateOtp(AuthenticationFlowContext context, UserModel user, String otp) {
    SingleUseObjectProvider store = context.getSession().singleUseObjects();
    String key = storeKey(context.getRealm(), user);

    Map<String, String> notes = store.get(key);
    if (notes == null) {
      context.getEvent().error(Errors.EXPIRED_CODE);
      failure(
          context,
          AuthenticationFlowError.EXPIRED_CODE,
          Response.Status.UNAUTHORIZED,
          ERROR_OTP_EXPIRED,
          "The OTP code has expired or was never requested. Request a new code.");
      return;
    }

    int attempts = Integer.parseInt(notes.getOrDefault(NOTE_ATTEMPTS, "0"));
    if (attempts >= otpMaxAttempts(context)) {
      store.remove(key);
      context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
      failure(
          context,
          AuthenticationFlowError.INVALID_CREDENTIALS,
          Response.Status.UNAUTHORIZED,
          ERROR_OTP_MAX_ATTEMPTS,
          "Too many incorrect attempts. Request a new code.");
      return;
    }

    String expected = notes.get(NOTE_CODE);
    boolean valid =
        expected != null
            && MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), otp.getBytes(StandardCharsets.UTF_8));

    if (!valid) {
      Map<String, String> updated = new HashMap<>(notes);
      updated.put(NOTE_ATTEMPTS, Integer.toString(attempts + 1));
      store.replace(key, updated);

      context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
      failure(
          context,
          AuthenticationFlowError.INVALID_CREDENTIALS,
          Response.Status.UNAUTHORIZED,
          ERROR_INVALID_OTP,
          "Invalid OTP code.");
      return;
    }

    store.remove(key);
    user.setEmailVerified(true);
    context.setUser(user);
    context.success();
  }

  private void challenge(AuthenticationFlowContext context, String error, String description) {
    context.challenge(errorResponse(Response.Status.UNAUTHORIZED, error, description));
  }

  private void failure(
      AuthenticationFlowContext context,
      AuthenticationFlowError flowError,
      Response.Status status,
      String error,
      String description) {
    context.failure(flowError, errorResponse(status, error, description));
  }

  private Response errorResponse(Response.Status status, String error, String description) {
    return Response.status(status)
        .entity(new OAuth2ErrorRepresentation(error, description))
        .type(MediaType.APPLICATION_JSON_TYPE)
        .build();
  }

  private String storeKey(RealmModel realm, UserModel user) {
    return "direct-grant-email-otp." + realm.getId() + "." + user.getId();
  }

  private boolean withinResendCooldown(
      AuthenticationFlowContext context, Map<String, String> notes) {
    int createdAt = Integer.parseInt(notes.getOrDefault(NOTE_CREATED_AT, "0"));
    return Time.currentTime() - createdAt < otpResendCooldownSeconds(context);
  }

  private boolean isForceCreate(AuthenticationFlowContext context) {
    return is(context, CREATE_NONEXISTENT_USER_CONFIG_PROPERTY, false);
  }

  private int otpTtlSeconds(AuthenticationFlowContext context) {
    return configInt(context, CONFIG_OTP_TTL_SECONDS, DEFAULT_OTP_TTL_SECONDS);
  }

  private int otpMaxAttempts(AuthenticationFlowContext context) {
    return configInt(context, CONFIG_OTP_MAX_ATTEMPTS, DEFAULT_OTP_MAX_ATTEMPTS);
  }

  private int otpResendCooldownSeconds(AuthenticationFlowContext context) {
    return configInt(context, CONFIG_OTP_RESEND_COOLDOWN_SECONDS, DEFAULT_OTP_RESEND_COOLDOWN_SECONDS);
  }

  private int configInt(AuthenticationFlowContext context, String name, int defaultValue) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    if (config == null || config.getConfig() == null) {
      return defaultValue;
    }
    String value = MagicLink.trimToNull(config.getConfig().get(name));
    if (value == null) {
      return defaultValue;
    }
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      log.warnf("Invalid integer for config %s: %s — using default %d", name, value, defaultValue);
      return defaultValue;
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    // Direct grant flows are single-request; all work happens in authenticate().
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public void close() {}
}
