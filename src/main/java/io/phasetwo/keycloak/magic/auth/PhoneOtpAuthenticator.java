package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;
import static io.phasetwo.keycloak.magic.auth.PhoneOtpAuthenticatorFactory.CHANNEL_CONFIG_PROPERTY;
import static io.phasetwo.keycloak.magic.auth.PhoneOtpAuthenticatorFactory.ROLE_CONFIG_PROPERTY;
import static io.phasetwo.keycloak.magic.auth.util.Authenticators.get;
import static io.phasetwo.keycloak.magic.auth.util.Authenticators.is;

import io.phasetwo.keycloak.magic.auth.util.PhoneSupport;
import io.phasetwo.keycloak.magic.otp.OtpService;
import io.phasetwo.keycloak.magic.otp.OtpServiceFactory;
import io.phasetwo.keycloak.magic.otp.PhoneMasking;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

/**
 * Phone-number + OTP browser authenticator.
 *
 * <p>Mirrors {@link EmailOtpAuthenticator}'s self-rendered-form + JIT-create pattern, but identity
 * is the phone number and the code is owned by a managed OTP provider ({@link OtpService}) — we
 * never generate or store a code here. Two forms: a phone-number input, then a code input. Bind to
 * the agent client only via a per-client browser-flow override.
 */
@JBossLog
public class PhoneOtpAuthenticator extends UsernamePasswordForm {

  public static final String FORM_PARAM_PHONE = "phone";
  public static final String FORM_PARAM_OTP = "otp";

  // Normalized E.164 phone for this attempt.
  static final String AUTH_NOTE_PHONE = "phone-otp-phone";
  // Present once an OTP has been sent → the next action is a code submission.
  static final String AUTH_NOTE_SENT = "phone-otp-sent";

  private static final String DEFAULT_CHANNEL = "whatsapp";
  private static final String DEFAULT_ROLE = "agent";

  private static final String PHONE_FORM = "phone-form.ftl";
  private static final String CODE_FORM = "phone-otp-form.ftl";
  private static final String MSG_INVALID_PHONE = "invalidPhoneNumber";
  private static final String MSG_OTP_SEND_FAILED = "otpSendFailed";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    String phone = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_PHONE);
    if (phone == null) {
      context.challenge(phoneForm(context, null));
    } else {
      // Resumed mid-flow with a known phone — (re)send and show the code form.
      startAndChallenge(context, phone);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    String phone = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_PHONE);

    // Resend from the code form.
    if (formData.containsKey("resend") && phone != null) {
      context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_SENT);
      startAndChallenge(context, phone);
      return;
    }

    boolean alreadySent = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_SENT) != null;
    if (alreadySent && phone != null) {
      validateCode(context, formData, phone);
      return;
    }

    // Phone-input form submission.
    String normalized = PhoneSupport.normalizeE164(formData.getFirst(FORM_PARAM_PHONE));
    if (normalized == null) {
      context.getEvent().error(Errors.INVALID_REGISTRATION);
      context.forceChallenge(phoneForm(context, MSG_INVALID_PHONE));
      return;
    }

    boolean forceCreate = is(context, CREATE_NONEXISTENT_USER_CONFIG_PROPERTY, false);
    UserModel user =
        PhoneSupport.findOrCreate(
            context.getSession(), context.getRealm(), normalized, forceCreate, role(context));
    if (user == null) {
      context.getEvent().event(EventType.LOGIN_ERROR).error(Errors.USER_NOT_FOUND);
      context.forceChallenge(phoneForm(context, MSG_INVALID_PHONE));
      return;
    }

    // Set the event type before enabledUser() — a disabled user triggers
    // EventBuilder.error(USER_DISABLED), which throws if no type is set
    // (same guard as EmailOtpAuthenticator).
    context.getEvent().user(user).event(EventType.LOGIN);
    if (!enabledUser(context, user)) {
      return;
    }

    context.setUser(user);
    context.getAuthenticationSession().setAuthNote(AUTH_NOTE_PHONE, normalized);
    startAndChallenge(context, normalized);
  }

  private void startAndChallenge(AuthenticationFlowContext context, String phone) {
    try {
      OtpService otp = OtpServiceFactory.create();
      otp.start(phone, channel(context));
      context.getAuthenticationSession().setAuthNote(AUTH_NOTE_SENT, "1");
    } catch (Exception e) {
      log.warnf(
          "ext-phone-otp: failed to send OTP to %s: %s", PhoneMasking.mask(phone), e.getMessage());
      context.forceChallenge(codeForm(context, phone, MSG_OTP_SEND_FAILED));
      return;
    }
    context.challenge(codeForm(context, phone, null));
  }

  private void validateCode(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData, String phone) {
    UserModel user = context.getUser();
    if (user == null) {
      context.getEvent().event(EventType.LOGIN_ERROR).error(Errors.USER_NOT_FOUND);
      context.failure(AuthenticationFlowError.INVALID_USER);
      return;
    }

    String code = formData.getFirst(FORM_PARAM_OTP);
    boolean valid;
    try {
      valid = code != null && OtpServiceFactory.create().check(phone, code);
    } catch (Exception e) {
      log.warnf(
          "ext-phone-otp: OTP check failed for %s: %s", PhoneMasking.mask(phone), e.getMessage());
      context.forceChallenge(codeForm(context, phone, MSG_OTP_SEND_FAILED));
      return;
    }

    if (valid) {
      PhoneSupport.markVerified(user);
      context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_SENT);
      context.success();
      return;
    }

    context.getEvent().user(user).event(EventType.LOGIN_ERROR).error(Errors.INVALID_CODE);
    context.forceChallenge(codeForm(context, phone, Messages.INVALID_ACCESS_CODE));
  }

  private Response phoneForm(AuthenticationFlowContext context, String error) {
    LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
    if (error != null) {
      form.setError(error);
    }
    return form.createForm(PHONE_FORM);
  }

  private Response codeForm(AuthenticationFlowContext context, String phone, String error) {
    LoginFormsProvider form =
        context
            .form()
            .setExecution(context.getExecution().getId())
            .setAttribute("phoneNumber", phone);
    if (error != null) {
      form.setError(error);
    }
    return form.createForm(CODE_FORM);
  }

  private String channel(AuthenticationFlowContext context) {
    return get(context, CHANNEL_CONFIG_PROPERTY, DEFAULT_CHANNEL);
  }

  private String role(AuthenticationFlowContext context) {
    return get(context, ROLE_CONFIG_PROPERTY, DEFAULT_ROLE);
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  protected Response createLoginForm(LoginFormsProvider form) {
    return form.createForm(PHONE_FORM);
  }

  @Override
  protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
    return MSG_INVALID_PHONE;
  }
}
