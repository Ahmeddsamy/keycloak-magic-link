package io.phasetwo.keycloak.magic.auth;

import io.phasetwo.keycloak.magic.auth.util.PhoneOtpSendLimits;
import io.phasetwo.keycloak.magic.auth.util.PhoneSupport;
import io.phasetwo.keycloak.magic.auth.util.SingleUseCounterStore;
import io.phasetwo.keycloak.magic.auth.util.SupportedMobile;
import io.phasetwo.keycloak.magic.otp.OtpChannel;
import io.phasetwo.keycloak.magic.otp.OtpCheckOutcome;
import io.phasetwo.keycloak.magic.otp.OtpConfig;
import io.phasetwo.keycloak.magic.otp.OtpProviderException;
import io.phasetwo.keycloak.magic.otp.OtpProviderFailure;
import io.phasetwo.keycloak.magic.otp.OtpSendResult;
import io.phasetwo.keycloak.magic.otp.OtpService;
import io.phasetwo.keycloak.magic.otp.OtpServiceFactory;
import io.phasetwo.keycloak.magic.otp.PhoneMasking;
import io.phasetwo.keycloak.magic.otp.PhoneOtpSender;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Locale;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.common.util.Time;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Phone-number + OTP browser authenticator for agents ({@code ext-phone-otp}).
 *
 * <p>Two pages: {@code phone-form.ftl} (country + number) and {@code phone-otp-form.ftl} (code).
 * The code itself is owned by the OTP provider (Cequens); this authenticator keeps only the
 * provider's check code, in server-side auth notes that never reach the browser.
 *
 * <p>Security properties:
 *
 * <ul>
 *   <li>Only Saudi/Egyptian mobiles (same rules as the backend and the app).
 *   <li>No user enumeration and no junk accounts: the phone page answers the same for every number,
 *       and a user is looked up / created only after the code passed.
 *   <li>Per code: {@code max-attempts} tries, then the code is burned. Wrong codes go through
 *       {@code failureChallenge}, so realm brute-force protection counts them.
 *   <li>Per phone (any browser, any node): hourly/daily send caps in the cluster store.
 *   <li>Escalating resend cooldown; resends go by SMS; WhatsApp rejection falls back to SMS.
 *   <li>Logs carry only the masked phone, the failure class and the provider request id.
 * </ul>
 */
@JBossLog
public class PhoneOtpAuthenticator extends UsernamePasswordForm {

  static final String FORM_PARAM_COUNTRY = "country";
  static final String FORM_PARAM_PHONE = "phone";
  static final String FORM_PARAM_OTP = "otp";
  static final String FORM_PARAM_RESEND = "resend";
  static final String FORM_PARAM_BACK = "back";

  static final String NOTE_PHONE = "phone-otp-phone";
  static final String NOTE_CHECK_CODE = "phone-otp-check-code";
  static final String NOTE_CHANNEL = "phone-otp-channel";
  static final String NOTE_SENT_AT = "phone-otp-sent-at";
  static final String NOTE_SEND_COUNT = "phone-otp-send-count";
  static final String NOTE_ATTEMPTS = "phone-otp-attempts";
  private static final List<String> ALL_NOTES =
      List.of(
          NOTE_PHONE, NOTE_CHECK_CODE, NOTE_CHANNEL, NOTE_SENT_AT, NOTE_SEND_COUNT, NOTE_ATTEMPTS);

  static final String PHONE_FORM = "phone-form.ftl";
  static final String CODE_FORM = "phone-otp-form.ftl";

  static final String MSG_INVALID_PHONE = "phoneOtpInvalidPhone";
  static final String MSG_INVALID_CODE = "phoneOtpInvalidCode";
  static final String MSG_EXPIRED = "phoneOtpExpired";
  static final String MSG_TOO_MANY_ATTEMPTS = "phoneOtpTooManyAttempts";
  static final String MSG_RATE_LIMITED = "phoneOtpRateLimited";
  static final String MSG_RESEND_TOO_SOON = "phoneOtpResendTooSoon";
  static final String MSG_PROVIDER_UNAVAILABLE = "phoneOtpProviderUnavailable";
  static final String MSG_LOGIN_FAILED = "phoneOtpLoginFailed";

  private static final String EVENT_DETAIL_CHANNEL = "otp_channel";
  private static final String EVENT_DETAIL_OUTCOME = "otp_outcome";
  private static final String LOCALE_AR = "ar";
  private static final String LOCALE_EN = "en";
  private static final int SECONDS_PER_MINUTE = 60;

  private PhoneOtpSettings settings = PhoneOtpSettings.from(null);

  // ---------------------------------------------------------------------------
  // Flow entry points
  // ---------------------------------------------------------------------------

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    settings = PhoneOtpSettings.from(context.getAuthenticatorConfig());
    // A refresh never re-sends: with a phone noted, show the code page again.
    if (note(context, NOTE_PHONE) == null) {
      context.challenge(phoneForm(context, null, null, null));
    } else {
      context.challenge(codeForm(context, null));
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    settings = PhoneOtpSettings.from(context.getAuthenticatorConfig());
    MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();

    if (form.containsKey(FORM_PARAM_BACK)) {
      clearNotes(context);
      context.challenge(phoneForm(context, null, null, null));
      return;
    }
    String phone = note(context, NOTE_PHONE);
    if (phone == null) {
      submitPhone(context, form.getFirst(FORM_PARAM_COUNTRY), form.getFirst(FORM_PARAM_PHONE));
    } else if (form.containsKey(FORM_PARAM_RESEND)) {
      resend(context, phone);
    } else {
      submitCode(context, phone, form.getFirst(FORM_PARAM_OTP));
    }
  }

  // ---------------------------------------------------------------------------
  // Phone page
  // ---------------------------------------------------------------------------

  private void submitPhone(AuthenticationFlowContext context, String countryIso, String raw) {
    SupportedMobile.Country selected = SupportedMobile.Country.fromIso(countryIso);
    if (selected == null || !settings.allowedCountries().contains(selected)) {
      selected = settings.defaultCountry();
    }
    String phone = SupportedMobile.normalize(raw, selected);
    SupportedMobile.Country country = SupportedMobile.countryOf(phone);
    if (phone == null || !settings.allowedCountries().contains(country)) {
      context.getEvent().error(Errors.INVALID_INPUT);
      context.challenge(phoneForm(context, MSG_INVALID_PHONE, selected, raw));
      return;
    }
    context.getAuthenticationSession().setAuthNote(NOTE_PHONE, phone);
    sendCode(context, phone, false);
  }

  // ---------------------------------------------------------------------------
  // Sending
  // ---------------------------------------------------------------------------

  private void resend(AuthenticationFlowContext context, String phone) {
    long wait = resendWaitSeconds(context);
    if (wait > 0) {
      context.challenge(codeForm(context, error(MSG_RESEND_TOO_SOON, wait)));
      return;
    }
    sendCode(context, phone, true);
  }

  private void sendCode(AuthenticationFlowContext context, String phone, boolean isResend) {
    PhoneOtpSendLimits limits = limits(context);
    long retryAfter = limits.retryAfterSeconds(phone);
    if (retryAfter > 0) {
      log.infof("ext-phone-otp: send cap reached for %s", PhoneMasking.mask(phone));
      context.getEvent().detail(EVENT_DETAIL_OUTCOME, "rate_limited").error(Errors.SLOW_DOWN);
      long minutes = Math.max(1, (retryAfter + SECONDS_PER_MINUTE - 1) / SECONDS_PER_MINUTE);
      sendFailed(context, isResend, error(MSG_RATE_LIMITED, minutes), null);
      return;
    }

    OtpSendResult sent;
    try {
      sent =
          new PhoneOtpSender(otpService())
              .send(
                  phone,
                  settings.primaryChannel(),
                  settings.resendChannel(),
                  isResend,
                  locale(context),
                  settings.codeLength(),
                  OtpConfig.fromEnv().codeExpiryMinutes);
    } catch (OtpProviderException e) {
      log.warnf(
          "ext-phone-otp: send to %s failed: %s requestId=%s",
          PhoneMasking.mask(phone), e.failure(), e.requestId());
      context.getEvent().detail(EVENT_DETAIL_OUTCOME, "failed:" + e.failure());
      if (e.failure() == OtpProviderFailure.INVALID_RECIPIENT) {
        clearNotes(context);
        context.challenge(phoneForm(context, MSG_INVALID_PHONE, null, null));
        return;
      }
      sendFailed(context, isResend, error(MSG_PROVIDER_UNAVAILABLE), e);
      return;
    } catch (IllegalStateException e) {
      // Provider misconfigured; already logged with an alert by the factory.
      sendFailed(context, isResend, error(MSG_PROVIDER_UNAVAILABLE), null);
      return;
    }

    AuthenticationSessionModel session = context.getAuthenticationSession();
    session.setAuthNote(NOTE_CHECK_CODE, sent.checkCode());
    session.setAuthNote(NOTE_CHANNEL, sent.channel().configValue());
    session.setAuthNote(NOTE_SENT_AT, Integer.toString(Time.currentTime()));
    session.setAuthNote(NOTE_SEND_COUNT, Integer.toString(intNote(context, NOTE_SEND_COUNT) + 1));
    session.setAuthNote(NOTE_ATTEMPTS, "0");
    limits.recordSend(phone);
    context
        .getEvent()
        .detail(EVENT_DETAIL_CHANNEL, sent.channel().configValue())
        .detail(EVENT_DETAIL_OUTCOME, "sent");
    context.challenge(codeForm(context, null));
  }

  /** A failed first send returns to the phone page; a failed resend stays on the code page. */
  private void sendFailed(
      AuthenticationFlowContext context, boolean isResend, PageError error, Exception cause) {
    if (isResend) {
      context.challenge(codeForm(context, error));
      return;
    }
    clearNotes(context);
    LoginFormsProvider form = basePhoneForm(context, null, null);
    form.setError(error.key(), error.args());
    context.challenge(form.createForm(PHONE_FORM));
  }

  // ---------------------------------------------------------------------------
  // Checking
  // ---------------------------------------------------------------------------

  private void submitCode(AuthenticationFlowContext context, String phone, String rawCode) {
    String checkCode = note(context, NOTE_CHECK_CODE);
    if (checkCode == null) {
      context.challenge(codeForm(context, error(MSG_EXPIRED)));
      return;
    }
    String code = rawCode == null ? "" : SupportedMobile.toAsciiDigits(rawCode.trim());
    if (!code.matches("\\d{" + settings.codeLength() + "}")) {
      context.challenge(codeForm(context, error(MSG_INVALID_CODE, attemptsRemaining(context))));
      return;
    }

    // Reserve the attempt before asking the provider.
    int attempts = intNote(context, NOTE_ATTEMPTS) + 1;
    if (attempts > settings.maxAttempts()) {
      burnCode(context);
      context.challenge(codeForm(context, error(MSG_TOO_MANY_ATTEMPTS)));
      return;
    }
    context.getAuthenticationSession().setAuthNote(NOTE_ATTEMPTS, Integer.toString(attempts));

    OtpCheckOutcome outcome;
    try {
      outcome = otpService().check(checkCode, code);
    } catch (OtpProviderException | IllegalStateException e) {
      // The provider couldn't answer: the attempt doesn't count.
      context.getAuthenticationSession().setAuthNote(NOTE_ATTEMPTS, Integer.toString(attempts - 1));
      log.warnf("ext-phone-otp: check for %s could not complete", PhoneMasking.mask(phone));
      context.challenge(codeForm(context, error(MSG_PROVIDER_UNAVAILABLE)));
      return;
    }
    context.getEvent().detail(EVENT_DETAIL_OUTCOME, outcome.name().toLowerCase(Locale.ROOT));

    switch (outcome) {
      case VALID -> completeLogin(context, phone);
      case INVALID -> wrongCode(context, phone);
      case EXPIRED -> {
        burnCode(context);
        context.challenge(codeForm(context, error(MSG_EXPIRED)));
      }
      case EXHAUSTED, ALREADY_USED -> {
        burnCode(context);
        context.challenge(codeForm(context, error(MSG_TOO_MANY_ATTEMPTS)));
      }
    }
  }

  private void wrongCode(AuthenticationFlowContext context, String phone) {
    int remaining = attemptsRemaining(context);
    if (remaining == 0) burnCode(context);
    PageError pageError =
        remaining == 0 ? error(MSG_TOO_MANY_ATTEMPTS) : error(MSG_INVALID_CODE, remaining);

    // Let realm brute-force protection count the failure against an existing account.
    UserModel existing = PhoneSupport.findByPhone(context.getSession(), context.getRealm(), phone);
    if (existing != null) context.setUser(existing);
    context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
    context.failureChallenge(
        AuthenticationFlowError.INVALID_CREDENTIALS, codeForm(context, pageError));
  }

  private void completeLogin(AuthenticationFlowContext context, String phone) {
    UserModel user = PhoneSupport.findByPhone(context.getSession(), context.getRealm(), phone);
    if (user == null && settings.createUsers()) {
      user = PhoneSupport.create(context.getSession(), context.getRealm(), phone, settings.role());
    }
    if (user == null) {
      clearNotes(context);
      context.getEvent().error(Errors.USER_NOT_FOUND);
      LoginFormsProvider form = basePhoneForm(context, null, null);
      form.setError(MSG_LOGIN_FAILED);
      context.challenge(form.createForm(PHONE_FORM));
      return;
    }

    context.getEvent().user(user).event(EventType.LOGIN);
    if (!user.isEnabled()) {
      // Same generic message as an unknown number — never "account disabled".
      clearNotes(context);
      context.getEvent().error(Errors.USER_DISABLED);
      LoginFormsProvider form = basePhoneForm(context, null, null);
      form.setError(MSG_LOGIN_FAILED);
      context.challenge(form.createForm(PHONE_FORM));
      return;
    }
    // Brute-force lockout (temporary): enabledUser() shows Keycloak's standard message.
    if (!enabledUser(context, user)) {
      clearNotes(context);
      return;
    }
    PhoneSupport.markVerified(user, phone);
    context.setUser(user);
    clearNotes(context);
    context.success();
  }

  // ---------------------------------------------------------------------------
  // Pages
  // ---------------------------------------------------------------------------

  /** A page error: message key + arguments. */
  private record PageError(String key, Object... args) {}

  private static PageError error(String key, Object... args) {
    return new PageError(key, args);
  }

  private Response phoneForm(
      AuthenticationFlowContext context,
      String fieldError,
      SupportedMobile.Country selected,
      String typed) {
    LoginFormsProvider form = basePhoneForm(context, selected, typed);
    if (fieldError != null) form.addError(new FormMessage(FORM_PARAM_PHONE, fieldError));
    return form.createForm(PHONE_FORM);
  }

  private LoginFormsProvider basePhoneForm(
      AuthenticationFlowContext context, SupportedMobile.Country selected, String typed) {
    SupportedMobile.Country country = selected == null ? settings.defaultCountry() : selected;
    LoginFormsProvider form =
        context
            .form()
            .setExecution(context.getExecution().getId())
            .setAttribute("allowedCountries", settings.allowedCountryCodes())
            .setAttribute("selectedCountry", country.name())
            .setAttribute("codeLength", settings.codeLength());
    if (typed != null) form.setAttribute("phoneInput", typed);
    return form;
  }

  private Response codeForm(AuthenticationFlowContext context, PageError pageError) {
    String phone = note(context, NOTE_PHONE);
    LoginFormsProvider form =
        context
            .form()
            .setExecution(context.getExecution().getId())
            .setAttribute("phoneNumber", phone)
            .setAttribute("maskedPhone", PhoneMasking.mask(phone))
            .setAttribute(
                "channel",
                OtpChannel.fromConfig(note(context, NOTE_CHANNEL), OtpChannel.SMS).configValue())
            .setAttribute("codeLength", settings.codeLength())
            .setAttribute("codeUsable", note(context, NOTE_CHECK_CODE) != null)
            .setAttribute("attemptsRemaining", attemptsRemaining(context))
            .setAttribute("resendAvailableInSeconds", resendWaitSeconds(context));
    if (pageError != null) form.setError(pageError.key(), pageError.args());
    return form.createForm(CODE_FORM);
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private long resendWaitSeconds(AuthenticationFlowContext context) {
    int sentAt = intNote(context, NOTE_SENT_AT);
    if (sentAt == 0) return 0;
    long cooldown = settings.cooldownAfter(intNote(context, NOTE_SEND_COUNT));
    return Math.max(0, sentAt + cooldown - Time.currentTime());
  }

  private int attemptsRemaining(AuthenticationFlowContext context) {
    return Math.max(0, settings.maxAttempts() - intNote(context, NOTE_ATTEMPTS));
  }

  private void burnCode(AuthenticationFlowContext context) {
    context.getAuthenticationSession().removeAuthNote(NOTE_CHECK_CODE);
  }

  private void clearNotes(AuthenticationFlowContext context) {
    ALL_NOTES.forEach(context.getAuthenticationSession()::removeAuthNote);
  }

  private PhoneOtpSendLimits limits(AuthenticationFlowContext context) {
    return new PhoneOtpSendLimits(
        new SingleUseCounterStore(context.getSession().singleUseObjects()),
        context.getRealm().getId(),
        settings.maxSendsPerPhoneHour(),
        settings.maxSendsPerPhoneDay(),
        Time::currentTime);
  }

  /** Overridable for tests. */
  protected OtpService otpService() {
    return OtpServiceFactory.get();
  }

  private static String locale(AuthenticationFlowContext context) {
    Locale locale = context.getSession().getContext().resolveLocale(context.getUser());
    return locale != null && LOCALE_AR.equals(locale.getLanguage()) ? LOCALE_AR : LOCALE_EN;
  }

  private static String note(AuthenticationFlowContext context, String name) {
    return context.getAuthenticationSession().getAuthNote(name);
  }

  private static int intNote(AuthenticationFlowContext context, String name) {
    String value = note(context, name);
    if (value == null) return 0;
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      return 0;
    }
  }

  // ---------------------------------------------------------------------------
  // UsernamePasswordForm hooks (used by enabledUser() for disabled / locked users)
  // ---------------------------------------------------------------------------

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  protected Response createLoginForm(LoginFormsProvider form) {
    return form.setAttribute("allowedCountries", settings.allowedCountryCodes())
        .setAttribute("selectedCountry", settings.defaultCountry().name())
        .createForm(PHONE_FORM);
  }

  @Override
  protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
    return MSG_LOGIN_FAILED;
  }
}
