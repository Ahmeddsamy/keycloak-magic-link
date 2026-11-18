package io.phasetwo.keycloak.magic.otp;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * OTP provider configuration from environment variables. The names match the parcelo-backend so one
 * secret set serves both runtimes. Secrets live in env only — never in realm/config files.
 */
public final class OtpConfig {

  public static final String PROVIDER_CEQUENS = "cequens";
  public static final String PROVIDER_MOCK = "mock";

  private static final String WHATSAPP_TEMPLATE_PREFIX = "verify_";
  private static final String HTTPS_PREFIX = "https://";

  /** {@code mock} (default) or {@code cequens}. */
  public final String provider;

  /** Code the mock provider accepts (dev only). */
  public final String mockCode;

  public final int codeExpiryMinutes;

  public final String cequensBaseUrl;

  /** Long-lived console token used as-is (no sign-in); {@code null} to sign in with the API key. */
  public final String cequensAccessToken;

  public final String cequensUserName;
  public final String cequensApiKey;
  public final String whatsappTemplateName;
  public final String smsTemplateCodeEn;
  public final String smsTemplateCodeAr;
  public final int timeoutMs;
  public final int tokenTtlSeconds;

  OtpConfig(Function<String, String> env) {
    this.provider = value(env, "OTP_PROVIDER", PROVIDER_MOCK).toLowerCase();
    this.mockCode = value(env, "OTP_MOCK_CODE", "0000");
    this.codeExpiryMinutes = intValue(env, "OTP_CODE_EXPIRY_MINUTES", 5);
    this.cequensBaseUrl =
        stripTrailingSlash(value(env, "CEQUENS_BASE_URL", "https://apis.cequens.com"));
    this.cequensAccessToken = value(env, "CEQUENS_ACCESS_TOKEN", null);
    this.cequensUserName = value(env, "CEQUENS_USERNAME", null);
    this.cequensApiKey = value(env, "CEQUENS_API_KEY", null);
    this.whatsappTemplateName = value(env, "CEQUENS_WHATSAPP_TEMPLATE_NAME", null);
    this.smsTemplateCodeEn = value(env, "CEQUENS_SMS_TEMPLATE_CODE_EN", null);
    this.smsTemplateCodeAr = value(env, "CEQUENS_SMS_TEMPLATE_CODE_AR", null);
    this.timeoutMs = intValue(env, "CEQUENS_TIMEOUT_MS", 8000);
    this.tokenTtlSeconds = intValue(env, "CEQUENS_TOKEN_TTL_SECONDS", 3600);
  }

  public static OtpConfig fromEnv() {
    return new OtpConfig(System::getenv);
  }

  public boolean isCequens() {
    return PROVIDER_CEQUENS.equals(provider);
  }

  /**
   * WhatsApp needs an approved authentication template. Until one is configured, codes go by SMS
   * instead of a call that can only fail. The mock "sends" anything.
   */
  public boolean whatsappReady() {
    return !isCequens() || whatsappTemplateName != null;
  }

  /** SMS template for {@code locale}, or {@code null} to use the account default. */
  public String smsTemplateCode(String locale) {
    return "ar".equals(locale) ? smsTemplateCodeAr : smsTemplateCodeEn;
  }

  /** Configuration problems for the selected provider; empty when usable. Never lists values. */
  public List<String> problems() {
    List<String> problems = new ArrayList<>();
    if (!PROVIDER_CEQUENS.equals(provider) && !PROVIDER_MOCK.equals(provider)) {
      problems.add("OTP_PROVIDER must be 'cequens' or 'mock'");
    }
    if (!isCequens()) {
      return problems;
    }
    if (cequensAccessToken == null) {
      if (cequensUserName == null) problems.add("CEQUENS_USERNAME is not set");
      if (cequensApiKey == null) problems.add("CEQUENS_API_KEY is not set");
    }
    if (!cequensBaseUrl.startsWith(HTTPS_PREFIX)) problems.add("CEQUENS_BASE_URL must be https");
    // Optional: without it every code goes by SMS (see whatsappReady()).
    if (whatsappTemplateName != null
        && !whatsappTemplateName.startsWith(WHATSAPP_TEMPLATE_PREFIX)) {
      problems.add("CEQUENS_WHATSAPP_TEMPLATE_NAME must start with 'verify_'");
    }
    return problems;
  }

  private static String value(Function<String, String> env, String key, String def) {
    String v = env.apply(key);
    return (v == null || v.isBlank()) ? def : v.trim();
  }

  private static int intValue(Function<String, String> env, String key, int def) {
    String v = value(env, key, null);
    if (v == null) return def;
    try {
      int parsed = Integer.parseInt(v);
      return parsed > 0 ? parsed : def;
    } catch (NumberFormatException e) {
      return def;
    }
  }

  private static String stripTrailingSlash(String url) {
    return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
  }
}
