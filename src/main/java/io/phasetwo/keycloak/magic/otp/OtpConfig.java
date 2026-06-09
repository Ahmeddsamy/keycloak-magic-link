package io.phasetwo.keycloak.magic.otp;

/**
 * OTP provider configuration, read from environment variables so the same keys are used by the
 * Keycloak runtime and the backend. Secrets (the Cequens API token) live in env only — never in
 * committed realm/config files.
 */
public final class OtpConfig {

  /** {@code mock} (default) or {@code cequens}. */
  public final String provider;

  /** Fixed code the mock provider accepts (dev/CI only). */
  public final String mockCode;

  public final String cequensBaseUrl;
  public final String cequensApiToken;
  public final String cequensSenderName;

  private OtpConfig(
      String provider,
      String mockCode,
      String cequensBaseUrl,
      String cequensApiToken,
      String cequensSenderName) {
    this.provider = provider;
    this.mockCode = mockCode;
    this.cequensBaseUrl = cequensBaseUrl;
    this.cequensApiToken = cequensApiToken;
    this.cequensSenderName = cequensSenderName;
  }

  public static OtpConfig fromEnv() {
    return new OtpConfig(
        env("OTP_PROVIDER", "mock"),
        env("OTP_MOCK_CODE", "000000"),
        env("CEQUENS_API_BASE_URL", null),
        env("CEQUENS_API_TOKEN", null),
        env("CEQUENS_VERIFY_SENDER_NAME", null));
  }

  private static String env(String key, String def) {
    String v = System.getenv(key);
    return (v == null || v.isBlank()) ? def : v;
  }
}
