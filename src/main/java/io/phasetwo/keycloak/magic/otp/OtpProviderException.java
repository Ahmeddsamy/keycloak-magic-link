package io.phasetwo.keycloak.magic.otp;

/** A classified provider failure. Never carries the code, the check code or the full phone. */
public class OtpProviderException extends Exception {

  private final OtpProviderFailure failure;
  private final int httpStatus;
  private final String requestId;

  public OtpProviderException(OtpProviderFailure failure) {
    this(failure, 0, null);
  }

  public OtpProviderException(OtpProviderFailure failure, int httpStatus, String requestId) {
    super(
        "OTP provider failure: " + failure + (httpStatus > 0 ? " (HTTP " + httpStatus + ")" : ""));
    this.failure = failure;
    this.httpStatus = httpStatus;
    this.requestId = requestId;
  }

  public OtpProviderFailure failure() {
    return failure;
  }

  /** HTTP status from the provider, or 0 when there was no response. */
  public int httpStatus() {
    return httpStatus;
  }

  /** Provider request id for support tickets, or {@code null}. */
  public String requestId() {
    return requestId;
  }
}
