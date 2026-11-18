package io.phasetwo.keycloak.magic.otp;

/**
 * A sent code.
 *
 * @param checkCode provider reference used to check the code; server-side only (auth note), never
 *     sent to the browser or logged
 * @param channel channel actually used
 * @param requestId provider request id for support, or {@code null}
 */
public record OtpSendResult(String checkCode, OtpChannel channel, String requestId) {

  @Override
  public String toString() {
    return "OtpSendResult[channel=" + channel + ", requestId=" + requestId + "]";
  }
}
