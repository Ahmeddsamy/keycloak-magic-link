package io.phasetwo.keycloak.magic.otp;

/** Minimal HTTP seam for {@link CequensOtpProvider}, so tests can replay recorded responses. */
public interface CequensTransport {

  /** A response; {@code body} is the raw text (may be empty or non-JSON). */
  record Response(int status, String body) {}

  /** Why no response arrived. Only {@link Kind#CONNECT} is safe to retry (nothing was sent). */
  final class TransportException extends Exception {
    public enum Kind {
      CONNECT,
      TIMEOUT,
      OTHER
    }

    private final Kind kind;

    public TransportException(Kind kind, Throwable cause) {
      super("Cequens transport failure: " + kind, cause);
      this.kind = kind;
    }

    public Kind kind() {
      return kind;
    }
  }

  /**
   * @param bearerToken {@code null} for the sign-in call
   */
  Response exchange(String method, String path, String jsonBody, String bearerToken)
      throws TransportException;
}
