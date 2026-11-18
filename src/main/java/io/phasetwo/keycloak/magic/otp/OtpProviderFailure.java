package io.phasetwo.keycloak.magic.otp;

/** Classified provider failures. Same names as the backend and the shared fixtures. */
public enum OtpProviderFailure {
  /** Provider rejected the phone number format. */
  INVALID_RECIPIENT,
  /** Channel not enabled for the account (e.g. WhatsApp not provisioned). */
  CHANNEL_UNAVAILABLE,
  /** Account out of credit. Page on-call. */
  NO_CREDIT,
  /** Credentials / token rejected even after re-authenticating. Page on-call. */
  PROVIDER_AUTH,
  /** Our request or the account setup is wrong (template, privileges). Page on-call. */
  MISCONFIGURED,
  /** Network error, timeout or 5xx. Transient. */
  UNAVAILABLE,
  /** A response we don't understand. Fail closed. */
  UNEXPECTED_RESPONSE;

  /** Failures that need a human (credit, credentials, account setup), not a retry. */
  public boolean isCritical() {
    return this == NO_CREDIT || this == PROVIDER_AUTH || this == MISCONFIGURED;
  }
}
