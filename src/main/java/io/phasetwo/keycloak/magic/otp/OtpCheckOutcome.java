package io.phasetwo.keycloak.magic.otp;

/** Result of checking a code. Mirrors the backend {@code OtpCheckOutcome}. */
public enum OtpCheckOutcome {
  VALID,
  INVALID,
  EXPIRED,
  /** The provider's per-code trial limit was hit — the code is burned. */
  EXHAUSTED,
  /** The code was already used successfully — a replay; treat as a failure. */
  ALREADY_USED
}
