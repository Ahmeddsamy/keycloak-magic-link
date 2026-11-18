package io.phasetwo.keycloak.magic.auth.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.function.LongSupplier;

/**
 * Login code send caps per phone number, shared across nodes through the cluster-wide {@link
 * CounterStore}. Fixed hour and day windows; keys carry a SHA-256 of the phone, never the number.
 */
public final class PhoneOtpSendLimits {

  /** A cluster-wide counter with expiry (backed by {@code SingleUseObjectProvider}). */
  public interface CounterStore {
    int get(String key);

    /** Adds one to {@code key}, which expires after {@code lifespanSeconds}. */
    void increment(String key, long lifespanSeconds);
  }

  static final long HOUR_SECONDS = 3600;
  static final long DAY_SECONDS = 86_400;
  private static final String KEY_PREFIX = "phone-otp:sends:";

  private final CounterStore store;
  private final String realmId;
  private final int maxPerHour;
  private final int maxPerDay;
  private final LongSupplier nowSeconds;

  public PhoneOtpSendLimits(
      CounterStore store, String realmId, int maxPerHour, int maxPerDay, LongSupplier nowSeconds) {
    this.store = store;
    this.realmId = realmId;
    this.maxPerHour = maxPerHour;
    this.maxPerDay = maxPerDay;
    this.nowSeconds = nowSeconds;
  }

  /** Seconds until another code may be sent to {@code phone}; 0 when allowed now. */
  public long retryAfterSeconds(String phone) {
    long now = nowSeconds.getAsLong();
    long wait = 0;
    if (store.get(key(phone, DAY_SECONDS, now)) >= maxPerDay) {
      wait = Math.max(wait, windowEnd(DAY_SECONDS, now) - now);
    }
    if (store.get(key(phone, HOUR_SECONDS, now)) >= maxPerHour) {
      wait = Math.max(wait, windowEnd(HOUR_SECONDS, now) - now);
    }
    return wait;
  }

  /** Counts a successful send. */
  public void recordSend(String phone) {
    long now = nowSeconds.getAsLong();
    for (long window : new long[] {HOUR_SECONDS, DAY_SECONDS}) {
      store.increment(key(phone, window, now), windowEnd(window, now) - now);
    }
  }

  private String key(String phone, long windowSeconds, long now) {
    return KEY_PREFIX
        + realmId
        + ":"
        + sha256(phone)
        + ":"
        + windowSeconds
        + ":"
        + now / windowSeconds;
  }

  private static long windowEnd(long windowSeconds, long now) {
    return (now / windowSeconds + 1) * windowSeconds;
  }

  static String sha256(String value) {
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
