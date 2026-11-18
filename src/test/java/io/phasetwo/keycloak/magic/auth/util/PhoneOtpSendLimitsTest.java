package io.phasetwo.keycloak.magic.auth.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class PhoneOtpSendLimitsTest {

  private static final String PHONE = "+966501234567";

  /** In-memory store that honours lifespans against the test clock. */
  private static final class MemoryStore implements PhoneOtpSendLimits.CounterStore {
    final Map<String, long[]> entries = new HashMap<>();
    final AtomicLong clock;

    MemoryStore(AtomicLong clock) {
      this.clock = clock;
    }

    @Override
    public int get(String key) {
      long[] entry = entries.get(key);
      return entry == null || entry[1] <= clock.get() ? 0 : (int) entry[0];
    }

    @Override
    public void increment(String key, long lifespanSeconds) {
      entries.put(key, new long[] {get(key) + 1, clock.get() + lifespanSeconds});
    }
  }

  private final AtomicLong clock = new AtomicLong(10 * PhoneOtpSendLimits.DAY_SECONDS + 600);
  private final MemoryStore store = new MemoryStore(clock);
  private final PhoneOtpSendLimits limits =
      new PhoneOtpSendLimits(store, "realm", 3, 5, clock::get);

  @Test
  void allowsUpToTheHourlyCapThenSaysWhenTheWindowFrees() {
    for (int i = 0; i < 3; i++) {
      assertEquals(0, limits.retryAfterSeconds(PHONE));
      limits.recordSend(PHONE);
    }
    assertEquals(PhoneOtpSendLimits.HOUR_SECONDS - 600, limits.retryAfterSeconds(PHONE));

    clock.addAndGet(PhoneOtpSendLimits.HOUR_SECONDS);
    assertEquals(0, limits.retryAfterSeconds(PHONE));
  }

  @Test
  void dailyCapOutlastsTheHourlyWindow() {
    for (int i = 0; i < 5; i++) {
      limits.recordSend(PHONE);
      clock.addAndGet(PhoneOtpSendLimits.HOUR_SECONDS);
    }
    long wait = limits.retryAfterSeconds(PHONE);
    assertTrue(wait > PhoneOtpSendLimits.HOUR_SECONDS, "daily cap should block for hours");
  }

  @Test
  void keysNeverContainThePhoneNumber() {
    limits.recordSend(PHONE);
    assertFalse(store.entries.keySet().stream().anyMatch(k -> k.contains("501234567")));
  }

  @Test
  void numbersAreCountedSeparately() {
    for (int i = 0; i < 3; i++) limits.recordSend(PHONE);
    assertEquals(0, limits.retryAfterSeconds("+201012345678"));
  }
}
