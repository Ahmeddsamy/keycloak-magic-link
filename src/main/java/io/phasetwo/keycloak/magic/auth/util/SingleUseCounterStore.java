package io.phasetwo.keycloak.magic.auth.util;

import java.util.Map;
import org.keycloak.models.SingleUseObjectProvider;

/**
 * {@link PhoneOtpSendLimits.CounterStore} on Keycloak's cluster-wide single-use object store. Not
 * atomic across nodes (get + put); two simultaneous sends can both pass the last slot, which is
 * acceptable for a cost cap.
 */
public final class SingleUseCounterStore implements PhoneOtpSendLimits.CounterStore {

  private static final String COUNT = "count";

  private final SingleUseObjectProvider store;

  public SingleUseCounterStore(SingleUseObjectProvider store) {
    this.store = store;
  }

  @Override
  public int get(String key) {
    Map<String, String> notes = store.get(key);
    if (notes == null) return 0;
    try {
      return Integer.parseInt(notes.getOrDefault(COUNT, "0"));
    } catch (NumberFormatException e) {
      return 0;
    }
  }

  @Override
  public void increment(String key, long lifespanSeconds) {
    int next = get(key) + 1;
    // remove + put: replace() does not keep the per-entry lifespan on every store.
    store.remove(key);
    store.put(key, Math.max(1, lifespanSeconds), Map.of(COUNT, Integer.toString(next)));
  }
}
