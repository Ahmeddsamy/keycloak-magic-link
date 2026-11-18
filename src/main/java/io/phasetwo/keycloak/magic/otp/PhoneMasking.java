package io.phasetwo.keycloak.magic.otp;

/**
 * Masks phone numbers for logs: {@code +9665****67}, same as the backend. Never log a full number.
 */
public final class PhoneMasking {

  private static final int MIN_MASKABLE_LENGTH = 6;
  private static final int VISIBLE_PREFIX = 4;
  private static final int VISIBLE_SUFFIX = 2;

  private PhoneMasking() {}

  public static String mask(String phone) {
    if (phone == null || phone.length() < MIN_MASKABLE_LENGTH) return "***";
    return phone.substring(0, VISIBLE_PREFIX)
        + "****"
        + phone.substring(phone.length() - VISIBLE_SUFFIX);
  }
}
