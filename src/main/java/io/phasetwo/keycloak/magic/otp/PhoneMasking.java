package io.phasetwo.keycloak.magic.otp;

/** Masks phone numbers for logging — never log a full number. */
public final class PhoneMasking {

  private PhoneMasking() {}

  public static String mask(String phone) {
    if (phone == null || phone.length() < 4) {
      return "***";
    }
    return "***" + phone.substring(phone.length() - 3);
  }
}
