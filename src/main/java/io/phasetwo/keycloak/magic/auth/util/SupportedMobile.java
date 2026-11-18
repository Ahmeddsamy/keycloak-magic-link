package io.phasetwo.keycloak.magic.auth.util;

import java.util.regex.Pattern;

/**
 * Saudi Arabia and Egypt mobile numbers — the only numbers Parcelo sends codes to. Java mirror of
 * {@code @repo/shared-types} {@code phone.ts}; tested against the shared {@code
 * supported-mobile.json} vectors so Keycloak, the backend and the app agree.
 */
public final class SupportedMobile {

  /** A supported country. */
  public enum Country {
    SA("966", Pattern.compile("^5\\d{8}$")),
    EG("20", Pattern.compile("^1[0125]\\d{8}$"));

    private final String dialCode;
    private final Pattern nationalPattern;

    Country(String dialCode, Pattern nationalPattern) {
      this.dialCode = dialCode;
      this.nationalPattern = nationalPattern;
    }

    /** Dial code without the plus sign. */
    public String dialCode() {
      return dialCode;
    }

    boolean matches(String national) {
      return nationalPattern.matcher(national).matches();
    }

    /** Parses an ISO code ({@code SA}/{@code EG}, any case), or {@code null}. */
    public static Country fromIso(String iso) {
      if (iso == null) return null;
      for (Country country : values()) {
        if (country.name().equalsIgnoreCase(iso.trim())) return country;
      }
      return null;
    }
  }

  private static final String TRUNK_PREFIX = "0";
  private static final String INTERNATIONAL_PREFIX = "00";
  private static final Pattern SEPARATORS =
      Pattern.compile("[\\s\\u00A0\\u200E\\u200F\\u202A-\\u202E\\u2066-\\u2069().\\-]");
  private static final Pattern DIGITS = Pattern.compile("^\\d+$");
  private static final char ARABIC_INDIC_ZERO = '٠';
  private static final char ARABIC_INDIC_NINE = '٩';
  private static final char EXTENDED_ARABIC_INDIC_ZERO = '۰';
  private static final char EXTENDED_ARABIC_INDIC_NINE = '۹';

  private SupportedMobile() {}

  /** Converts Arabic-Indic (٠-٩) and Extended Arabic-Indic (۰-۹) digits to ASCII. */
  public static String toAsciiDigits(String input) {
    StringBuilder out = new StringBuilder(input.length());
    for (char ch : input.toCharArray()) {
      if (ch >= ARABIC_INDIC_ZERO && ch <= ARABIC_INDIC_NINE) {
        out.append((char) ('0' + (ch - ARABIC_INDIC_ZERO)));
      } else if (ch >= EXTENDED_ARABIC_INDIC_ZERO && ch <= EXTENDED_ARABIC_INDIC_NINE) {
        out.append((char) ('0' + (ch - EXTENDED_ARABIC_INDIC_ZERO)));
      } else {
        out.append(ch);
      }
    }
    return out.toString();
  }

  /**
   * Normalizes input to the E.164 form of a supported mobile, or {@code null}.
   *
   * @param defaultCountry country selected on the form, for numbers typed without a country code
   */
  public static String normalize(String raw, Country defaultCountry) {
    if (raw == null || raw.isEmpty()) return null;
    String value = SEPARATORS.matcher(toAsciiDigits(raw)).replaceAll("");

    boolean international = false;
    if (value.startsWith("+")) {
      value = value.substring(1);
      international = true;
    } else if (value.startsWith(INTERNATIONAL_PREFIX)) {
      value = value.substring(INTERNATIONAL_PREFIX.length());
      international = true;
    }
    if (!DIGITS.matcher(value).matches()) return null;

    if (international) return matchInternational(value);

    if (defaultCountry != null) {
      String national = matchNational(defaultCountry, value);
      if (national != null) return national;
    }
    // Typed with the country code but without "+" / "00" (966501234567).
    return matchInternational(value);
  }

  /** Country of an already-normalized E.164 number, or {@code null}. */
  public static Country countryOf(String e164) {
    if (e164 == null || !e164.startsWith("+")) return null;
    for (Country country : Country.values()) {
      String prefix = "+" + country.dialCode;
      if (e164.startsWith(prefix) && country.matches(e164.substring(prefix.length()))) {
        return country;
      }
    }
    return null;
  }

  private static String matchNational(Country country, String national) {
    if (country.matches(national)) return "+" + country.dialCode + national;
    // Common mistake: keeping the trunk 0 after the country code (+20 010…).
    if (national.startsWith(TRUNK_PREFIX) && country.matches(national.substring(1))) {
      return "+" + country.dialCode + national.substring(1);
    }
    return null;
  }

  private static String matchInternational(String digits) {
    for (Country country : Country.values()) {
      if (!digits.startsWith(country.dialCode)) continue;
      String e164 = matchNational(country, digits.substring(country.dialCode.length()));
      if (e164 != null) return e164;
    }
    return null;
  }
}
