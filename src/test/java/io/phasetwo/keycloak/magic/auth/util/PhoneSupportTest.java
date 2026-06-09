package io.phasetwo.keycloak.magic.auth.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/** Pure-logic tests for {@link PhoneSupport#normalizeE164} — no Keycloak/Docker. */
class PhoneSupportTest {

  @ParameterizedTest
  @CsvSource({
    "'+966500000000', '+966500000000'",
    "'966500000000', '+966500000000'",
    "'+966 50 000 0000', '+966500000000'",
    "'+966-50-000-0000', '+966500000000'",
    "'(966)500000000', '+966500000000'",
    "'  +966500000000  ', '+966500000000'"
  })
  void normalizesAndAddsLeadingPlus(String raw, String expected) {
    assertEquals(expected, PhoneSupport.normalizeE164(raw));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(
      strings = {
        "   ", // whitespace only
        "abc", // non-numeric
        "+96650abc000", // embedded letters
        "+0500000000", // E.164 first digit must be non-zero
        "+", // no digits
        "+1234567890123456" // 16 digits — exceeds E.164 max of 15
      })
  void rejectsInvalidNumbers(String raw) {
    assertNull(PhoneSupport.normalizeE164(raw));
  }
}
