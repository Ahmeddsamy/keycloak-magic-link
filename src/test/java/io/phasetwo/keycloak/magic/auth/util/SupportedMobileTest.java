package io.phasetwo.keycloak.magic.auth.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.JsonNode;
import io.phasetwo.keycloak.magic.Fixtures;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Runs the shared {@code supported-mobile.json} vectors (same as backend and app). */
class SupportedMobileTest {

  static Stream<Arguments> vectors() {
    List<JsonNode> cases = Fixtures.cases("supported-mobile.json");
    return cases.stream()
        .map(
            c ->
                Arguments.of(
                    c.path("note").asText(),
                    c.path("input").asText(),
                    c.path("defaultCountry").isNull() ? null : c.path("defaultCountry").asText(),
                    c.path("expected").isNull() ? null : c.path("expected").asText()));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("vectors")
  void normalizesLikeEveryOtherAdapter(
      String note, String input, String defaultCountry, String expected) {
    assertEquals(
        expected,
        SupportedMobile.normalize(input, SupportedMobile.Country.fromIso(defaultCountry)));
  }

  @Test
  void fixtureIsNotEmpty() {
    assertFalse(Fixtures.cases("supported-mobile.json").isEmpty());
  }

  @Test
  void countryOfNormalizedNumbers() {
    assertEquals(SupportedMobile.Country.SA, SupportedMobile.countryOf("+966501234567"));
    assertEquals(SupportedMobile.Country.EG, SupportedMobile.countryOf("+201012345678"));
    assertNull(SupportedMobile.countryOf("+96555123456"));
    assertNull(SupportedMobile.countryOf(null));
  }
}
