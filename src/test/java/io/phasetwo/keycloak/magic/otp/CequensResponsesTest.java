package io.phasetwo.keycloak.magic.otp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import io.phasetwo.keycloak.magic.Fixtures;
import java.util.Locale;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Every recorded Cequens response maps to the same result as in the backend adapter. */
class CequensResponsesTest {

  static Stream<Arguments> cases() {
    return Fixtures.cases("cequens-mfa-responses.json").stream()
        .map(c -> Arguments.of(c.path("name").asText(), c));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("cases")
  void classifiesLikeTheBackend(String name, JsonNode c) throws Exception {
    int status = c.path("httpStatus").asInt();
    JsonNode bodyNode = c.path("body");
    String raw = bodyNode.isTextual() ? bodyNode.asText() : bodyNode.toString();
    JsonNode body = CequensResponses.parse(raw);
    JsonNode expected = c.path("expected");
    String operation = c.path("operation").asText();

    switch (expected.path("kind").asText()) {
      case "failure" -> {
        OtpProviderException e =
            assertThrows(OtpProviderException.class, () -> run(operation, status, body));
        assertEquals(expected.path("failure").asText(), e.failure().name());
      }
      case "token" -> assertEquals(expected.path("token").asText(), run(operation, status, body));
      case "sent" -> {
        assertEquals(expected.path("checkCode").asText(), run(operation, status, body));
        assertEquals(expected.path("requestId").asText(), CequensResponses.requestId(body));
      }
      case "outcome" ->
          assertEquals(
              expected.path("outcome").asText(),
              ((OtpCheckOutcome) run(operation, status, body)).name().toLowerCase(Locale.ROOT));
      default -> throw new IllegalArgumentException("Unknown kind in " + name);
    }
  }

  private static Object run(String operation, int status, JsonNode body)
      throws OtpProviderException {
    return switch (operation) {
      case "signIn" -> CequensResponses.token(status, body);
      case "send" -> CequensResponses.checkCode(status, body);
      case "check" -> CequensResponses.checkOutcome(status, body);
      default -> throw new IllegalArgumentException(operation);
    };
  }
}
