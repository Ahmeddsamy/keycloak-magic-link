package io.phasetwo.keycloak.magic;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.util.JsonSerialization;

/** Loads the shared cross-language fixtures from {@code src/test/resources/fixtures}. */
public final class Fixtures {

  private Fixtures() {}

  public static List<JsonNode> cases(String fileName) {
    try (InputStream in = Fixtures.class.getResourceAsStream("/fixtures/" + fileName)) {
      if (in == null) throw new IllegalStateException("Missing fixture " + fileName);
      List<JsonNode> cases = new ArrayList<>();
      JsonSerialization.readValue(in, JsonNode.class).path("cases").forEach(cases::add);
      return cases;
    } catch (Exception e) {
      throw new IllegalStateException("Cannot read fixture " + fileName, e);
    }
  }
}
