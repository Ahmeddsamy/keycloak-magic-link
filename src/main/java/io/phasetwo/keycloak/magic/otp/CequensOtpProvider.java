package io.phasetwo.keycloak.magic.otp;

import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.util.JsonSerialization;

/**
 * Cequens Verification Hub provider (managed OTP: send + check, native WhatsApp&rarr;SMS fallback).
 * Calls the Hub REST API directly over HTTPS — the Keycloak host egress IP must be on the Cequens
 * IP allow-list (CR-03).
 *
 * <p>Mirrors the parcelo-backend {@code CequensVerifyProvider}. Two facts are pending confirmation
 * against the Cequens API docs at integration time and are marked {@code TODO(CR-03)}: the exact
 * verify/validate endpoint paths and the field that signals a valid code. Both are overridable via
 * env so they can be fixed without a rebuild.
 */
@JBossLog
public class CequensOtpProvider implements OtpService {

  private final OtpConfig config;
  private final HttpClient http;

  // TODO(CR-03): confirm exact Verification Hub paths against Cequens docs.
  private final String sendPath = envOr("CEQUENS_VERIFY_SEND_PATH", "/verification/send");
  private final String checkPath = envOr("CEQUENS_VERIFY_CHECK_PATH", "/verification/validate");

  public CequensOtpProvider(OtpConfig config) {
    this.config = config;
    this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
  }

  @Override
  public void start(String phoneNumber, String channel) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("recipient", phoneNumber);
    body.put("channel", channel);
    if (config.cequensSenderName != null) {
      body.put("senderName", config.cequensSenderName);
    }
    JsonNode response = post(sendPath, body);
    log.debugf(
        "Cequens send over %s to %s -> %s",
        channel, PhoneMasking.mask(phoneNumber), response.path("status").asText("ok"));
  }

  @Override
  public boolean check(String phoneNumber, String code) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("recipient", phoneNumber);
    body.put("code", code);
    JsonNode response = post(checkPath, body);
    // TODO(CR-03): confirm the exact success field/value. Accept a few likely
    // shapes leniently so a wrong guess fails closed (invalid) rather than open.
    boolean valid =
        response.path("valid").asBoolean(false)
            || response.path("data").path("valid").asBoolean(false)
            || "approved".equalsIgnoreCase(response.path("status").asText(""))
            || "verified".equalsIgnoreCase(response.path("status").asText(""));
    log.debugf("Cequens check for %s -> %s", PhoneMasking.mask(phoneNumber), valid);
    return valid;
  }

  private JsonNode post(String path, Map<String, Object> body) {
    if (config.cequensBaseUrl == null || config.cequensApiToken == null) {
      throw new IllegalStateException(
          "Cequens OTP provider selected but CEQUENS_API_BASE_URL / CEQUENS_API_TOKEN are not set");
    }
    try {
      String json = JsonSerialization.writeValueAsString(body);
      HttpRequest request =
          HttpRequest.newBuilder()
              .uri(URI.create(config.cequensBaseUrl + path))
              .timeout(Duration.ofSeconds(15))
              .header("Content-Type", "application/json")
              // TODO(CR-03): confirm the auth scheme/header Cequens expects
              // (Bearer JWT vs custom header) once credentials are provisioned.
              .header("Authorization", "Bearer " + config.cequensApiToken)
              .POST(HttpRequest.BodyPublishers.ofString(json))
              .build();

      HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() >= 400) {
        // Never log the provider's raw body (may echo the code); status only.
        throw new RuntimeException("Cequens returned HTTP " + response.statusCode());
      }
      String responseBody = response.body();
      if (responseBody == null || responseBody.isBlank()) {
        return JsonSerialization.mapper.createObjectNode();
      }
      return JsonSerialization.readValue(responseBody, JsonNode.class);
    } catch (RuntimeException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException("Cequens request failed: " + e.getMessage(), e);
    }
  }

  private static String envOr(String key, String def) {
    String v = System.getenv(key);
    return (v == null || v.isBlank()) ? def : v;
  }
}
