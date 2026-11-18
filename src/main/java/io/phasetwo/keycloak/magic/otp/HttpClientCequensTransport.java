package io.phasetwo.keycloak.magic.otp;

import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/** {@link CequensTransport} over one shared {@link HttpClient} (no redirects). */
final class HttpClientCequensTransport implements CequensTransport {

  private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
  private static final String JSON = "application/json; charset=utf-8";

  private final HttpClient client;
  private final String baseUrl;
  private final Duration requestTimeout;

  HttpClientCequensTransport(String baseUrl, int timeoutMs) {
    this.baseUrl = baseUrl;
    this.requestTimeout = Duration.ofMillis(timeoutMs);
    this.client =
        HttpClient.newBuilder()
            .connectTimeout(CONNECT_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
  }

  @Override
  public Response exchange(String method, String path, String jsonBody, String bearerToken)
      throws TransportException {
    HttpRequest.Builder builder =
        HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .timeout(requestTimeout)
            .header("Content-Type", JSON)
            .header("Accept", "application/json")
            .method(method, HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));
    if (bearerToken != null) {
      builder.header("Authorization", "Bearer " + bearerToken);
    }
    try {
      HttpResponse<String> response =
          client.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      return new Response(response.statusCode(), response.body());
    } catch (HttpConnectTimeoutException | ConnectException e) {
      throw new TransportException(TransportException.Kind.CONNECT, e);
    } catch (HttpTimeoutException e) {
      throw new TransportException(TransportException.Kind.TIMEOUT, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new TransportException(TransportException.Kind.OTHER, e);
    } catch (IOException e) {
      throw new TransportException(TransportException.Kind.OTHER, e);
    }
  }
}
