package io.phasetwo.keycloak.magic.otp;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.util.JsonSerialization;

/**
 * CEQUENS MFA adapter (developer.cequens.com, confirmed 2026-11-18):
 *
 * <ul>
 *   <li>sign-in {@code POST /auth/v1/tokens/} {@code {apiKey, userName}} → {@code
 *       data.access_token}
 *   <li>send {@code POST /mfa/v2/verifications} → {@code data.checkCode}
 *   <li>check {@code PUT /mfa/v2/verifications} {@code {checkCode, otpPasscode}} → {@code
 *       data.otpPasscodeStatus} (1 verified, 0 expired, anything else invalid)
 * </ul>
 *
 * <p>One instance per JVM (see {@link OtpServiceFactory}): the token is cached until shortly before
 * its JWT {@code exp}, sign-in is single-flight, a 401 triggers one re-authentication, and only
 * connect failures (nothing sent) are retried. Response bodies are never logged.
 */
@JBossLog
public final class CequensOtpProvider implements OtpService {

  static final String AUTH_PATH = "/auth/v1/tokens/";
  static final String MFA_PATH = "/mfa/v2/verifications";
  private static final long TOKEN_EXPIRY_MARGIN_MS = 60_000;
  private static final String POST = "POST";
  private static final String PUT = "PUT";

  private record CachedToken(String value, long expiresAtMs) {}

  private final OtpConfig config;
  private final CequensTransport transport;
  private final LongSupplier nowMs;
  private final ReentrantLock signInLock = new ReentrantLock();
  private volatile CachedToken token;

  public CequensOtpProvider(OtpConfig config) {
    this(
        config,
        new HttpClientCequensTransport(config.cequensBaseUrl, config.timeoutMs),
        System::currentTimeMillis);
  }

  CequensOtpProvider(OtpConfig config, CequensTransport transport, LongSupplier nowMs) {
    this.config = config;
    this.transport = transport;
    this.nowMs = nowMs;
  }

  @Override
  public OtpSendResult send(OtpSendRequest request) throws OtpProviderException {
    CequensTransport.Response response = callMfa(POST, sendBody(request));
    JsonNode body = CequensResponses.parse(response.body());
    try {
      String checkCode = CequensResponses.checkCode(response.status(), body);
      return new OtpSendResult(checkCode, request.channel(), CequensResponses.requestId(body));
    } catch (OtpProviderException e) {
      throw logged(e, "send");
    }
  }

  @Override
  public OtpCheckOutcome check(String checkCode, String code) throws OtpProviderException {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("checkCode", checkCode);
    payload.put("otpPasscode", code);
    CequensTransport.Response response = callMfa(PUT, payload);
    try {
      return CequensResponses.checkOutcome(
          response.status(), CequensResponses.parse(response.body()));
    } catch (OtpProviderException e) {
      throw logged(e, "check");
    }
  }

  private Map<String, Object> sendBody(OtpSendRequest request) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("channel", request.channel().cequensValue());
    body.put("recipientIdentifier", request.recipient());
    // Cequens types these as strings.
    body.put("otpCodeLength", String.valueOf(request.codeLength()));
    body.put("otpCodeExpiry", String.valueOf(request.expiryMinutes()));
    if (request.channel() == OtpChannel.WHATSAPP) {
      body.put("wabTemplateName", config.whatsappTemplateName);
      body.put("wabTemplateLanguage", request.locale());
    } else {
      String template = config.smsTemplateCode(request.locale());
      if (template != null) body.put("templateCode", template);
    }
    return body;
  }

  private CequensTransport.Response callMfa(String method, Map<String, Object> payload)
      throws OtpProviderException {
    String json = toJson(payload);
    String current = token();
    CequensTransport.Response response = exchange(method, MFA_PATH, json, current);
    // A fixed console token can't be refreshed: a 401 is final (PROVIDER_AUTH).
    if (response.status() != CequensResponses.HTTP_UNAUTHORIZED
        || config.cequensAccessToken != null) {
      return response;
    }

    invalidate(current);
    return exchange(method, MFA_PATH, json, token());
  }

  /** Cached token, or a fresh one; concurrent callers share a single sign-in. */
  String token() throws OtpProviderException {
    if (config.cequensAccessToken != null) return config.cequensAccessToken;
    CachedToken cached = token;
    if (cached != null && nowMs.getAsLong() < cached.expiresAtMs()) return cached.value();
    signInLock.lock();
    try {
      cached = token;
      if (cached != null && nowMs.getAsLong() < cached.expiresAtMs()) return cached.value();
      String fresh = signIn();
      token = new CachedToken(fresh, expiryOf(fresh));
      return fresh;
    } finally {
      signInLock.unlock();
    }
  }

  private String signIn() throws OtpProviderException {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("apiKey", config.cequensApiKey);
    payload.put("userName", config.cequensUserName);
    CequensTransport.Response response = exchange(POST, AUTH_PATH, toJson(payload), null);
    try {
      return CequensResponses.token(response.status(), CequensResponses.parse(response.body()));
    } catch (OtpProviderException e) {
      throw logged(e, "signIn");
    }
  }

  private void invalidate(String rejected) {
    CachedToken cached = token;
    if (cached != null && cached.value().equals(rejected)) token = null;
  }

  private long expiryOf(String jwt) {
    long now = nowMs.getAsLong();
    long fallback = now + config.tokenTtlSeconds * 1000L;
    Long exp = readJwtExp(jwt);
    if (exp == null) return fallback;
    long expiresAt = exp * 1000L - TOKEN_EXPIRY_MARGIN_MS;
    return expiresAt > now ? expiresAt : fallback;
  }

  static Long readJwtExp(String jwt) {
    String[] parts = jwt.split("\\.");
    if (parts.length != 3) return null;
    try {
      byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
      JsonNode exp =
          JsonSerialization.readValue(new String(payload, StandardCharsets.UTF_8), JsonNode.class)
              .path("exp");
      return exp.isNumber() ? exp.asLong() : null;
    } catch (Exception e) {
      return null;
    }
  }

  private CequensTransport.Response exchange(String method, String path, String json, String bearer)
      throws OtpProviderException {
    try {
      return transport.exchange(method, path, json, bearer);
    } catch (CequensTransport.TransportException e) {
      if (e.kind() != CequensTransport.TransportException.Kind.CONNECT) {
        throw noResponse(e, path);
      }
      try {
        return transport.exchange(method, path, json, bearer);
      } catch (CequensTransport.TransportException retry) {
        throw noResponse(retry, path);
      }
    }
  }

  private OtpProviderException noResponse(CequensTransport.TransportException e, String path) {
    log.warnf("Cequens request got no response: path=%s transportFailure=%s", path, e.kind());
    return new OtpProviderException(OtpProviderFailure.UNAVAILABLE);
  }

  private OtpProviderException logged(OtpProviderException e, String operation) {
    if (e.failure().isCritical()) {
      log.errorf(
          "Cequens request failed (alert=otp_provider_critical): operation=%s failure=%s httpStatus=%d requestId=%s",
          operation, e.failure(), e.httpStatus(), e.requestId());
    } else {
      log.warnf(
          "Cequens request failed: operation=%s failure=%s httpStatus=%d requestId=%s",
          operation, e.failure(), e.httpStatus(), e.requestId());
    }
    return e;
  }

  private static String toJson(Map<String, Object> payload) throws OtpProviderException {
    try {
      return JsonSerialization.writeValueAsString(payload);
    } catch (Exception e) {
      throw new OtpProviderException(OtpProviderFailure.MISCONFIGURED);
    }
  }
}
