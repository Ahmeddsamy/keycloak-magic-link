package io.phasetwo.keycloak.magic.otp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class CequensOtpProviderTest {

  private static final String SEND_OK =
      "{\"status\":201,\"requestId\":\"r-1\",\"data\":{\"checkCode\":\"CHK1\"}}";
  private static final String CHECK_OK = "{\"status\":200,\"data\":{\"otpPasscodeStatus\":1}}";
  private static final String UNAUTHORIZED = "{\"status\":401,\"error\":\"Unauthoized\"}";

  /** Replays queued responses and records requests. */
  private static final class FakeTransport implements CequensTransport {
    record Call(String method, String path, String body, String bearer) {}

    final Deque<Object> responses = new ArrayDeque<>();
    final List<Call> calls = new ArrayList<>();

    FakeTransport then(int status, String body) {
      responses.add(new Response(status, body));
      return this;
    }

    FakeTransport thenFail(TransportException.Kind kind) {
      responses.add(new TransportException(kind, null));
      return this;
    }

    @Override
    public Response exchange(String method, String path, String jsonBody, String bearerToken)
        throws TransportException {
      calls.add(new Call(method, path, jsonBody, bearerToken));
      Object next = responses.removeFirst();
      if (next instanceof TransportException e) throw e;
      return (Response) next;
    }

    long signIns() {
      return calls.stream().filter(c -> c.path().equals(CequensOtpProvider.AUTH_PATH)).count();
    }
  }

  private final AtomicLong clock = new AtomicLong(1_000_000_000_000L);
  private final OtpConfig config =
      new OtpConfig(
          Map.of(
                  "OTP_PROVIDER", "cequens",
                  "CEQUENS_USERNAME", "user",
                  "CEQUENS_API_KEY", "key",
                  "CEQUENS_WHATSAPP_TEMPLATE_NAME", "verify_parcelo_otp",
                  "CEQUENS_SMS_TEMPLATE_CODE_AR", "AR-TPL")
              ::get);

  private static String signIn(String token) {
    return "{\"replyCode\":0,\"data\":{\"access_token\":\"" + token + "\"}}";
  }

  private static String jwt(long expSeconds) {
    String payload = "{\"exp\":" + expSeconds + "}";
    return "h."
        + Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(payload.getBytes(StandardCharsets.UTF_8))
        + ".s";
  }

  private CequensOtpProvider provider(FakeTransport transport) {
    return new CequensOtpProvider(config, transport, clock::get);
  }

  private static OtpSendRequest whatsapp() {
    return new OtpSendRequest("+966501234567", OtpChannel.WHATSAPP, "ar", 4, 5);
  }

  @Test
  void signsInOnceAndReusesTheTokenUntilJustBeforeExp() throws Exception {
    String token = jwt(clock.get() / 1000 + 3600);
    FakeTransport transport =
        new FakeTransport().then(200, signIn(token)).then(201, SEND_OK).then(201, SEND_OK);
    CequensOtpProvider provider = provider(transport);

    provider.send(whatsapp());
    provider.send(whatsapp());

    assertEquals(1, transport.signIns());
    assertEquals(token, transport.calls.get(1).bearer());
    assertNull(transport.calls.get(0).bearer());
  }

  @Test
  void refreshesTheTokenOnceItIsWithinTheExpiryMargin() throws Exception {
    FakeTransport transport =
        new FakeTransport()
            .then(200, signIn(jwt(clock.get() / 1000 + 120)))
            .then(201, SEND_OK)
            .then(200, signIn(jwt(clock.get() / 1000 + 3600)))
            .then(201, SEND_OK);
    CequensOtpProvider provider = provider(transport);

    provider.send(whatsapp());
    clock.addAndGet(61_000);
    provider.send(whatsapp());

    assertEquals(2, transport.signIns());
  }

  @Test
  void reauthenticatesOnceWhenTheTokenIsRejected() throws Exception {
    FakeTransport transport =
        new FakeTransport()
            .then(200, signIn("old"))
            .then(401, UNAUTHORIZED)
            .then(200, signIn("new"))
            .then(201, SEND_OK);

    OtpSendResult result = provider(transport).send(whatsapp());

    assertEquals("CHK1", result.checkCode());
    assertEquals("new", transport.calls.get(3).bearer());
  }

  @Test
  void aSecondRejectionIsAProviderAuthFailure() {
    FakeTransport transport =
        new FakeTransport()
            .then(200, signIn("old"))
            .then(401, UNAUTHORIZED)
            .then(200, signIn("new"))
            .then(401, UNAUTHORIZED);

    OtpProviderException e =
        assertThrows(OtpProviderException.class, () -> provider(transport).send(whatsapp()));
    assertEquals(OtpProviderFailure.PROVIDER_AUTH, e.failure());
  }

  @Test
  void retriesConnectFailuresButNotTimeouts() throws Exception {
    FakeTransport connect =
        new FakeTransport()
            .then(200, signIn("t"))
            .thenFail(CequensTransport.TransportException.Kind.CONNECT)
            .then(200, CHECK_OK);
    assertEquals(OtpCheckOutcome.VALID, provider(connect).check("CHK1", "1234"));

    FakeTransport timeout =
        new FakeTransport()
            .then(200, signIn("t"))
            .thenFail(CequensTransport.TransportException.Kind.TIMEOUT);
    OtpProviderException e =
        assertThrows(OtpProviderException.class, () -> provider(timeout).check("CHK1", "1234"));
    assertEquals(OtpProviderFailure.UNAVAILABLE, e.failure());
    assertEquals(2, timeout.calls.size());
  }

  @Test
  void usesAConsoleAccessTokenWithoutSigningIn() throws Exception {
    OtpConfig tokenConfig =
        new OtpConfig(
            Map.of("OTP_PROVIDER", "cequens", "CEQUENS_ACCESS_TOKEN", "console-token")::get);
    FakeTransport transport = new FakeTransport().then(201, SEND_OK);

    new CequensOtpProvider(tokenConfig, transport, clock::get)
        .send(new OtpSendRequest("+966501234567", OtpChannel.SMS, "en", 4, 5));

    assertEquals(0, transport.signIns());
    assertEquals("console-token", transport.calls.get(0).bearer());
  }

  @Test
  void aRejectedConsoleTokenIsFinal() {
    OtpConfig tokenConfig =
        new OtpConfig(
            Map.of("OTP_PROVIDER", "cequens", "CEQUENS_ACCESS_TOKEN", "console-token")::get);
    FakeTransport transport = new FakeTransport().then(401, UNAUTHORIZED);

    OtpProviderException e =
        assertThrows(
            OtpProviderException.class,
            () ->
                new CequensOtpProvider(tokenConfig, transport, clock::get)
                    .send(new OtpSendRequest("+966501234567", OtpChannel.SMS, "en", 4, 5)));
    assertEquals(OtpProviderFailure.PROVIDER_AUTH, e.failure());
    assertEquals(1, transport.calls.size());
  }

  @Test
  void whatsappBodyCarriesTheTemplateAndLanguage() throws Exception {
    FakeTransport transport = new FakeTransport().then(200, signIn("t")).then(201, SEND_OK);

    provider(transport).send(whatsapp());

    String body = transport.calls.get(1).body();
    assertTrue(body.contains("\"channel\":\"Whatsapp\""));
    assertTrue(body.contains("\"wabTemplateName\":\"verify_parcelo_otp\""));
    assertTrue(body.contains("\"wabTemplateLanguage\":\"ar\""));
    assertTrue(body.contains("\"otpCodeLength\":\"4\""));
    assertTrue(body.contains("\"otpCodeExpiry\":\"5\""));
    assertFalse(body.contains("templateCode"));
  }

  @Test
  void smsBodyUsesTheLocaleTemplate() throws Exception {
    FakeTransport transport = new FakeTransport().then(200, signIn("t")).then(201, SEND_OK);

    provider(transport).send(new OtpSendRequest("+201012345678", OtpChannel.SMS, "ar", 4, 5));

    String body = transport.calls.get(1).body();
    assertTrue(body.contains("\"channel\":\"SMS\""));
    assertTrue(body.contains("\"templateCode\":\"AR-TPL\""));
    assertFalse(body.contains("wabTemplateName"));
  }

  @Test
  void checkUsesPutWithTheCheckCode() throws Exception {
    FakeTransport transport = new FakeTransport().then(200, signIn("t")).then(200, CHECK_OK);

    provider(transport).check("CHK1", "1234");

    FakeTransport.Call call = transport.calls.get(1);
    assertEquals("PUT", call.method());
    assertTrue(call.body().contains("\"checkCode\":\"CHK1\""));
    assertTrue(call.body().contains("\"otpPasscode\":\"1234\""));
  }

  @Test
  void resultToStringHidesTheCheckCode() {
    assertFalse(new OtpSendResult("SECRET", OtpChannel.SMS, "r").toString().contains("SECRET"));
  }
}
