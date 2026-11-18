package io.phasetwo.keycloak.magic.otp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class PhoneOtpSenderTest {

  private static final String PHONE = "+966501234567";

  /** Fails WhatsApp with a configurable failure; SMS succeeds. */
  private static final class FakeService implements OtpService {
    final List<OtpChannel> sends = new ArrayList<>();
    final OtpProviderFailure whatsappFailure;

    FakeService(OtpProviderFailure whatsappFailure) {
      this.whatsappFailure = whatsappFailure;
    }

    @Override
    public OtpSendResult send(OtpSendRequest request) throws OtpProviderException {
      sends.add(request.channel());
      if (request.channel() == OtpChannel.WHATSAPP && whatsappFailure != null) {
        throw new OtpProviderException(whatsappFailure);
      }
      return new OtpSendResult("chk", request.channel(), null);
    }

    @Override
    public OtpCheckOutcome check(String checkCode, String code) {
      return OtpCheckOutcome.VALID;
    }
  }

  private static OtpSendResult send(FakeService service, boolean isResend)
      throws OtpProviderException {
    return new PhoneOtpSender(service, true)
        .send(PHONE, OtpChannel.WHATSAPP, OtpChannel.SMS, isResend, "en", 4, 5);
  }

  @Test
  void firstCodeGoesByWhatsapp() throws Exception {
    FakeService service = new FakeService(null);
    assertEquals(OtpChannel.WHATSAPP, send(service, false).channel());
    assertEquals(List.of(OtpChannel.WHATSAPP), service.sends);
  }

  @Test
  void sendsBySmsWhileWhatsappHasNoTemplate() throws Exception {
    FakeService service = new FakeService(null);
    OtpSendResult result =
        new PhoneOtpSender(service, false)
            .send(PHONE, OtpChannel.WHATSAPP, OtpChannel.SMS, false, "en", 4, 5);
    assertEquals(OtpChannel.SMS, result.channel());
    assertEquals(List.of(OtpChannel.SMS), service.sends);
  }

  @Test
  void resendsGoBySms() throws Exception {
    FakeService service = new FakeService(null);
    assertEquals(OtpChannel.SMS, send(service, true).channel());
    assertEquals(List.of(OtpChannel.SMS), service.sends);
  }

  @Test
  void fallsBackToSmsWhenWhatsappIsUnavailable() throws Exception {
    FakeService service = new FakeService(OtpProviderFailure.CHANNEL_UNAVAILABLE);
    assertEquals(OtpChannel.SMS, send(service, false).channel());
    assertEquals(List.of(OtpChannel.WHATSAPP, OtpChannel.SMS), service.sends);
  }

  @Test
  void doesNotFallBackForAnInvalidNumberOrAnOutage() {
    for (OtpProviderFailure failure :
        List.of(OtpProviderFailure.INVALID_RECIPIENT, OtpProviderFailure.UNAVAILABLE)) {
      FakeService service = new FakeService(failure);
      OtpProviderException e = assertThrows(OtpProviderException.class, () -> send(service, false));
      assertEquals(failure, e.failure());
      assertEquals(List.of(OtpChannel.WHATSAPP), service.sends);
    }
  }
}
