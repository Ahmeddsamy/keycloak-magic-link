package io.phasetwo.keycloak.magic.otp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.MissingNode;
import java.util.Locale;
import org.keycloak.util.JsonSerialization;

/**
 * Pure classification of Cequens MFA responses — the Java twin of the backend adapter's helpers,
 * tested against the shared {@code cequens-mfa-responses.json} fixtures. Every unclear answer fails
 * closed.
 */
final class CequensResponses {

  static final int HTTP_OK = 200;
  static final int HTTP_CREATED = 201;
  static final int HTTP_BAD_REQUEST = 400;
  static final int HTTP_UNAUTHORIZED = 401;
  static final int HTTP_PAYMENT_REQUIRED = 402;
  static final int HTTP_FORBIDDEN = 403;
  static final int HTTP_NOT_FOUND = 404;
  static final int HTTP_SERVER_ERROR = 500;

  private static final int PASSCODE_VERIFIED = 1;
  private static final int PASSCODE_EXPIRED = 0;
  private static final int REPLY_CODE_MAX_TRIALS = 2001;

  private CequensResponses() {}

  /** Parses a body; non-JSON or empty bodies become a missing node. */
  static JsonNode parse(String body) {
    if (body == null || body.isBlank()) return MissingNode.getInstance();
    try {
      JsonNode node = JsonSerialization.readValue(body, JsonNode.class);
      return node == null ? MissingNode.getInstance() : node;
    } catch (Exception e) {
      return MissingNode.getInstance();
    }
  }

  static String requestId(JsonNode body) {
    JsonNode id = body.path("requestId");
    return id.isTextual() ? id.asText() : null;
  }

  /** A 2xx whose body {@code status} is an error counts as that error. */
  static int effectiveStatus(int httpStatus, JsonNode body) {
    JsonNode bodyStatus = body.path("status");
    boolean successHttp = httpStatus >= HTTP_OK && httpStatus < 300;
    if (successHttp && bodyStatus.isNumber() && bodyStatus.asInt() >= HTTP_BAD_REQUEST) {
      return bodyStatus.asInt();
    }
    return httpStatus;
  }

  /** Access token from a sign-in response. */
  static String token(int httpStatus, JsonNode body) throws OtpProviderException {
    if (httpStatus == HTTP_OK) {
      JsonNode token = body.path("data").path("access_token");
      if (token.isTextual() && !token.asText().isEmpty()) return token.asText();
      throw failure(OtpProviderFailure.UNEXPECTED_RESPONSE, httpStatus, body);
    }
    OtpProviderFailure failure =
        httpStatus == HTTP_UNAUTHORIZED || httpStatus == HTTP_FORBIDDEN
            ? OtpProviderFailure.PROVIDER_AUTH
            : common(httpStatus);
    throw failure(failure, httpStatus, body);
  }

  /** Check code from a send response. */
  static String checkCode(int httpStatus, JsonNode body) throws OtpProviderException {
    int status = effectiveStatus(httpStatus, body);
    if (status == HTTP_OK || status == HTTP_CREATED) {
      JsonNode checkCode = body.path("data").path("checkCode");
      if (checkCode.isTextual() && !checkCode.asText().isEmpty()) return checkCode.asText();
      throw failure(OtpProviderFailure.UNEXPECTED_RESPONSE, status, body);
    }
    throw failure(sendFailure(status, body), status, body);
  }

  /** Outcome of a check response. */
  static OtpCheckOutcome checkOutcome(int httpStatus, JsonNode body) throws OtpProviderException {
    int status = effectiveStatus(httpStatus, body);
    if (status == HTTP_OK) {
      JsonNode passcode = body.path("data").path("otpPasscodeStatus");
      if (passcode.isIntegralNumber() && passcode.asInt() == PASSCODE_VERIFIED) {
        return OtpCheckOutcome.VALID;
      }
      if (passcode.isIntegralNumber() && passcode.asInt() == PASSCODE_EXPIRED) {
        return OtpCheckOutcome.EXPIRED;
      }
      return OtpCheckOutcome.INVALID;
    }
    if (status == HTTP_FORBIDDEN) {
      boolean maxTrials =
          body.path("replyCode").asInt(-1) == REPLY_CODE_MAX_TRIALS
              || errorText(body).contains("maximum trials");
      return maxTrials ? OtpCheckOutcome.EXHAUSTED : OtpCheckOutcome.ALREADY_USED;
    }
    if (status == HTTP_NOT_FOUND) {
      // Unknown checkCode — nothing to verify against; same as an expired code.
      return OtpCheckOutcome.EXPIRED;
    }
    throw failure(common(status), status, body);
  }

  static OtpProviderFailure common(int status) {
    if (status == HTTP_UNAUTHORIZED) return OtpProviderFailure.PROVIDER_AUTH;
    if (status == HTTP_PAYMENT_REQUIRED) return OtpProviderFailure.NO_CREDIT;
    if (status >= HTTP_SERVER_ERROR) return OtpProviderFailure.UNAVAILABLE;
    return OtpProviderFailure.UNEXPECTED_RESPONSE;
  }

  static OtpProviderFailure sendFailure(int status, JsonNode body) {
    String text = errorText(body);
    if (status == HTTP_BAD_REQUEST) {
      return text.contains("recipientidentifier")
          ? OtpProviderFailure.INVALID_RECIPIENT
          : OtpProviderFailure.MISCONFIGURED;
    }
    if (status == HTTP_NOT_FOUND) {
      return text.contains("on channel")
          ? OtpProviderFailure.CHANNEL_UNAVAILABLE
          : OtpProviderFailure.MISCONFIGURED;
    }
    return common(status);
  }

  private static String errorText(JsonNode body) {
    JsonNode error = body.path("error");
    return error.isTextual() ? error.asText().toLowerCase(Locale.ROOT) : "";
  }

  private static OtpProviderException failure(
      OtpProviderFailure failure, int status, JsonNode body) {
    return new OtpProviderException(failure, status, requestId(body));
  }
}
