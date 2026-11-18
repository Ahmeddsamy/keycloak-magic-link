package io.phasetwo.keycloak.magic.otp;

/**
 * Delivery channel for a verification code. Parcelo picks the channel per request (WhatsApp first,
 * SMS for resends and as fallback); the Cequens console only holds templates/defaults.
 */
public enum OtpChannel {
  WHATSAPP("whatsapp", "Whatsapp"),
  SMS("sms", "SMS");

  private final String configValue;
  private final String cequensValue;

  OtpChannel(String configValue, String cequensValue) {
    this.configValue = configValue;
    this.cequensValue = cequensValue;
  }

  /**
   * Value used in authenticator config, auth notes and the theme ({@code whatsapp}/{@code sms}).
   */
  public String configValue() {
    return configValue;
  }

  /** Value of the Cequens {@code channel} field. */
  public String cequensValue() {
    return cequensValue;
  }

  /** Parses a config value; anything unknown falls back to {@code defaultChannel}. */
  public static OtpChannel fromConfig(String value, OtpChannel defaultChannel) {
    if (value != null) {
      for (OtpChannel channel : values()) {
        if (channel.configValue.equalsIgnoreCase(value.trim())) {
          return channel;
        }
      }
    }
    return defaultChannel;
  }
}
