package io.phasetwo.keycloak.magic.auth.util;

import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

/**
 * Phone-number identity helpers for the {@code ext-phone-otp} authenticator.
 *
 * <p>Agents are keyed by their E.164 phone: the Keycloak {@code username} is the phone and the
 * {@code phoneNumber} attribute feeds the {@code phone_number} token claim (via the agent client's
 * {@code phone} scope). This is the IdP-side counterpart to the backend's phone-keyed,
 * email-optional provisioning.
 */
@JBossLog
public final class PhoneSupport {

  public static final String PHONE_NUMBER_ATTRIBUTE = "phoneNumber";
  public static final String PHONE_NUMBER_VERIFIED_ATTRIBUTE = "phoneNumberVerified";

  private PhoneSupport() {}

  /**
   * Strips spaces/dashes/parens and ensures a leading {@code +}. Returns the normalized E.164
   * string, or {@code null} if the input isn't E.164-shaped ({@code +} then 1–15 digits, first
   * digit non-zero).
   */
  public static String normalizeE164(String raw) {
    if (raw == null) {
      return null;
    }
    String trimmed = raw.trim().replaceAll("[\\s\\-()]", "");
    if (trimmed.isEmpty()) {
      return null;
    }
    if (!trimmed.startsWith("+")) {
      trimmed = "+" + trimmed;
    }
    if (!trimmed.matches("^\\+[1-9]\\d{1,14}$")) {
      return null;
    }
    return trimmed;
  }

  /** Finds a user whose username OR {@code phoneNumber} attribute equals {@code phone}. */
  public static UserModel findByPhone(KeycloakSession session, RealmModel realm, String phone) {
    UserModel byUsername = session.users().getUserByUsername(realm, phone);
    if (byUsername != null) {
      return byUsername;
    }
    return session
        .users()
        .searchForUserByUserAttributeStream(realm, PHONE_NUMBER_ATTRIBUTE, phone)
        .findFirst()
        .orElse(null);
  }

  /**
   * Finds the user by phone, or creates one (username = phone) when {@code forceCreate} is true —
   * assigning {@code roleName} and marking the phone verified. Returns {@code null} if not found
   * and not creating.
   */
  public static UserModel findOrCreate(
      KeycloakSession session,
      RealmModel realm,
      String phone,
      boolean forceCreate,
      String roleName) {
    UserModel user = findByPhone(session, realm, phone);
    if (user != null) {
      return user;
    }
    if (!forceCreate) {
      return null;
    }

    user = session.users().addUser(realm, phone);
    user.setEnabled(true);
    user.setSingleAttribute(PHONE_NUMBER_ATTRIBUTE, phone);
    markVerified(user);

    if (roleName != null && !roleName.isBlank()) {
      RoleModel role = realm.getRole(roleName);
      if (role != null) {
        user.grantRole(role);
      } else {
        log.warnf(
            "ext-phone-otp: configured role '%s' not found in realm '%s' — user created without it",
            roleName, realm.getName());
      }
    }
    return user;
  }

  public static void markVerified(UserModel user) {
    user.setSingleAttribute(PHONE_NUMBER_VERIFIED_ATTRIBUTE, "true");
  }
}
