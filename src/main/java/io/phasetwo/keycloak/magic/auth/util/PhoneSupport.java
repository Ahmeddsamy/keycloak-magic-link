package io.phasetwo.keycloak.magic.auth.util;

import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

/**
 * Phone identity for the {@code ext-phone-otp} authenticator. A phone-only agent has {@code
 * username} = E.164; agents migrated from email keep their username and are found by the {@code
 * phoneNumber} attribute (set by the backfill script). The {@code phoneNumber} attribute feeds the
 * {@code phone_number} token claim through the agent client's {@code phone} scope.
 */
@JBossLog
public final class PhoneSupport {

  public static final String PHONE_NUMBER_ATTRIBUTE = "phoneNumber";
  public static final String PHONE_NUMBER_VERIFIED_ATTRIBUTE = "phoneNumberVerified";

  private PhoneSupport() {}

  /** Finds a user whose username or {@code phoneNumber} attribute equals {@code phone}. */
  public static UserModel findByPhone(KeycloakSession session, RealmModel realm, String phone) {
    UserModel byUsername = session.users().getUserByUsername(realm, phone);
    if (byUsername != null) return byUsername;
    return session
        .users()
        .searchForUserByUserAttributeStream(realm, PHONE_NUMBER_ATTRIBUTE, phone)
        .findFirst()
        .orElse(null);
  }

  /**
   * Creates a user for a verified phone (username = phone) with {@code roleName}. Only called after
   * the code passed, so unverified numbers never create accounts.
   */
  public static UserModel create(
      KeycloakSession session, RealmModel realm, String phone, String roleName) {
    UserModel user = session.users().addUser(realm, phone);
    user.setEnabled(true);
    user.setSingleAttribute(PHONE_NUMBER_ATTRIBUTE, phone);
    if (roleName != null && !roleName.isBlank()) {
      RoleModel role = realm.getRole(roleName);
      if (role != null) {
        user.grantRole(role);
      } else {
        log.warnf(
            "ext-phone-otp: role '%s' not found in realm '%s'; user created without it",
            roleName, realm.getName());
      }
    }
    return user;
  }

  /** Marks the phone verified (and sets it if the account had none). */
  public static void markVerified(UserModel user, String phone) {
    if (user.getFirstAttribute(PHONE_NUMBER_ATTRIBUTE) == null) {
      user.setSingleAttribute(PHONE_NUMBER_ATTRIBUTE, phone);
    }
    user.setSingleAttribute(PHONE_NUMBER_VERIFIED_ATTRIBUTE, "true");
  }
}
