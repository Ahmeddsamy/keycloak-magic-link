package io.phasetwo.keycloak.magic.exchange;

import lombok.extern.jbosslog.JBossLog;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.tokenexchange.V1TokenExchangeProvider;
import org.keycloak.services.validation.Validation;

/**
 * V1 token exchange provider that auto-links external identities to existing
 * accounts by verified email.
 *
 * <p>The stock V1 external-to-internal exchange hard-rejects with "User
 * already exists" when a user with the subject token's email exists but has
 * no federated identity for the identity provider — there is no exchange-time
 * equivalent of the browser flow's "Automatically Set Existing User"
 * authenticator. For native social login (Apple/Google/Microsoft ID tokens
 * exchanged directly, no browser), that would strand every user who first
 * registered through another method.
 *
 * <p>This provider adds a pre-step: when the identity provider is marked
 * {@code trustEmail} (the same trust assertion the browser auto-link flow
 * relies on) and an existing enabled account matches the token's email, the
 * federated identity is linked to that account first. The stock import logic
 * then finds the link and proceeds through its normal existing-user path
 * (enabled + brute-force checks, profile sync, mappers). All other behavior
 * is inherited unchanged.
 */
@JBossLog
public class AutoLinkTokenExchangeProvider extends V1TokenExchangeProvider {

  @Override
  protected UserModel importUserFromExternalIdentity(BrokeredIdentityContext brokerContext) {
    autoLinkByTrustedEmail(brokerContext);
    return super.importUserFromExternalIdentity(brokerContext);
  }

  private void autoLinkByTrustedEmail(BrokeredIdentityContext brokerContext) {
    if (brokerContext.getIdpConfig().isTransientUsers()
        || !brokerContext.getIdpConfig().isTrustEmail()
        || Validation.isBlank(brokerContext.getEmail())) {
      return;
    }

    FederatedIdentityModel federatedIdentity =
        new FederatedIdentityModel(
            brokerContext.getIdpConfig().getAlias(),
            brokerContext.getId(),
            brokerContext.getUsername(),
            brokerContext.getToken());

    if (session.users().getUserByFederatedIdentity(realm, federatedIdentity) != null) {
      return; // Already linked — nothing to do.
    }

    UserModel existing = session.users().getUserByEmail(realm, brokerContext.getEmail());
    if (existing == null || !existing.isEnabled()) {
      return; // No matching account (or disabled) — stock create path applies.
    }

    session.users().addFederatedIdentity(realm, existing, federatedIdentity);
    log.infof(
        "Auto-linked identity provider %s to existing user %s by trusted email",
        brokerContext.getIdpConfig().getAlias(), existing.getId());
  }
}
