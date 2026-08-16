package io.phasetwo.keycloak.magic.exchange;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

/**
 * Registers {@link AutoLinkTokenExchangeProvider} ahead of the built-in V1
 * provider (id {@code default}, order 0) so it handles all token exchange
 * requests when the {@code token-exchange} feature is enabled.
 */
@AutoService(TokenExchangeProviderFactory.class)
public class AutoLinkTokenExchangeProviderFactory
    implements TokenExchangeProviderFactory, EnvironmentDependentProviderFactory {

  public static final String PROVIDER_ID = "ext-auto-link";

  @Override
  public TokenExchangeProvider create(KeycloakSession session) {
    return new AutoLinkTokenExchangeProvider();
  }

  @Override
  public int order() {
    return 100;
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public boolean isSupported(Config.Scope config) {
    return Profile.isFeatureEnabled(Profile.Feature.TOKEN_EXCHANGE);
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
