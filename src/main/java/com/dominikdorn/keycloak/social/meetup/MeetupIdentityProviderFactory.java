package com.dominikdorn.keycloak.social.meetup;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * Meetup.com (OAuth2) Identity Provider factory class.
 *
 * @author Dominik Dorn
 */
public class MeetupIdentityProviderFactory extends
    AbstractIdentityProviderFactory<MeetupIdentityProvider> implements
    SocialIdentityProviderFactory<MeetupIdentityProvider> {

  public static final String PROVIDER_ID = "meetup-oauth2";
  public static final String NAME = "Meetup.com (OAuth2)";

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public MeetupIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    return new MeetupIdentityProvider(session, new MeetupIdentityProviderConfig(model));
  }

  @Override
  public OAuth2IdentityProviderConfig createConfig() {
    return new MeetupIdentityProviderConfig();
  }

}
