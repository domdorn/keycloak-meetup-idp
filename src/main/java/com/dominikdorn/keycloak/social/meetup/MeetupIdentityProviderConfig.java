package com.dominikdorn.keycloak.social.meetup;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class MeetupIdentityProviderConfig extends OAuth2IdentityProviderConfig {

  public MeetupIdentityProviderConfig(IdentityProviderModel model) {
    super(model);
  }

  public MeetupIdentityProviderConfig() {
  }
}
