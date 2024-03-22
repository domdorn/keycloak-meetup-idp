package com.dominikdorn.keycloak.social.meetup;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashMap;
import javax.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.ExchangeTokenToIdentityProviderToken;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

public class MeetupIdentityProvider extends
    AbstractOAuth2IdentityProvider<MeetupIdentityProviderConfig> implements
    SocialIdentityProvider<MeetupIdentityProviderConfig>, ExchangeTokenToIdentityProviderToken {

  public static final String BASE_URL = "https://secure.meetup.com";

  public static final String AUTHORIZATION_URL = BASE_URL + "/oauth2/authorize";
  public static final String ACCESS_TOKEN_URL = BASE_URL + "/oauth2/access";


  protected static final Logger logger = Logger.getLogger(MeetupIdentityProvider.class);

  public MeetupIdentityProvider(KeycloakSession session, MeetupIdentityProviderConfig config) {
    super(session, config);
    config.setAuthorizationUrl(AUTHORIZATION_URL);
    config.setTokenUrl(ACCESS_TOKEN_URL);
    config.setTrustEmail(true);
  }

  @Override
  protected String getDefaultScopes() {
    return "profile";
  }

  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
    final UriBuilder uriBuilder = UriBuilder.fromUri(getConfig().getAuthorizationUrl())
//        .queryParam(OAUTH2_PARAMETER_SCOPE, getConfig().getDefaultScope())
        .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
        .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
        .queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
        .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());

    return uriBuilder;
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return super.callback(realm, callback, event);
  }

  @Override
  protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
    try {
      JsonNode data = profile.get("data");
      JsonNode self = data.get("self");

      String userId = self.get("id").asText();
      String email = self.get("email").asText();
      String name = self.get("name").asText();
      String memberUrl = self.get("memberUrl").asText();
      String memberPhotoUrl = self.get("memberPhotoUrl").asText();

      BrokeredIdentityContext user = new BrokeredIdentityContext(userId);
      user.setId(userId);
      user.setUsername(email);
      user.setIdpConfig(getConfig());
      user.setIdp(this);
      user.setName(name);
      user.setEmail(email);
      user.setModelUsername(userId);
      user.setBrokerUserId(userId);
      HashMap<String, Object> contextData = new HashMap<>();
      contextData.put("memberUrl", memberUrl);
      contextData.put("memberPhotoUrl", memberPhotoUrl);
      user.setContextData(contextData);
      user.setUserAttribute("memberUrl", memberUrl);
      user.setUserAttribute("memberPhotoUrl", memberPhotoUrl);

      AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile,
          getConfig().getAlias());
      return user;
    } catch (Exception e) {
      throw new IdentityBrokerException("Could not obtain user profile from meetup.", e);
    }
  }

  class GraphQLQuery {
    private String query;

    public GraphQLQuery(String query) {
      this.query = query;
    }

    public String getQuery() {
      return query;
    }
  }

  @Override
  protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
    try {
      GraphQLQuery query = new GraphQLQuery(
          "query { self { id email name memberUrl memberPhotoUrl } }");
      JsonNode profile = SimpleHttp.doPost("https://api.meetup.com/gql",
          session
      ).json(query).header("Authorization", "Bearer " + accessToken).asJson();

      BrokeredIdentityContext context = extractIdentityFromProfile(null, profile);

      if(getConfig().isStoreToken()) {
        context.setToken(accessToken);
      }

      return context;
    } catch (Exception e) {
      throw new IdentityBrokerException("Could not obtain user profile from meetup.", e);
    }
  }


//    @Override
//  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
//    return new Endpoint(realm, callback, event);
//  }

//  @Override
//  public Response performLogin(AuthenticationRequest request) {
//    try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
//      Twitter twitter = new TwitterFactory().getInstance();
//      twitter.setOAuthConsumer(getConfig().getClientId(), vaultStringSecret.get().orElse(getConfig().getClientSecret()));
//
//      URI uri = new URI(request.getRedirectUri() + "?state=" + request.getState().getEncoded());
//
//      RequestToken requestToken = twitter.getOAuthRequestToken(uri.toString());
//      AuthenticationSessionModel authSession = request.getAuthenticationSession();
//
//      authSession.setAuthNote(TWITTER_TOKEN, requestToken.getToken());
//      authSession.setAuthNote(TWITTER_TOKENSECRET, requestToken.getTokenSecret());
//
//      URI authenticationUrl = URI.create(requestToken.getAuthenticationURL());
//
//      return Response.seeOther(authenticationUrl).build();
//    } catch (Exception e) {
//      throw new IdentityBrokerException("Could send authentication request to twitter.", e);
//    }
//  }

//  @Override
//  public Response exchangeFromToken(UriInfo uriInfo, EventBuilder builder, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject, MultivaluedMap<String, String> params) {
//    String requestedType = params.getFirst(OAuth2Constants.REQUESTED_TOKEN_TYPE);
//    if (requestedType != null && !requestedType.equals(TWITTER_TOKEN_TYPE)) {
//      return exchangeUnsupportedRequiredType();
//    }
//    if (!getConfig().isStoreToken()) {
//      String brokerId = tokenUserSession.getNote(Details.IDENTITY_PROVIDER);
//      if (brokerId == null || !brokerId.equals(getConfig().getAlias())) {
//        return exchangeNotLinkedNoStore(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
//      }
//      return exchangeSessionToken(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
//    } else {
//      return exchangeStoredToken(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
//    }
//  }

//  protected Response exchangeStoredToken(UriInfo uriInfo, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
//    FederatedIdentityModel model = session.users().getFederatedIdentity(authorizedClient.getRealm(), tokenSubject, getConfig().getAlias());
//    if (model == null || model.getToken() == null) {
//      return exchangeNotLinked(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
//    }
//    String accessToken = model.getToken();
//    if (accessToken == null) {
//      model.setToken(null);
//      session.users().updateFederatedIdentity(authorizedClient.getRealm(), tokenSubject, model);
//      return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
//    }
//    AccessTokenResponse tokenResponse = new AccessTokenResponse();
//    tokenResponse.setToken(accessToken);
//    tokenResponse.setIdToken(null);
//    tokenResponse.setRefreshToken(null);
//    tokenResponse.setRefreshExpiresIn(0);
//    tokenResponse.getOtherClaims().clear();
//    tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, TWITTER_TOKEN_TYPE);
//    tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
//    return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
//  }

//  protected Response exchangeSessionToken(UriInfo uriInfo, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
//    String accessToken = tokenUserSession.getNote(IdentityProvider.FEDERATED_ACCESS_TOKEN);
//    if (accessToken == null) {
//      return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
//    }
//    AccessTokenResponse tokenResponse = new AccessTokenResponse();
//    tokenResponse.setToken(accessToken);
//    tokenResponse.setIdToken(null);
//    tokenResponse.setRefreshToken(null);
//    tokenResponse.setRefreshExpiresIn(0);
//    tokenResponse.getOtherClaims().clear();
//    tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, TWITTER_TOKEN_TYPE);
//    tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
//    return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
//  }

//
//  protected class Endpoint {
//    protected RealmModel realm;
//    protected AuthenticationCallback callback;
//    protected EventBuilder event;
//
//    @Context
//    protected KeycloakSession session;
//
//    @Context
//    protected ClientConnection clientConnection;
//
//    @Context
//    protected HttpHeaders headers;
//
//    public Endpoint(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
//      this.realm = realm;
//      this.callback = callback;
//      this.event = event;
//    }
//
//    @GET
//    public Response authResponse(@QueryParam("state") String state,
//        @QueryParam("denied") String denied,
//        @QueryParam("oauth_verifier") String verifier) {
//      IdentityBrokerState idpState = IdentityBrokerState.encoded(state);
//      String clientId = idpState.getClientId();
//      String tabId = idpState.getTabId();
//      if (clientId == null || tabId == null) {
//        logger.errorf("Invalid state parameter: %s", state);
//        sendErrorEvent();
//        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
//      }
//
//      ClientModel client = realm.getClientByClientId(clientId);
//      AuthenticationSessionModel authSession = ClientSessionCode.getClientSession(state, tabId, session, realm, client, event, AuthenticationSessionModel.class);
//
//      if (denied != null) {
//        return callback.cancelled();
//      }
//
//      try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
//        Twitter twitter = new TwitterFactory(new ConfigurationBuilder().setIncludeEmailEnabled(true).build()).getInstance();
//        twitter.setOAuthConsumer(getConfig().getClientId(), vaultStringSecret.get().orElse(getConfig().getClientSecret()));
//
//        String twitterToken = authSession.getAuthNote(TWITTER_TOKEN);
//        String twitterSecret = authSession.getAuthNote(TWITTER_TOKENSECRET);
//
//        RequestToken requestToken = new RequestToken(twitterToken, twitterSecret);
//
//        AccessToken oAuthAccessToken = twitter.getOAuthAccessToken(requestToken, verifier);
//        twitter4j.User twitterUser = twitter.verifyCredentials();
//
//        BrokeredIdentityContext identity = new BrokeredIdentityContext(Long.toString(twitterUser.getId()));
//        identity.setIdp(MeetupIdentityProvider.this);
//
//        identity.setUsername(twitterUser.getScreenName());
//        identity.setEmail(twitterUser.getEmail());
//        identity.setName(twitterUser.getName());
//
//
//        StringBuilder tokenBuilder = new StringBuilder();
//
//        tokenBuilder.append("{");
//        tokenBuilder.append("\"oauth_token\":").append("\"").append(oAuthAccessToken.getToken()).append("\"").append(",");
//        tokenBuilder.append("\"oauth_token_secret\":").append("\"").append(oAuthAccessToken.getTokenSecret()).append("\"").append(",");
//        tokenBuilder.append("\"screen_name\":").append("\"").append(oAuthAccessToken.getScreenName()).append("\"").append(",");
//        tokenBuilder.append("\"user_id\":").append("\"").append(oAuthAccessToken.getUserId()).append("\"");
//        tokenBuilder.append("}");
//        String token = tokenBuilder.toString();
//        if (getConfig().isStoreToken()) {
//          identity.setToken(token);
//        }
//        identity.getContextData().put(IdentityProvider.FEDERATED_ACCESS_TOKEN, token);
//
//        identity.setIdpConfig(getConfig());
//        identity.setAuthenticationSession(authSession);
//
//        return callback.authenticated(identity);
//      } catch (WebApplicationException e) {
//        sendErrorEvent();
//        return e.getResponse();
//      } catch (Exception e) {
//        logger.error("Couldn't get user profile from twitter.", e);
//        sendErrorEvent();
//        return ErrorPage.error(session, authSession, Response.Status.BAD_GATEWAY, Messages.UNEXPECTED_ERROR_HANDLING_RESPONSE);
//      }
//    }
//
//    private void sendErrorEvent() {
//      event.event(EventType.LOGIN);
//      event.error("twitter_login_failed");
//    }
//
//  }

//  @Override
//  public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
//    return Response.ok(identity.getToken()).type(MediaType.APPLICATION_JSON).build();
//  }
//
//  @Override
//  public void authenticationFinished(AuthenticationSessionModel authSession, BrokeredIdentityContext context) {
//    authSession.setUserSessionNote(IdentityProvider.FEDERATED_ACCESS_TOKEN, (String)context.getContextData().get(IdentityProvider.FEDERATED_ACCESS_TOKEN));
//  }

}
