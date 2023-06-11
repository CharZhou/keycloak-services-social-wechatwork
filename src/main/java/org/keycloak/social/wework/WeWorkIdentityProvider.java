/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.social.wework;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.infinispan.Cache;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

public class WeWorkIdentityProvider
    extends AbstractOAuth2IdentityProvider<WeWorkIdentityProviderConfig>
    implements SocialIdentityProvider<WeWorkIdentityProviderConfig> {
  static final String ACCESS_TOKEN_CACHE_KEY = "wechat_work_agent_access_token";
  static final String AGENT_ACCESS_TOKEN_URL = "https://qyapi.weixin.qq.com/cgi-bin/gettoken";
  static final String WEWORK_AUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize";
  static final String TOKEN_URL = "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo";
  static final String USER_INFO_URL = "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserdetail";
  static final String DEFAULT_SCOPE = "snsapi_privateinfo";
  static final String USER_TICKET = "user_ticket";
  static final String CORP_ID = "corpid";
  static final String CORP_SECRET = "corpsecret";
  static final String ACCESS_TOKEN = "access_token";
  static final String EXPIRES_IN = "expires_in";
  static final String ERROR_CODE = "errcode";
  static final String ERROR_MESSAGE = "errmsg";
  static final String USER_ID = "userid";
  static final String EMAIL = "biz_mail";

  static final String APPID = "appid";
  static final String AGENT_ID = "agentid";

  protected static ObjectMapper mapper = new ObjectMapper();

  private static final DefaultCacheManager cacheManager = new DefaultCacheManager();

  private static final ConcurrentMap<String, Cache<String, String>> caches =
      new ConcurrentHashMap<>();

  private static Cache<String, String> createCache(String suffix) {
    String cacheName = WeWorkIdentityProviderFactory.PROVIDER_ID + ":" + suffix;
    cacheManager.defineConfiguration(cacheName, new ConfigurationBuilder().build());
    return cacheManager.getCache(cacheName);
  }

  private Cache<String, String> getCache() {
    return caches.computeIfAbsent(
        getConfig().getClientId() + ":" + getConfig().getAgentId(),
        WeWorkIdentityProvider::createCache);
  }

  private String getAccessToken() {
    String token = getCache().get(ACCESS_TOKEN_CACHE_KEY);
    if (token == null) {
      token = renewAccessToken();
    }
    return token;
  }

  private String renewAccessToken() {
    JsonNode data;
    try {
      data =
          SimpleHttp.doGet(AGENT_ACCESS_TOKEN_URL, session)
              .param(CORP_ID, getConfig().getClientId())
              .param(CORP_SECRET, getConfig().getClientSecret())
              .asJson();
    } catch (Exception e) {
      throw new IdentityBrokerException("Failed to renew access token", e);
    }
    if (data == null) {
      throw new IdentityBrokerException("Failed to renew access token, data is null");
    }
    int errorCode = data.get(ERROR_CODE).asInt();
    String errorMsg = data.get(ERROR_MESSAGE).asText();
    if (errorCode != 0) {
      throw new IdentityBrokerException(
          "Failed to renew access token, error code: "
              + errorCode
              + ", error message: "
              + errorMsg);
    }
    String accessToken = data.get(ACCESS_TOKEN).asText();
    int expiresIn = data.get(EXPIRES_IN).asInt();
    getCache().put(ACCESS_TOKEN_CACHE_KEY, accessToken, expiresIn, TimeUnit.SECONDS);

    return accessToken;
  }

  public WeWorkIdentityProvider(KeycloakSession session, WeWorkIdentityProviderConfig config) {
    super(session, config);
    config.setAuthorizationUrl(WEWORK_AUTH_URL);
    config.setTokenUrl(TOKEN_URL);
    config.setUserInfoUrl(USER_INFO_URL);
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return new WeWorkAuthenticationEndpoint(callback, realm, event, this);
  }

  protected String getAccessTokenResponseParameter() {
    return USER_TICKET;
  }

  @Override
  protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
    BrokeredIdentityContext user;
    try {
      JsonNode data = buildUserInfoRequest(accessToken, getConfig().getUserInfoUrl()).asJson();
      //      logger.info("doGetFederatedIdentity data: " + data.toString());
      int errorCode = data.get(ERROR_CODE).asInt();
      String errorMsg = data.get(ERROR_MESSAGE).asText();
      if (errorCode != 0) {
        throw new IdentityBrokerException(errorMsg);
      }

      user = extractIdentityFromProfile(null, data);
    } catch (Exception e) {
      throw new IdentityBrokerException("Failed to get federated identity", e);
    }
    return user;
  }

  @Override
  protected boolean supportsExternalExchange() {
    return true;
  }

  @Override
  protected String getProfileEndpointForValidation(EventBuilder event) {
    return USER_INFO_URL;
  }

  @Override
  protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode node) {
    String userId = getJsonProperty(node, USER_ID);
    String email = getJsonProperty(node, EMAIL);

    BrokeredIdentityContext user = new BrokeredIdentityContext(userId);

    user.setUsername(userId);
    user.setEmail(email);

    user.setIdpConfig(getConfig());
    user.setIdp(this);

    AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, node, getConfig().getAlias());
    return user;
  }

  @Override
  protected SimpleHttp buildUserInfoRequest(String subjectToken, String userInfoUrl) {
    ObjectNode node = mapper.createObjectNode();
    node.put(USER_TICKET, subjectToken);

    String uri =
        UriBuilder.fromUri(userInfoUrl)
            .queryParam(ACCESS_TOKEN, getAccessToken())
            .build()
            .toString();
    return SimpleHttp.doPost(uri, session).json(node);
  }

  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
    UriBuilder uriBuilder = super.createAuthorizationUrl(request);

    uriBuilder.queryParam(AGENT_ID, getConfig().getAgentId());
    uriBuilder.queryParam(APPID, getConfig().getClientId());
    uriBuilder.replaceQueryParam(OAUTH2_PARAMETER_CLIENT_ID, null);
    uriBuilder.fragment("wechat_redirect");

    return uriBuilder;
  }

  @Override
  protected String getDefaultScopes() {
    return DEFAULT_SCOPE;
  }

  @Override
  public SimpleHttp authenticateTokenRequest(SimpleHttp tokenRequest) {
    return tokenRequest.param(ACCESS_TOKEN, getAccessToken());
  }

  protected static class WeWorkAuthenticationEndpoint {
    protected final AuthenticationCallback callback;
    protected final RealmModel realm;
    protected final EventBuilder event;
    private final WeWorkIdentityProvider provider;

    protected final KeycloakSession session;

    protected final ClientConnection clientConnection;

    protected final HttpHeaders headers;

    protected final HttpRequest httpRequest;

    public WeWorkAuthenticationEndpoint(
        AuthenticationCallback callback,
        RealmModel realm,
        EventBuilder event,
        WeWorkIdentityProvider provider) {
      this.callback = callback;
      this.realm = realm;
      this.event = event;
      this.provider = provider;
      this.session = provider.session;
      this.clientConnection = session.getContext().getConnection();
      this.httpRequest = session.getContext().getHttpRequest();
      this.headers = session.getContext().getRequestHeaders();
    }

    @GET
    public Response authResponse(
        @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
        @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
        @QueryParam(OAuth2Constants.ERROR) String error) {
      if (state == null) {
        return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_STATE_ERROR);
      }

      try {
        AuthenticationSessionModel authSession =
            this.callback.getAndVerifyAuthenticationSession(state);
        session.getContext().setAuthenticationSession(authSession);

        WeWorkIdentityProviderConfig providerConfig = provider.getConfig();

        if (error != null) {
          logger.error(error + " for broker login " + providerConfig.getProviderId());
          if (error.equals(ACCESS_DENIED)) {
            return callback.cancelled(providerConfig);
          } else if (error.equals(OAuthErrorException.LOGIN_REQUIRED)
              || error.equals(OAuthErrorException.INTERACTION_REQUIRED)) {
            return callback.error(error);
          } else {
            return callback.error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
          }
        }

        if (authorizationCode != null) {
          String response = generateTokenRequest(authorizationCode).asString();

          JsonNode data = mapper.readTree(response);
          int errorCode = data.get(ERROR_CODE).asInt();
          if (errorCode != 0) {
            String errorMsg = data.get(ERROR_MESSAGE).asText();
            logger.error(
                "Failed to get access token, errcode: " + errorCode + ", errmsg: " + errorMsg);
            return errorIdentityProviderLogin(errorMsg);
          }

          BrokeredIdentityContext federatedIdentity = provider.getFederatedIdentity(response);

          if (providerConfig.isStoreToken()) {
            if (federatedIdentity.getToken() == null) {
              federatedIdentity.setToken(response);
            }
          }

          federatedIdentity.setIdpConfig(providerConfig);
          federatedIdentity.setIdp(provider);
          federatedIdentity.setAuthenticationSession(authSession);

          return callback.authenticated(federatedIdentity);
        }
      } catch (WebApplicationException e) {
        return e.getResponse();
      } catch (Exception e) {
        logger.error("Failed to make identity provider oauth callback", e);
      }
      return errorIdentityProviderLogin(Messages.ACCESS_DENIED);
    }

    private Response errorIdentityProviderLogin(String message) {
      event.event(EventType.IDENTITY_PROVIDER_LOGIN);
      event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
      return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, message);
    }

    public SimpleHttp generateTokenRequest(String authorizationCode) {
      WeWorkIdentityProviderConfig providerConfig = provider.getConfig();
      SimpleHttp tokenRequest =
          SimpleHttp.doGet(providerConfig.getTokenUrl(), session)
              .param(OAUTH2_PARAMETER_CODE, authorizationCode);

      return provider.authenticateTokenRequest(tokenRequest);
    }
  }
}
