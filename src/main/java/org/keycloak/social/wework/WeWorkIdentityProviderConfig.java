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

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;

public class WeWorkIdentityProviderConfig extends OAuth2IdentityProviderConfig {

  public WeWorkIdentityProviderConfig(IdentityProviderModel model) {
    super(model);
  }

  public WeWorkIdentityProviderConfig() {}

  @Override
  public String getAuthorizationUrl() {
    return "https://open.weixin.qq.com/connect/oauth2/authorize";
  }

  @Override
  public String getTokenUrl() {
    return "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo";
  }

  @Override
  public String getUserInfoUrl() {
    return "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserdetail";
  }

  public String getAgentId() {
    String clientId = getClientId();
    if (clientId == null) {
      return null;
    }
    String[] parts = clientId.split(":");
    if (parts.length != 2) {
      return null;
    }
    return parts[1];
  }

  public String getCorpSecret() {
    return getClientSecret();
  }

  public String getCorpId() {
    String clientId = getClientId();
    if (clientId == null) {
      return null;
    }
    String[] parts = clientId.split(":");
    if (parts.length != 2) {
      return null;
    }
    return parts[0];
  }

  @Override
  public void validate(RealmModel realm) {
    super.validate(realm);
    if (getCorpId() == null) {
      throw new RuntimeException("Corp ID not configured");
    }
    if (getCorpSecret() == null) {
      throw new RuntimeException("Corp Secret not configured");
    }
    if (getAgentId() == null) {
      throw new RuntimeException("Agent ID not configured");
    }
  }
}
