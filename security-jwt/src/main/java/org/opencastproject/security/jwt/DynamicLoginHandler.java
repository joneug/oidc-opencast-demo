/**
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.security.jwt;

import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UserDirectoryService;
import org.opencastproject.security.impl.jpa.JpaOrganization;
import org.opencastproject.security.impl.jpa.JpaRole;
import org.opencastproject.security.impl.jpa.JpaUserReference;
import org.opencastproject.userdirectory.api.UserReferenceProvider;

import com.auth0.jwk.JwkException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class DynamicLoginHandler implements InitializingBean, JWTLoginHandler {

  private static final Logger logger = LoggerFactory.getLogger(DynamicLoginHandler.class);

  private UserDetailsService userDetailsService = null;
  private UserDirectoryService userDirectoryService = null;
  private UserReferenceProvider userReferenceProvider = null;
  private SecurityService securityService = null;
  private String jwksUrl = null;
  private int jwksCacheExpiresIn = 10;
  private String secret = null;
  private List<String> expectedAlgorithms = null;
  private List<String> claimConstraints = null;
  private String usernameMapping = null;
  private String nameMapping = null;
  private String emailMapping = null;
  private List<String> roleMappings = null;
  private GuavaCachedUrlJwkProvider jwkProvider;
  private int jwtCacheSize = 500;
  private int jwtCacheExpiresIn = 60;
  private Cache<String, CachedJWT> cache;

  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(userDetailsService, "A UserDetailsService must be set");
    Assert.notNull(userDirectoryService, "A UserDirectoryService must be set");
    Assert.notNull(userReferenceProvider, "A UserReferenceProvider must be set");
    Assert.notNull(securityService, "A SecurityService must be set");
    Assert.isTrue(StringUtils.isNotBlank(jwksUrl) ^ StringUtils.isNotBlank(secret),
        "Either a JWKS URL or a secret must be set");
    Assert.notEmpty(expectedAlgorithms, "Expected algorithms must be set");
    Assert.notEmpty(claimConstraints, "Claim constraints must be set");
    Assert.notNull(usernameMapping, "User name mapping must be set");
    Assert.notNull(nameMapping, "Name mapping must be set");
    Assert.notNull(emailMapping, "Email mapping must be set");
    Assert.notEmpty(roleMappings, "Role mappings must be set");

    jwkProvider = new GuavaCachedUrlJwkProvider(jwksUrl, jwksCacheExpiresIn, TimeUnit.MINUTES);
    userReferenceProvider.setRoleProvider(new JWTRoleProvider(securityService, userReferenceProvider));
    cache = CacheBuilder.newBuilder()
        .maximumSize(jwtCacheSize)
        .expireAfterWrite(jwtCacheExpiresIn, TimeUnit.MINUTES)
        .build();
  }

  @Override
  public String handleToken(String token) {
    try {
      String signature = extractSignature(token);
      CachedJWT cachedJwt = cache.getIfPresent(signature);

      if (cachedJwt == null) {
        // JWT hasn't been cached before, so validate all claims
        DecodedJWT jwt = decodeAndVerify(token);
        String username = extractUsername(jwt);

        try {
          if (userDetailsService.loadUserByUsername(username) != null) {
            existingUserLogin(username, jwt);
          }
        } catch (UsernameNotFoundException e) {
          newUserLogin(username, jwt);
          userDirectoryService.invalidate(username);
        }

        cache.put(jwt.getSignature(), new CachedJWT(jwt, username));
        return username;
      } else {
        // JWT has been cached before, so only check if it has expired
        if (cachedJwt.hasExpired()) {
          cache.invalidate(signature);
          throw new JWTVerificationException("JWT token is not valid anymore");
        }
        logger.debug("Using decoded and validated JWT from cache");
        return cachedJwt.getUsername();
      }
    } catch (JWTVerificationException | JwkException exception) {
      logger.error(exception.getMessage());
    }

    return null;
  }

  private DecodedJWT decodeAndVerify(String token) throws JwkException {
    DecodedJWT jwt;
    if (jwksUrl != null) {
      jwt = JWTVerifier.verify(token, jwkProvider, claimConstraints);
    } else {
      jwt = JWTVerifier.verify(token, secret, claimConstraints);
    }
    return jwt;
  }

  private String extractSignature(String token) {
    String[] parts = token.split("\\.");
    if (parts.length != 3) {
      throw new JWTDecodeException("Given token is not in a valid JWT format");
    }
    return parts[2];
  }

  private String extractUsername(DecodedJWT jwt) {
    String username = evaluateMapping(jwt, usernameMapping, false);
    Assert.isTrue(StringUtils.isNotBlank(username), "Extracted username is blank");
    return username;
  }

  private String extractName(DecodedJWT jwt) {
    String name = evaluateMapping(jwt, nameMapping, true);
    Assert.isTrue(StringUtils.isNotBlank(name), "Extracted name is blank");
    return name;
  }

  private String extractEmail(DecodedJWT jwt) {
    String email = evaluateMapping(jwt, emailMapping, true);
    Assert.isTrue(StringUtils.isNotBlank(email), "Extracted email is blank");
    return email;
  }

  private Set<JpaRole> extractRoles(DecodedJWT jwt) {
    JpaOrganization organization = fromOrganization(securityService.getOrganization());
    Set<JpaRole> roles = new HashSet<>();
    for (String mapping : roleMappings) {
      String role = evaluateMapping(jwt, mapping, false);
      if (StringUtils.isNotBlank(role)) {
        roles.add(new JpaRole(role, organization));
      }
    }
    Assert.notEmpty(roles, "No roles could be extracted");
    return roles;
  }

  private String evaluateMapping(DecodedJWT jwt, String mapping, boolean ensureEncoding) {
    ExpressionParser parser = new SpelExpressionParser();
    Expression exp = parser.parseExpression(mapping);
    String value = exp.getValue(jwt.getClaims(), String.class);
    if (ensureEncoding) {
      value = new String(value.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
    }
    return value;
  }

  public void newUserLogin(String username, DecodedJWT jwt) {
    // Create a new user reference
    JpaUserReference userReference = new JpaUserReference(username, extractName(jwt), extractEmail(jwt), MECH_JWT,
        new Date(), fromOrganization(securityService.getOrganization()), extractRoles(jwt));

    logger.debug("JWT user '{}' logged in for the first time", username);
    userReferenceProvider.addUserReference(userReference, MECH_JWT);
  }

  public void existingUserLogin(String username, DecodedJWT jwt) {
    Organization organization = securityService.getOrganization();

    // Load the user reference
    JpaUserReference userReference = userReferenceProvider.findUserReference(username, organization.getId());
    if (userReference == null) {
      throw new UsernameNotFoundException("User reference '" + username + "' was not found");
    }

    // Update the reference
    userReference.setName(extractName(jwt));
    userReference.setEmail(extractEmail(jwt));
    userReference.setLastLogin(new Date());
    userReference.setRoles(extractRoles(jwt));

    logger.debug("JWT user '{}' logged in", username);
    userReferenceProvider.updateUserReference(userReference);
  }

  private JpaOrganization fromOrganization(Organization org) {
    if (org instanceof JpaOrganization) {
      return (JpaOrganization) org;
    }

    return new JpaOrganization(org.getId(), org.getName(), org.getServers(), org.getAdminRole(), org.getAnonymousRole(),
        org.getProperties());
  }

  public void setUserDetailsService(UserDetailsService userDetailsService) {
    this.userDetailsService = userDetailsService;
  }

  public void setUserDirectoryService(UserDirectoryService userDirectoryService) {
    this.userDirectoryService = userDirectoryService;
  }

  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  public void setUserReferenceProvider(UserReferenceProvider userReferenceProvider) {
    this.userReferenceProvider = userReferenceProvider;
  }

  public void setJwksUrl(String jwksUrl) {
    this.jwksUrl = jwksUrl;
  }

  public void setJwksCacheExpiresIn(int jwksCacheExpiresIn) {
    this.jwksCacheExpiresIn = jwksCacheExpiresIn;
  }

  public void setSecret(String secret) {
    this.secret = secret;
  }

  public void setExpectedAlgorithms(List<String> expectedAlgorithms) {
    this.expectedAlgorithms = expectedAlgorithms;
  }

  public void setClaimConstraints(List<String> claimConstraints) {
    this.claimConstraints = claimConstraints;
  }

  public void setUsernameMapping(String usernameMapping) {
    this.usernameMapping = usernameMapping;
  }

  public void setNameMapping(String nameMapping) {
    this.nameMapping = nameMapping;
  }

  public void setEmailMapping(String emailMapping) {
    this.emailMapping = emailMapping;
  }

  public void setRoleMappings(List<String> roleMappings) {
    this.roleMappings = roleMappings;
  }

  public void setJwtCacheSize(int jwtCacheSize) {
    this.jwtCacheSize = jwtCacheSize;
  }

  public void setJwtCacheExpiresIn(int jwtCacheExpiresIn) {
    this.jwtCacheExpiresIn = jwtCacheExpiresIn;
  }

}
