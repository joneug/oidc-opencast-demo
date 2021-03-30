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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Strings.isNullOrEmpty;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.SigningKeyNotFoundException;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * Jwk provider that caches previously fetched JWKs in memory using a Google Guava cache
 */
public class GuavaCachedUrlJwkProvider extends UrlJwkProvider {

  /**
   * The logging facility
   */
  private static final Logger logger = LoggerFactory.getLogger(GuavaCachedUrlJwkProvider.class);

  private final Cache<String, List<Jwk>> cache;
  static final String KEY = "GET_ALL";

  /**
   * Creates a new provider that will cache up the JWKs for at most 10 minutes.
   *
   * @param jwksUrl The URL where JWKs are published.
   */
  public GuavaCachedUrlJwkProvider(String jwksUrl) {
    this(jwksUrl, 10, TimeUnit.MINUTES);
  }

  /**
   * Creates a new cached provider specifying the JWKs URL and TTL.
   *
   * @param jwksUrl     URL where JWKs are published.
   * @param expiresIn   Amount of time the fetched JWKs will live in the cache.
   * @param expiresUnit Unit of the expiresIn parameter.
   */
  public GuavaCachedUrlJwkProvider(String jwksUrl, long expiresIn, TimeUnit expiresUnit) {
    super(urlFromString(jwksUrl));
    this.cache = CacheBuilder.newBuilder().maximumSize(1).expireAfterWrite(expiresIn, expiresUnit).build();
  }

  static URL urlFromString(String url) {
    checkArgument(!isNullOrEmpty(url), "A URL is required");
    try {
      final URI uri = new URI(url).normalize();
      return uri.toURL();
    } catch (MalformedURLException | URISyntaxException e) {
      throw new IllegalArgumentException("Invalid JWKS URI", e);
    }
  }

  public Jwk get(String keyId, boolean forceFetch) throws JwkException {
    cache.invalidate(KEY);
    return super.get(keyId);
  }

  @Override
  public List<Jwk> getAll() {
    return getAll(false);
  }

  public List<Jwk> getAll(boolean forceFetch) {
    try {
      if (forceFetch) {
        cache.invalidate(KEY);
      }

      List<Jwk> jwks = cache.getIfPresent(KEY);
      if (jwks == null) {
        logger.debug("JWKS cache miss");
        jwks = cache.get(KEY, super::getAll);
      } else {
        logger.debug("JWKS cache hit");
      }

      return jwks;
    } catch (ExecutionException e) {
      logger.error("Error while loading from JWKS cache: " + e.getMessage());
      return Collections.emptyList();
    }
  }

  public List<Algorithm> getAlgorithms(DecodedJWT jwt) throws JwkException {
    return getAlgorithms(jwt, false);
  }

  public List<Algorithm> getAlgorithms(DecodedJWT jwt, boolean forceFetch) throws JwkException {
    List<Algorithm> algorithms = new ArrayList<>();

    for (Jwk jwk : getAll(forceFetch)) {
      if (jwt.getKeyId() == null && jwt.getAlgorithm().equals(jwk.getAlgorithm())
          || jwt.getKeyId() != null && jwt.getKeyId().equals(jwk.getId())) {
        algorithms.add(AlgorithmBuilder.buildAlgorithm(jwk));
      }
    }

    if (algorithms.isEmpty()) {
      throw new SigningKeyNotFoundException("No key found", null);
    }

    return algorithms;
  }

}
