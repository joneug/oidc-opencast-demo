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

import com.auth0.jwk.JwkException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.apache.commons.lang3.StringUtils;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.util.Assert;

import java.util.List;

public final class JWTVerifier {

  private JWTVerifier() { }

  public static DecodedJWT verify(String token, GuavaCachedUrlJwkProvider provider, List<String> claimConstraints)
          throws JwkException, JWTVerificationException {
    Assert.notNull(token, "A token must be set");
    Assert.notNull(provider, "A JWKS provider must be set");

    DecodedJWT jwt = JWT.decode(token);

    // First try with cache...
    List<Algorithm> algorithms = provider.getAlgorithms(jwt, false);
    try {
      return verify(jwt, claimConstraints, algorithms);
    } catch (JWTVerificationException e) {
      // ...then try again with forced fetch
      // (recommended by e.g. https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys)
      algorithms = provider.getAlgorithms(jwt, true);
      return verify(jwt, claimConstraints, algorithms);
    }
  }

  public static DecodedJWT verify(String token, String secret, List<String> claimConstraints)
          throws JWTVerificationException {
    Assert.notNull(token, "A token must be set");
    Assert.isTrue(StringUtils.isNotBlank(secret), "A secret must be set");

    DecodedJWT jwt = JWT.decode(token);
    return verify(jwt, claimConstraints, AlgorithmBuilder.buildAlgorithm(jwt, secret));
  }

  public static DecodedJWT verify(DecodedJWT jwt, List<String> claimConstraints, List<Algorithm> algorithms)
          throws JWTVerificationException {
    return verify(jwt, claimConstraints, algorithms.toArray(new Algorithm[0]));
  }

  public static DecodedJWT verify(DecodedJWT jwt, List<String> claimConstraints, Algorithm... algorithms)
          throws JWTVerificationException {
    Assert.notNull(jwt, "A decoded JWT must be set");
    Assert.notEmpty(claimConstraints, "Claim constraints must be set");
    Assert.notEmpty(algorithms, "Algorithms must be set");
    Assert.isTrue(algorithmsMatch(algorithms), "Algorithms must be of same class");

    boolean verified = false;
    Exception lastException = new JWTVerificationException("JWT could not be verified");
    for (Algorithm algorithm : algorithms) {
      try {
        // General verification
        JWT.require(algorithm).build().verify(jwt);

        // Claim constraints verification
        ExpressionParser parser = new SpelExpressionParser();
        for (String constraint : claimConstraints) {
          Expression exp = parser.parseExpression(constraint);
          if (!exp.getValue(jwt.getClaims(), Boolean.class)) {
            throw new JWTVerificationException("The claims did not fulfill constraint \"" + constraint + "\"");
          }
        }

        // Verification was successful if no exception has been thrown
        verified = true;
        break;
      } catch (JWTVerificationException | EvaluationException | ParseException e) {
        // Ignore for now and try next algorithm
        lastException = e;
      }
    }

    // If verification was not successful until here, throw last known exception
    if (!verified) {
      throw new JWTVerificationException(lastException.getMessage());
    }

    return jwt;
  }

  private static boolean algorithmsMatch(Algorithm... algorithms) {
    for (int i = 1; i < algorithms.length; i++) {
      if (!algorithms[i].getClass().equals(algorithms[0].getClass())) {
        return false;
      }
    }
    return true;
  }

}
