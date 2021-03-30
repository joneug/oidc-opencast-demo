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

import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;

public class CachedJWT {

  private final String signature;
  private final Date expiresAt;
  private final String username;

  public CachedJWT(DecodedJWT jwt, String username) {
    this.signature = jwt.getSignature();
    this.expiresAt = jwt.getExpiresAt();
    this.username = username;
  }

  public boolean hasExpired() {
    return !this.expiresAt.after(new Date());
  }

  public String getSignature() {
    return signature;
  }

  public Date getExpiresAt() {
    return expiresAt;
  }

  public String getUsername() {
    return username;
  }

}
