/*
 * Copyright 2020 Attribyte, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.
 *
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

package org.attribyte.snook.auth;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * Base class for sequences of authenticators.
 */
public abstract class MultiAuthenticator extends Authenticator {

   public MultiAuthenticator(final List<Authenticator> authenticators, final String schemeName) {
      this.authenticators = authenticators != null ? ImmutableList.copyOf(authenticators) : ImmutableList.of();
      this.schemeName = schemeName + " " +
              Joiner.on(',').join(this.authenticators.stream().map(Authenticator::schemeName).iterator());
   }

   @Override
   public String credentials(final HttpServletRequest request) {
      return null;
   }

   @Override
   protected String scheme() {
      return null;
   }

   @Override
   public String schemeName() {
      return schemeName;
   }

   @Override
   public String credentialsHeader() {
      return null;
   }

   /**
    * The list of authenticators.
    */
   protected final ImmutableList<Authenticator> authenticators;

   /**
    * The scheme name.
    */
   protected final String schemeName;
}
