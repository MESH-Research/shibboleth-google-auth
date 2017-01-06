/*
* Copyright (C) 2017 Modern Language Association
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
* except in compliance with the License. You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable law or agreed to in writing, software distributed under
* the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/

package org.mla.cbox.shibboleth.idp.authn.impl;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.net.URLEncoder;
import java.io.UnsupportedEncodingException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

import org.opensaml.messaging.context.BaseContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Context, usually attached to {@link AuthenticationContext}, that carries a GoogleIdToken
 */
public class GoogleContext extends BaseContext {
    /** Anti forgery state token  */
    @Nullable private String antiForgeryStateToken = null;
    
    /** Google integration details */
    @Nullable private GoogleIntegration googleIntegration = null;
    
    /** The Google Id token string */
    @Nullable private String googleIdTokenString = null;
    
    /** The OIDC ID token */
    @Nullable private OidcIdToken IdToken = null;
    
    /** The OAuth2 redirect_uri */
    @Nullable private String redirectUri = null;
    
    /** Class logger */
    @Nonnull private final Logger log = LoggerFactory.getLogger(GoogleContext.class);
    
    /** Log prefix */
    @Nonnull private final String logPrefix = getClass().getSimpleName() + ":";
    
    /** Constructor */
    public GoogleContext() {
        
    }
    
    /**
     * Get the anti forgery state token
     * 
     * @return token as String
     */
    @Nullable public String getAntiForgeryStateToken() {
        return this.antiForgeryStateToken;
    }
    
     /**
      * Get the URL UTF-8 encoded redirect_uri
      * 
      * @return encoded redirect URI as String
      */
     @Nullable public String getEncodedRedirectUri() {
         String encodedRedirectUri = null;
         try {
             encodedRedirectUri = URLEncoder.encode(this.redirectUri, "UTF-8");
         } catch (UnsupportedEncodingException e) {
             log.warn("{} Caught UnsupportedEncodingException when attempting to encode redirect_uri {} : {}", logPrefix, this.redirectUri, e.getMessage());
             encodedRedirectUri = this.redirectUri;
         }
         
         return encodedRedirectUri;
     }
     
     @Nullable public String getEncodedRedirectUri(String scheme, String serverName, String flowExecutionUrl) {
         this.redirectUri = this.getRedirectUri(scheme, serverName, flowExecutionUrl);
         return this.getEncodedRedirectUri();
     }
    
    /**
     * Get the Google integration
     * 
     * @return the Google integration object
     */
    @Nullable public GoogleIntegration getGoogleIntegration() {
        return this.googleIntegration;
    }
    
    /**
     * Get the ID token string to be validated
     * 
     * @return the ID token string to be validated
     */
    @Nullable public String getGoogleIdTokenString() {
        return this.googleIdTokenString;
    }
    
    /**
     * Get the ID token
     * 
     * @return the ID token
     */
     @Nullable public OidcIdToken getIdToken() {
         return this.IdToken;
     }
     
     /**
      * Get the redirect_uri
      * 
      * @return redirect URI as String
      */
     @Nullable public String getRedirectUri() {
         return this.redirectUri;
     }
     
     /**
      * Get the redirect_uri
      * 
      * @param scheme
      * @param serverName
      * @param flowExecutionUrl
      * 
      * @return redirect URI as String
      */
     @Nullable public String getRedirectUri(String scheme, String serverName, String flowExecutionUrl) {
         StringBuilder redirectUriBuilder = new StringBuilder().append(scheme)
                 .append("://")
                 .append(serverName)
                 .append(flowExecutionUrl)
                 .append("&_eventId=proceed");
         
         this.redirectUri = redirectUriBuilder.toString();
         
         return this.redirectUri;
     }
     
     /**
      * Compute the Google OAuth2 authentication URL
      * 
      * @return the URL
      */
     public String googleOauth2Url(HttpServletRequest request, String flowExecutionUrl) {
         StringBuilder oauth2Url = new StringBuilder().append(this.googleIntegration.getOauth2Url())
                 .append("?client_id=").append(this.googleIntegration.getOauth2ClientId())
                 .append("&response_type=code")
                 .append("&scope=openid%20email%20profile")
                 .append("&redirect_uri=").append(this.getEncodedRedirectUri(request.getScheme(),request.getServerName(), flowExecutionUrl))
                 .append("&prompt=select_account")
                 .append("&state=").append(this.getAntiForgeryStateToken());
                 
         log.debug("{} computed Google OAuth2 Url is {}", this.logPrefix, oauth2Url.toString());
         
         return oauth2Url.toString();
     }
     
     /**
      * Initialize the anti forgery state token
      * 
      */
     public void initializeAntiForgeryStateToken() {
         this.antiForgeryStateToken = new BigInteger(130, new SecureRandom()).toString(32);
     }
     
    /**
     * Set the ID token string to be validated
     * 
     * @param ID token string to be validated
     * 
     * @return this context
     */
    public GoogleContext setGoogleIdTokenString(@Nullable final String tokenString) {
        this.googleIdTokenString = tokenString;
        return this;
    }
    
    /**
     * Set the validated ID token
     * 
     * @param token the Google Id token
     * 
     * @return this context
     */
    public GoogleContext setIdToken(@Nullable final OidcIdToken token) {
        this.IdToken = token;
        return this;
    }
    
    /**
     * Set the Google integration.
     * 
     * @param googleIntegration the Google integration
     * 
     * @return this context
     */
    public GoogleContext setGoogleIntegration(@Nullable final GoogleIntegration googleIntegration) {
        this.googleIntegration = googleIntegration;
        return this;
    }
}
