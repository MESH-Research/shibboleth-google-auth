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

import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.client.util.Key;
import com.google.common.base.Strings;

import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;

/**
 * An action that extracts the Google OAuth2 one-time authorization code from the query
 * string after checking the anti forgery state token, then queries the Google OIDC 
 * token endpoint to exchange the one-time authorization code for an OICD ID token.
 *
 */
public class ProcessRedirectFromGoogle extends AbstractValidationAction {
    /** GoogleIdTokenContext containing the Google ID token to validate */
    @Nullable private GoogleContext googleContext;
    
    /** HTTP transport used to query Google token endpoint */
    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    
    /** JSON factory used for interpreting ID token response from Google */
    private static final JsonFactory JSON_FACTORY = new JacksonFactory();

    /** Class logger */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ProcessRedirectFromGoogle.class);

    /** Constructor */
    ProcessRedirectFromGoogle() {
    }
    
    /** Represents token response from Google */
    public static class TokenResponse extends GenericJson {
        @Key
        private String access_token;
        
        @Key
        private String token_type;
        
        @Key
        private Integer expires_in;
        
        @Key
        private String id_token;
        
        public String getIdTokenString () {
            return this.id_token;
        }
    }
    
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        
        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }
        
        if (authenticationContext.getAttemptedFlow() == null) {
            log.info("{} No attempted flow within authentication context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        
        /* Ensure that we have a GoogleContext established during initialization of flow */
        googleContext = authenticationContext.getSubcontext(GoogleContext.class);
        if (googleContext == null) {
            log.info("{} No GoogleIdTokenContext available within authentication context", getLogPrefix());
            handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                    AuthnEventIds.NO_CREDENTIALS);
            return false;
        } 
        
        return true;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        
        /* Ensure we were passed the incoming HTTP request */
        final HttpServletRequest servletRequest = getHttpServletRequest();
        if (servletRequest == null) {
            log.debug("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        
        /* Check the anti forgery state token returned by Google against the saved version in GoogleContext */
        final String antiForgeryStateToken = servletRequest.getParameter("state");
        if (antiForgeryStateToken == null || antiForgeryStateToken.isEmpty()) {
            log.debug("{} No anti forgery state token in request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        
        log.debug("{} Google returned anti forgery state token {}", getLogPrefix(), antiForgeryStateToken);
        
        if (!antiForgeryStateToken.equals(googleContext.getAntiForgeryStateToken())) {
            log.debug("{} Anti forgery state token in request is not equal to token from Google Context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        
        /* Parse the one-time authorization code returned by Google */
        final String authorizationCode = servletRequest.getParameter("code");
        if (authorizationCode == null || authorizationCode.isEmpty()) {
            log.debug("{} No one-time authorization code in request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        
        log.debug("{} Google one-time authorization code is {}", getLogPrefix(), authorizationCode);
        
        /* Query Google token endpoint using the one-time authorization code for an ID token */
        HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory(
                new HttpRequestInitializer() {
                    @Override
                    public void initialize(HttpRequest request) {
                        /* Set default parser as a JSON parser to make casting to class instance easier */
                        request.setParser(new JsonObjectParser(JSON_FACTORY));
                    }
                });
        
        GenericUrl tokenEndpoint = new GenericUrl(googleContext.getGoogleIntegration().getTokenEndpoint());
        
        /* Prepare the POST body required at the token endpoint */
        Map<String, String> params = new HashMap<String, String>(5);
        params.put("code", authorizationCode);
        params.put("grant_type", "authorization_code");
        params.put("client_id", googleContext.getGoogleIntegration().getOauth2ClientId());
        params.put("client_secret", googleContext.getGoogleIntegration().getOauth2ClientSecret());
        params.put("redirect_uri", googleContext.getRedirectUri());
        
        HttpContent httpContent = new UrlEncodedContent(params);
        log.debug("{} computed token endpoint payload is {}", getLogPrefix(), httpContent.toString());
        
        try {
            HttpRequest request = requestFactory.buildPostRequest(tokenEndpoint, httpContent);
            
            log.debug("{} executing POST to Google token endpoint", getLogPrefix());
            HttpResponse response = request.execute();
            log.debug("{} done executing POST to Google token endpoint", getLogPrefix());
            
            /* Cast the response to a TokenResponse class instance */
            TokenResponse tokenResponse = response.parseAs(TokenResponse.class);
            log.debug("{} received token response {}", getLogPrefix(), tokenResponse.toPrettyString());
            
            /* Close the HTTP connection */
            response.disconnect();
            
            /* We do not validate the ID token since we just received it over a secure channel
             * and we are not going to pass it around. We just grab the payload
             * and pad it as necessary so we can then decode the base64 encoding.
             */
            String idTokenPayloadString = tokenResponse.getIdTokenString().split("\\.")[1];
            String idTokenPayloadStringPadded = Strings.padEnd(idTokenPayloadString, idTokenPayloadString.length() + (4 - (idTokenPayloadString.length() % 4)), '=');
            String idTokenPayloadStringDecoded = new String(DatatypeConverter.parseBase64Binary(idTokenPayloadStringPadded));
        
            /* Cast the ID token as instance of OidcIdToken class */
            JsonObjectParser jsonParser = new JsonObjectParser(JSON_FACTORY);
            OidcIdToken idToken = jsonParser.parseAndClose(new StringReader(idTokenPayloadStringDecoded), OidcIdToken.class);
            log.debug("{} id token is {}", getLogPrefix(), idToken.toPrettyString());
        
            /* Attach the ID token to the GoogleContext */
            googleContext.setIdToken(idToken);
        } catch (IOException e) {
            log.warn("{} exception exchanging authorization code for id token : {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        
        log.info("{} Login by '{}' succeeded", getLogPrefix(), googleContext.getIdToken().getSub());
        
        /* Complete the authentication flow by building the authentication result */
        buildAuthenticationResult(profileRequestContext, authenticationContext);
        ActionSupport.buildProceedEvent(profileRequestContext);
    }
    
    /** {@inheritDoc} */
    @Override
    @Nonnull protected Subject populateSubject(@Nonnull final Subject subject) {
        subject.getPrincipals().add(new GoogleIdPrincipal(googleContext.getIdToken()));
        return subject;
    }
}
