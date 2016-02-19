package org.mla.cbox.shibboleth.idp.authn.impl;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;

import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;

/**
 * An action that checks for a GoogleContext and directly produces an
 * {@link net.shibboleth.idp.authn.AuthenticationResult} based on that identity.
 * 
 */
public class ValidateGoogleIdToken extends AbstractValidationAction {
    
	/** Class logger */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateGoogleIdToken.class);
    
    /** GoogleIdTokenContext containing the Google ID token to validate */
    @Nullable private GoogleContext googleContext;
    
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
        
        googleContext = authenticationContext.getSubcontext(GoogleContext.class);
        if (googleContext == null) {
            log.info("{} No GoogleIdTokenContext available within authentication context", getLogPrefix());
            handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                    AuthnEventIds.NO_CREDENTIALS);
            return false;
        } else if (googleContext.getGoogleIdTokenString() == null ) {
            log.info("{} No Google ID token string available within GoogleIdTokenContext", getLogPrefix());
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
        
        // Grab Google OAuth2 client ID from the GoogleIntegration object 
        ArrayList<String> clientIds = new ArrayList<String>();
        clientIds.add(this.googleContext.getGoogleIntegration().getOauth2ClientId());
        
        // Use Google Id token verifier object to verify token was properly signed and targeted
    	NetHttpTransport transport = new NetHttpTransport();
        GsonFactory jsonFactory = new GsonFactory();
        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory).setAudience(clientIds).build();
        
        GoogleIdToken googleIdToken;
        
        try {
            log.debug("{} Beginning to verify Google ID token now", getLogPrefix());
			googleIdToken = verifier.verify(googleContext.getGoogleIdTokenString());
            log.debug("{} Done verifying Google ID token", getLogPrefix());
            googleContext.setGoogleIdToken(googleIdToken);
		} catch (GeneralSecurityException e) {
            log.debug("{} Google ID token verification threw GeneralSecurityException {}", getLogPrefix(), e.getMessage());
            handleError(profileRequestContext, authenticationContext, AuthnEventIds.INVALID_CREDENTIALS, AuthnEventIds.INVALID_CREDENTIALS);
            return;
		} catch (IOException e) {
            log.debug("{} Google ID token verification threw IOException {}", getLogPrefix(), e.getMessage());
            handleError(profileRequestContext, authenticationContext, AuthnEventIds.INVALID_CREDENTIALS, AuthnEventIds.INVALID_CREDENTIALS);
            return;
		}
        
        log.debug("{} Google ID token is verified", getLogPrefix());
        
        log.info("{} Login by '{}' succeeded", getLogPrefix(), googleContext.getGoogleIdToken().getPayload().getSubject());
        buildAuthenticationResult(profileRequestContext, authenticationContext);
        ActionSupport.buildProceedEvent(profileRequestContext);
    }
    
    /** {@inheritDoc} */
    @Override
    @Nonnull protected Subject populateSubject(@Nonnull final Subject subject) {
        subject.getPrincipals().add(new GoogleIdPrincipal(googleContext.getGoogleIdToken()));
        return subject;
    }
}
