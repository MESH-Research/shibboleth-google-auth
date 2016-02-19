package org.mla.cbox.shibboleth.idp.authn.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.BaseContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;

/**
 * Context, usually attached to {@link AuthenticationContext}, that carries a GoogleIdToken
 */
public class GoogleContext extends BaseContext {
    /** Google integration details */
	@Nullable private GoogleIntegration googleIntegration = null;
    
    /** The unvalidated Google Id token string */
    @Nullable private String googleIdTokenString = null;
    
	/** The validated OIDC ID token */
	@Nullable private GoogleIdToken googleIdToken = null;
    
	/** Class logger */
    @Nonnull private final Logger log = LoggerFactory.getLogger(GoogleContext.class);
    
    /** Log prefix */
    @Nonnull private final String logPrefix = getClass().getSimpleName() + ":";
    
	/** Constructor */
    public GoogleContext() {
    	
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
     * Get the validated ID token
     * 
     * @return the validated ID token
     */
     @Nullable public GoogleIdToken getGoogleIdToken() {
    	 return this.googleIdToken;
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
    public GoogleContext setGoogleIdToken(@Nullable final GoogleIdToken token) {
    	this.googleIdToken = token;
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