package org.mla.cbox.shibboleth.idp.authn.impl;

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a Google OAuth 2 web application integration
 */
public class GoogleIntegration {
    /** Google OAuth2 Client ID */
    @Nonnull private String oauth2ClientId;
    
    /** Google OAuth2 Client Secret */
    @Nonnull private String oauth2ClientSecret;
    
    /** Google OAuth2 URL */
    @Nonnull private String oauth2Url;
    
    /** Google Token Endpoint */
    @Nonnull private String tokenEndpoint;
    
    /** Class logger */
	@Nonnull private final Logger log = LoggerFactory.getLogger(GoogleIntegration.class);
    
    /** Log prefix */
	@Nonnull private final String logPrefix = getClass().getSimpleName() + ":";
    
    /** Constructor */
    public GoogleIntegration() {
    	
    }
    
    public String getOauth2Url() {
    	return this.oauth2Url;
    }
    
    public String getOauth2ClientId(){
    	return this.oauth2ClientId;
    }
    
    public String getOauth2ClientSecret() {
    	return this.oauth2ClientSecret;
    }
    
    public String getTokenEndpoint() {
    	return this.tokenEndpoint;
    }
    
    public GoogleIntegration setOauth2Url(String url) {
    	this.oauth2Url = url;
    	return this;
    }
    
    public GoogleIntegration setOauth2ClientId(String clientId) {
    	this.oauth2ClientId = clientId;
    	return this;
    }
    
    public GoogleIntegration setOauth2ClientSecret(String secret) {
    	this.oauth2ClientSecret = secret;
    	return this;
    }
    
    public GoogleIntegration setTokenEndpoint(String url) {
    	this.tokenEndpoint = url;
    	return this;
    }
}