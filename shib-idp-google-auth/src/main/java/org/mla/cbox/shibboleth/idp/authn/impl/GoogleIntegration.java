package org.mla.cbox.shibboleth.idp.authn.impl;

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a Google OAuth 2 web application integration
 */
public class GoogleIntegration {
    /** Google integration details **/
    @Nonnull private String oauth2ClientId;
    
    /** Class logger */
	@Nonnull private final Logger log = LoggerFactory.getLogger(GoogleIntegration.class);
    
    /** Log prefix */
	@Nonnull private final String logPrefix = getClass().getSimpleName() + ":";
    
    /** Constructor */
    public GoogleIntegration() {
    	
    }
    
    public String getOauth2ClientId(){
    	return this.oauth2ClientId;
    }
    
    public GoogleIntegration setOauth2ClientId(String clientId) {
    	this.oauth2ClientId = clientId;
    	return this;
    }
}