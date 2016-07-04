package org.mla.cbox.shibboleth.idp.authn.impl;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import org.opensaml.profile.context.ProfileRequestContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;

public class InitializeGoogleContext extends AbstractAuthenticationAction {
    /** Google integration */
	@Nonnull private GoogleIntegration googleIntegration;
    
    /** Class logger */
    @Nonnull private final Logger log = LoggerFactory.getLogger(InitializeGoogleContext.class);
    
    /** Constructor **/
    InitializeGoogleContext() {
    }
	
	@Override
	protected void doExecute (
            @Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        
        /* Create a new GoogleContext */
        final GoogleContext googleContext = new GoogleContext();
        
        /* Set the Google integration details for the context */
        googleContext.setGoogleIntegration(this.googleIntegration);
        
        /* Initialize an anti forgery state token for the context */
        googleContext.initializeAntiForgeryStateToken();
        
        /* Save the context as a sub context to the authentication context */
        authenticationContext.addSubcontext(googleContext, true);
        log.debug("{} Created GoogleContext using GoogleIntegration with client ID {}", getLogPrefix(), this.googleIntegration.getOauth2ClientId());
	}
    
    /**
     * Get the GoogleIntegration 
     * 
     * @return the Google integration details including OAuth2 client ID
     */
    @Nonnull public GoogleIntegration getGoogleIntegration(){
    	return this.googleIntegration;
    }
    
    /**
     * Set the GoogleIntegration
     * 
     * @param googleIntegration the Google integration details 
     * @return instance of this class
     */
    public InitializeGoogleContext setGoogleIntegration(@Nonnull GoogleIntegration googleIntegration) {
    	this.googleIntegration = googleIntegration;
    	return this;
    }
}