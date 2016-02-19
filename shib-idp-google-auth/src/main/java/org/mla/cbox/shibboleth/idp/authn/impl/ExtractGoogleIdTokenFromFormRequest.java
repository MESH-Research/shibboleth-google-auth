package org.mla.cbox.shibboleth.idp.authn.impl;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that extracts a signed Google ID token passed from Google from an HTTP form body,
 * creates a GoogleContext, and attaches it to the AuthenticationContext. The GoogleIntegration
 * instance with the Google OAuth2 client ID string is attached to the GoogleContext.
 *
 */
public class ExtractGoogleIdTokenFromFormRequest extends AbstractExtractionAction {
    /** Google integration */
	@Nonnull private GoogleIntegration googleIntegration;

    /** Class logger */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ExtractGoogleIdTokenFromFormRequest.class);

    /** Constructor */
    ExtractGoogleIdTokenFromFormRequest() {
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        
        final GoogleContext googleContext = new GoogleContext();
        googleContext.setGoogleIntegration(this.googleIntegration);
        authenticationContext.addSubcontext(googleContext, true);
        
        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            log.debug("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        
        final String googleIdTokenString = request.getParameter("google_id_token");
        if (googleIdTokenString == null || googleIdTokenString.isEmpty()) {
            log.debug("{} No Google ID token in request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        
        log.debug("{} Google ID token string is {}", getLogPrefix(), googleIdTokenString);
        googleContext.setGoogleIdTokenString(googleIdTokenString);
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
    public ExtractGoogleIdTokenFromFormRequest setGoogleIntegration(@Nonnull GoogleIntegration googleIntegration) {
    	this.googleIntegration = googleIntegration;
    	return this;
    }
}