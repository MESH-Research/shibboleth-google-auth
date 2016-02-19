package org.mla.cbox.shibboleth.idp.authn.impl;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.principal.CloneablePrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

import com.google.common.base.MoreObjects;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;

/** Principal based on a Google Id token */
public class GoogleIdPrincipal implements CloneablePrincipal {
    
	/** Sub claim from ID token asserted by Google */
    @Nonnull @NotEmpty private String subClaim;
    
    /** Email claim from ID token asserted by Google, can be null if not asserted */
    private String emailClaim;
    
    /** Name claim from ID token asserted by Google, Can be null if not asserted */
    private String nameClaim;
    
    /**
     * Constructor.
     * 
     * @param googleIdToken Google ID token, can not be null or empty
     */
    public GoogleIdPrincipal(@Nonnull @NotEmpty final GoogleIdToken googleIdToken) {
        subClaim = googleIdToken.getPayload().getSubject();
        emailClaim = googleIdToken.getPayload().getEmail();
        nameClaim = (String) googleIdToken.getPayload().get("name");
    }
    
    /**
     * Get the email claim
     * 
     * @return emailClaim the email claim if asserted by Google
     */
    public String getEmailClaim() {
    	return emailClaim;
    }
    
    /**
     * Get the name claim
     * 
     * @return nameClaim the name claim if asserted by Google
     */
    public String getNameClaim() {
    	return nameClaim;
    }
    
    /**
     * Get the sub claim
     * 
     * @return subClaim the sub claim, always asserted by Google
     */
    public String getSubClaim() {
    	return subClaim;
    }
    
    /** {@inheritDoc} */
    @Override
    @Nonnull @NotEmpty public String getName() {
    	return subClaim;
    }
    
    /** {@inheritDoc} */
    @Override
    public int hashCode() {
    	return subClaim.hashCode();
    }
    
    /** {@inheritDoc} */
    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }

        if (this == other) {
            return true;
        }

        if (other instanceof GoogleIdPrincipal) {
            return subClaim.equals(((GoogleIdPrincipal) other).getSubClaim());
        }

        return false;
    }
    
    /** {@inheritDoc} */
    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this).add("GoogleSubClaim", subClaim).toString();
    }
    
    /** {@inheritDoc} */
    @Override
    public GoogleIdPrincipal clone() throws CloneNotSupportedException {
        GoogleIdPrincipal copy = (GoogleIdPrincipal) super.clone();
        copy.emailClaim = emailClaim;
        copy.nameClaim = nameClaim;
        copy.subClaim = subClaim;
        return copy;
    }
}