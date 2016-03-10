package org.mla.cbox.shibboleth.idp.authn.impl;

import java.io.IOException;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.principal.CloneablePrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

import com.google.common.base.MoreObjects;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.gson.Gson;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Principal based on a Google Id token */
public class GoogleIdPrincipal implements CloneablePrincipal {
    /** Sub claim from ID token asserted by Google */
	private String subClaim;
    
	/** Email claim from ID token asserted by Google, can be null if not asserted */
    private String emailClaim;
    
    /** Name claim from ID token asserted by Google, Can be null if not asserted */
    private String nameClaim;
    
    /**
     * Constructor
     */
    public GoogleIdPrincipal() {
    	
    }
    
    /**
     * Constructor using Google ID token.
     * 
     * @param googleIdToken Google ID token
     */
    public GoogleIdPrincipal(@Nonnull @NotEmpty final GoogleIdToken token) {
        this.subClaim = token.getPayload().getSubject();
        this.emailClaim = token.getPayload().getEmail();
        this.nameClaim = (String) token.getPayload().get("name");
    }
    
    /**
     * Get the email claim
     * 
     * @return emailClaim the email claim if asserted by Google
     */
    public String getEmailClaim() {
        return this.emailClaim;
    }
    
    /**
     * Get the name claim
     * 
     * @return nameClaim the name claim if asserted by Google
     */
    public String getNameClaim() {
        return this.nameClaim;
    }
    
    /**
     * Get the sub claim
     * 
     * @return subClaim the sub claim, always asserted by Google
     */
    public String getSubClaim() {
        return this.subClaim;
    }
    
    /** {@inheritDoc} */
    @Override
    @Nonnull @NotEmpty public String getName() {
        return this.subClaim;
    }
    
    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        return this.subClaim.hashCode();
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
            return this.subClaim.equals(((GoogleIdPrincipal) other).getSubClaim());
        }

        return false;
    }
    
    /** Serialize to JSON */
    public String serialize() {
    	Gson gson = new Gson();
    	return gson.toJson(this);
    }
    
    /** {@inheritDoc} */
    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this).add("GoogleIdPrincipal", this.getSubClaim()).toString();
    }
    
    /** {@inheritDoc} */
    @Override
    public GoogleIdPrincipal clone() throws CloneNotSupportedException {
        GoogleIdPrincipal copy = (GoogleIdPrincipal) super.clone();
        copy.subClaim = this.subClaim;
        copy.emailClaim = this.emailClaim;
        copy.nameClaim = this.nameClaim;
        return copy;
    }
}