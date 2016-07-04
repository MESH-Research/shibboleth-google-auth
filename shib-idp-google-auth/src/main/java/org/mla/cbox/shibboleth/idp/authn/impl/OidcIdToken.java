package org.mla.cbox.shibboleth.idp.authn.impl;

import com.google.api.client.json.GenericJson;
import com.google.api.client.util.Key;

/**
 * Represents OIDC ID token claims as issued by Google
 */
public class OidcIdToken extends GenericJson {
    
	@Key
	private String iss;
    
    /* not guaranteed to be present */
	@Key
	private String at_hash = null;
	
    /* not guaranteed to be present */
    @Key
	private Boolean email_verified = null;
	
    @Key
    private String sub;
    
    /* not guaranteed to be present */
    @Key
    private String azp = null;
    
    /* not guaranteed to be present */
    @Key
    private String email = null;
    
    /* not guaranteed to be present */
    @Key
    private String profile = null;
    
    /* not guaranteed to be present */
    @Key
    private String picture = null;
    
    /* not guaranteed to be present */
    @Key
    private String name = null;
    
    @Key
    private String aud;
    
    @Key
    private Integer iat;
    
    @Key
    private Integer exp;
    
    /* not guaranteed to be present */
    @Key
    private String hd = null;
    
    public String getSub() {
    	return this.sub;
    }
    
    public String getEmail() {
    	return this.email;
    }
    
    public String getName() {
    	return this.name;
    }
}