package org.mla.cbox.shibboleth.idp.authn.impl;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Principal;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonStructure;
import javax.json.stream.JsonGenerator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.google.gson.Gson;

import net.shibboleth.idp.authn.principal.AbstractPrincipalSerializer;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * Principal serializer for GoogleIdPrincipal
 */
@ThreadSafe
public class GoogleIdPrincipalSerializer extends AbstractPrincipalSerializer<String> {

    /** Field name of GoogleIdPrincipal */
    @Nonnull @NotEmpty private static final String GOOGLE_TOKEN_FIELD = "Google";

    /** Pattern used to determine if input is supported */
    @Nonnull private static final Pattern JSON_PATTERN = Pattern.compile("^\\{\"Google\":.*\\}$");

    /** Class logger */
    @Nonnull private final Logger log = LoggerFactory.getLogger(GoogleIdPrincipalSerializer.class);

    /** {@inheritDoc} */
    @Override
    public boolean supports(@Nonnull final Principal principal) {
        return principal instanceof GoogleIdPrincipal;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull @NotEmpty public String serialize(@Nonnull final Principal principal) throws IOException {
        GoogleIdPrincipal googlePrincipal = (GoogleIdPrincipal) principal;
        
        final StringWriter sink = new StringWriter(32);
        final JsonGenerator gen = getJsonGenerator(sink);
        gen.writeStartObject()
            .write(GOOGLE_TOKEN_FIELD, googlePrincipal.serialize())
            .writeEnd();
        gen.close();
        return sink.toString();
    }

    /** {@inheritDoc} */
    @Override
    public boolean supports(@Nonnull @NotEmpty final String value) {
        return JSON_PATTERN.matcher(value).matches();
    }

    /** {@inheritDoc} */
    @Override
    @Nullable public GoogleIdPrincipal deserialize(@Nonnull @NotEmpty final String value) throws IOException {
        final JsonReader reader = getJsonReader(new StringReader(value));
        JsonStructure st = null;
        try {
            st = reader.read();
        } finally {
            reader.close();
        }
        if (!(st instanceof JsonObject)) {
            throw new IOException("Found invalid data structure while parsing GoogleIdPrincipal");
        }
        final JsonString str = ((JsonObject) st).getJsonString(GOOGLE_TOKEN_FIELD);
        if (str != null) {
            final String serializedGoogleIdPrincipal = str.getString();
            if (!Strings.isNullOrEmpty(serializedGoogleIdPrincipal)) {
                Gson gson = new Gson();
                GoogleIdPrincipal googleIdPrincipal = gson.fromJson(serializedGoogleIdPrincipal, GoogleIdPrincipal.class);
                return googleIdPrincipal;
            }
        }
        return null;
    }
}