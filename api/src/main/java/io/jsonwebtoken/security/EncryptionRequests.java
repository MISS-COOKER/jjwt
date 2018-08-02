package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Classes;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public final class EncryptionRequests {

    private EncryptionRequests(){} //prevent instantiation

    public static EncryptionRequestBuilder<SecretKey> symmetric() {
        return Classes.newInstance("io.jsonwebtoken.impl.security.DefaultEncryptionRequestBuilder");
    }
}
