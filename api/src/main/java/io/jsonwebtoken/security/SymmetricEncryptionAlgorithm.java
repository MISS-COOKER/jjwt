package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SymmetricEncryptionAlgorithm extends EncryptionAlgorithm<SecretKey, SecretKey> {

    /**
     * Creates and returns a new secure-random key with a length sufficient to be used by this EncryptionAlgorithm.
     *
     * @return a new secure-random key with a length sufficient to be used by this EncryptionAlgorithm.
     */
    SecretKey generateKey();
}
