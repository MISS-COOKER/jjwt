package io.jsonwebtoken.security;

import io.jsonwebtoken.Named;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EncryptionAlgorithm<E extends Key, D extends Key> extends Named {

    EncryptionResult encrypt(EncryptionRequest<E> request) throws CryptoException;

    byte[] decrypt(DecryptionRequest<D> request) throws CryptoException;
}
