package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface AsymmetricEncryptionAlgorithm extends EncryptionAlgorithm<PrivateKey, PublicKey> {
}
