package io.jsonwebtoken.impl.security

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.*
import org.junit.Test

import javax.crypto.SecretKey

import static org.junit.Assert.assertArrayEquals
import static org.junit.Assert.fail

/**
 * @since JJWT_RELEASE_VERSION
 */
class HmacAesEncryptionAlgorithmTest {

    @Test
    void testGenerateHmacKeyBytesWithExactNumExpectedBytes() {

        int hmacKeySize = EncryptionAlgorithms.A128CBC_HS256.getRequiredKeyByteLength() / 2;

        def alg = new TestHmacAesEncryptionAlgorithm() {
            @Override
            protected byte[] generateHmacKeyBytes() {
                byte[] bytes = new byte[hmacKeySize]
                Randoms.secureRandom().nextBytes(bytes);
                return bytes;
            }
        }

        SecretKey key = alg.generateKey()

        def plaintext = "Hello World! Nice to meet you!".getBytes("UTF-8")

        def request = EncryptionRequests.symmetric().setKey(key).setPlaintext(plaintext).build()

        def result = alg.encrypt(request);
        assert result instanceof AuthenticatedEncryptionResult

        def dreq = DecryptionRequests.symmetric()
                .setKey(key)
                .setInitializationVector(result.getInitializationVector())
                .setAuthenticationTag(result.getAuthenticationTag())
                .setCiphertext(result.getCiphertext())
                .build()

        byte[] decryptedPlaintextBytes = alg.decrypt(dreq)

        assertArrayEquals(plaintext, decryptedPlaintextBytes);
    }

    @Test
    void testGenerateHmacKeyBytesWithInsufficientNumExpectedBytes() {

        int hmacKeySize = EncryptionAlgorithms.A128CBC_HS256.getRequiredKeyByteLength() / 2;

        def alg = new TestHmacAesEncryptionAlgorithm() {
            @Override
            protected byte[] generateHmacKeyBytes() {
                byte[] bytes = new byte[hmacKeySize - 1]
                Randoms.secureRandom().nextBytes(bytes)
                return bytes
            }
        }

        try {
            alg.generateKey()
            fail()
        } catch (CryptoException expected) {
        }
    }

    @Test
    void testDecryptWithInvalidTag() {

        def alg = EncryptionAlgorithms.A128CBC_HS256;

        SecretKey key = alg.generateKey()

        def plaintext = "Hello World! Nice to meet you!".getBytes("UTF-8")

        def request = EncryptionRequests.symmetric().setKey(key).setPlaintext(plaintext).build()

        def result = alg.encrypt(request);
        assert result instanceof AuthenticatedEncryptionResult

        def realTag = result.getAuthenticationTag();

        //fake it:

        def fakeTag = new byte[realTag.length]
        Randoms.secureRandom().nextBytes(fakeTag)

        def dreq = DecryptionRequests.symmetric()
                .setKey(key)
                .setInitializationVector(result.getInitializationVector())
                .setAuthenticationTag(fakeTag)
                .setCiphertext(result.getCiphertext())
                .build()

        try {
            alg.decrypt(dreq)
            fail()
        } catch (CryptoException expected) {
        }
    }

    static class TestHmacAesEncryptionAlgorithm extends HmacAesEncryptionAlgorithm {
        TestHmacAesEncryptionAlgorithm() {
            super(EncryptionAlgorithmName.A128CBC_HS256.getValue(), SignatureAlgorithm.HS256);
        }
    }

}
