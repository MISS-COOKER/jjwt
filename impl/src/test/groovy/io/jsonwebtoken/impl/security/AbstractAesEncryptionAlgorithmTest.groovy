package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.*
import org.junit.Test

import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

import static org.junit.Assert.*

/**
 * @since JJWT_RELEASE_VERSION
 */
class AbstractAesEncryptionAlgorithmTest {

    @Test
    void testConstructorWithIvLargerThanAesBlockSize() {

        try {
            new TestAesEncryptionAlgorithm('foo', 'foo', 136, 128)
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testConstructorWithoutIvLength() {

        try {
            new TestAesEncryptionAlgorithm('foo', 'foo', 0, 128)
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testConstructorWithoutRequiredKeyLength() {

        try {
            new TestAesEncryptionAlgorithm('foo', 'foo', 128, 0)
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testDoEncryptFailure() {

        def alg = new TestAesEncryptionAlgorithm('foo', 'foo', 128, 128) {
            @Override
            protected EncryptionResult doEncrypt(EncryptionRequest req) throws Exception {
                throw new IllegalArgumentException('broken')
            }
        }

        def req = EncryptionRequests.symmetric()
                .setAdditionalAuthenticatedData('foo'.getBytes())
                .setInitializationVector('iv'.getBytes())
                .setKey(alg.generateKey())
                .setPlaintext('bar'.getBytes())
                .build();

        try {
            alg.encrypt(req)
        } catch (CryptoException expected) {
            assertTrue expected.getCause() instanceof IllegalArgumentException
            assertTrue expected.getCause().getMessage().equals('broken')
        }
    }

    @Test
    void testAssertKeyLength() {

        def requiredKeyLength = 16

        def alg = new TestAesEncryptionAlgorithm('foo', 'foo', 128, requiredKeyLength)

        byte[] bytes = new byte[requiredKeyLength + 1] //not same as requiredKeyByteLength, but it should be
        Randoms.secureRandom().nextBytes(bytes)

        try {
            alg.assertKeyLength(new SecretKeySpec(bytes, "AES"))
            fail()
        } catch (CryptoException expected) {
        }
    }

    @Test
    void testGetSecureRandomWhenRequestHasSpecifiedASecureRandom() {

        def alg = new TestAesEncryptionAlgorithm('foo', 'foo', 128, 128)

        def secureRandom = new SecureRandom()

        def req = EncryptionRequests.symmetric()
                .setAdditionalAuthenticatedData('foo'.getBytes())
                .setInitializationVector('iv'.getBytes())
                .setKey(alg.generateKey())
                .setPlaintext('bar'.getBytes())
                .setSecureRandom(secureRandom)
                .build();

        def returnedSecureRandom = alg.getSecureRandom(req)

        assertSame(secureRandom, returnedSecureRandom)
    }

    static class TestAesEncryptionAlgorithm extends AbstractAesEncryptionAlgorithm {

        TestAesEncryptionAlgorithm(String name, String transformationString, int generatedIvLengthInBits, int requiredKeyLengthInBits) {
            super(name, transformationString, generatedIvLengthInBits, requiredKeyLengthInBits)
        }

        @Override
        protected EncryptionResult doEncrypt(EncryptionRequest req) throws Exception {
            return null
        }

        @Override
        protected byte[] doDecrypt(DecryptionRequest req) throws Exception {
            return new byte[0]
        }
    }

}
