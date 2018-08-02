package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.RuntimeEnvironment;
import io.jsonwebtoken.security.AuthenticatedDecryptionRequest;
import io.jsonwebtoken.security.DecryptionRequest;
import io.jsonwebtoken.security.EncryptionRequest;
import io.jsonwebtoken.security.EncryptionResult;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class GcmAesEncryptionAlgorithm extends AbstractAesEncryptionAlgorithm {

    //TODO: Remove this static block when JDK 7 support is removed
    // JDK <= 7 does not support AES GCM mode natively and so BouncyCastle is required
    static {
        RuntimeEnvironment.enableBouncyCastleIfPossible();
    }

    private static final int GCM_IV_SIZE_BITS = 96; // https://tools.ietf.org/html/rfc7518#section-5.3
    private static final String TRANSFORMATION_STRING = "AES/GCM/NoPadding";

    public GcmAesEncryptionAlgorithm(String name, int requiredKeyLengthInBits) {
        super(name, TRANSFORMATION_STRING, GCM_IV_SIZE_BITS, requiredKeyLengthInBits);
        //Standard AES only supports 128, 192, and 256 key lengths, respectively:
        Assert.isTrue(requiredKeyLengthInBits == 128 || requiredKeyLengthInBits == 192 || requiredKeyLengthInBits == 256, "Invalid AES Key length.");
    }

    @Override
    protected AlgorithmParameterSpec createAlgorithmParameterSpec(byte[] iv) {
        return new GCMParameterSpec(AES_BLOCK_SIZE_BITS, iv);
    }

    @Override
    protected EncryptionResult doEncrypt(EncryptionRequest<SecretKey> req) throws Exception {

        //Ensure IV:
        byte[] iv = ensureEncryptionIv(req);

        //Ensure Key:
        final SecretKey encryptionKey = assertKey(req);

        //See if there is any AAD:
        byte[] aad = getAAD(req); //can be null if request associated data does not exist or is empty

        Cipher cipher = createCipher(Cipher.ENCRYPT_MODE, encryptionKey, iv);
        if (aad != null) {
            cipher.updateAAD(aad);
        }

        byte[] plaintext = req.getPlaintext();
        byte[] ciphertext = cipher.doFinal(plaintext);

        // When using GCM mode, the JDK actually appends the authentication tag to the ciphertext, so let's
        // represent this appropriately:
        byte[] taggedCiphertext = ciphertext;

        // Now separate the tag from the ciphertext (tag has a length of AES_BLOCK_SIZE_BITS):
        int ciphertextLength = taggedCiphertext.length - AES_BLOCK_SIZE_BYTES;
        ciphertext = new byte[ciphertextLength];
        System.arraycopy(taggedCiphertext, 0, ciphertext, 0, ciphertextLength);

        byte[] tag = new byte[AES_BLOCK_SIZE_BYTES];
        System.arraycopy(taggedCiphertext, ciphertextLength, tag, 0, AES_BLOCK_SIZE_BYTES);

        return new DefaultAuthenticatedEncryptionResult(iv, ciphertext, tag);
    }

    @Override
    protected byte[] doDecrypt(DecryptionRequest<SecretKey> dreq) throws Exception {

        Assert.isInstanceOf(AuthenticatedDecryptionRequest.class, dreq,
                "AES GCM encryption always authenticates and therefore requires that DecryptionRequests are " +
                        "AuthenticatedDecryptionRequest instances.");
        AuthenticatedDecryptionRequest<SecretKey> req = (AuthenticatedDecryptionRequest<SecretKey>) dreq;

        byte[] tag = req.getAuthenticationTag();
        Assert.notEmpty(tag, "AuthenticatedDecryptionRequests must include a non-empty authentication tag.");

        byte[] iv = assertDecryptionIv(req);

        //Ensure Key:
        final SecretKey key = assertKey(req);

        //See if there is any AAD:
        byte[] aad = getAAD(req); //can be null if request associated data does not exist or is empty

        final byte[] ciphertext = req.getCiphertext();

        Cipher cipher = createCipher(Cipher.DECRYPT_MODE, key, iv);

        if (aad != null) {
            cipher.updateAAD(aad);
        }

        //for tagged GCM, the JVM spec requires that the tag be appended to the end of the ciphertext
        //byte array.  So we'll append it here:
        byte[] taggedCiphertext = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, taggedCiphertext, 0, ciphertext.length);
        System.arraycopy(tag, 0, taggedCiphertext, ciphertext.length, tag.length);

        return cipher.doFinal(taggedCiphertext);
    }
}
