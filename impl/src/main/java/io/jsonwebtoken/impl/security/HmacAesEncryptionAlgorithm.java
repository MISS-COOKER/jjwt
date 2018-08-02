package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import io.jsonwebtoken.impl.crypto.MacSigner;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AuthenticatedDecryptionRequest;
import io.jsonwebtoken.security.CryptoException;
import io.jsonwebtoken.security.DecryptionRequest;
import io.jsonwebtoken.security.EncryptionRequest;
import io.jsonwebtoken.security.EncryptionResult;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

import static io.jsonwebtoken.lang.Arrays.*;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class HmacAesEncryptionAlgorithm extends AbstractAesEncryptionAlgorithm {

    private static final String TRANSFORMATION_STRING = "AES/CBC/PKCS5Padding";

    private final SignatureAlgorithm SIGALG;

    public HmacAesEncryptionAlgorithm(String name, SignatureAlgorithm sigAlg) {
        super(name, TRANSFORMATION_STRING, AES_BLOCK_SIZE_BITS, sigAlg.getMinKeyLength());
        this.SIGALG = sigAlg;
    }

    @Override
    protected SecretKey doGenerateKey() throws Exception {

        int subKeyLength = getRequiredKeyByteLength() / 2;

        byte[] macKeyBytes = generateHmacKeyBytes();
        Assert.notEmpty(macKeyBytes, "Generated HMAC key byte array cannot be null or empty.");

        if (macKeyBytes.length > subKeyLength) {
            byte[] subKeyBytes = new byte[subKeyLength];
            System.arraycopy(macKeyBytes, 0, subKeyBytes, 0, subKeyLength);
            macKeyBytes = subKeyBytes;
        }

        if (macKeyBytes.length != subKeyLength) {
            String msg = "Generated HMAC key must be " + subKeyLength + " bytes (" +
                    subKeyLength * Byte.SIZE + " bits) long. The " + getClass().getName() + " implementation " +
                    "generated a key " + macKeyBytes.length + " bytes (" +
                    macKeyBytes.length * Byte.SIZE + " bits) long";
            throw new IllegalStateException(msg);
        }

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(subKeyLength * Byte.SIZE);

        SecretKey encKey = keyGenerator.generateKey();
        byte[] encKeyBytes = encKey.getEncoded();

        //return as one single key per https://tools.ietf.org/html/rfc7518#section-5.2.2.1

        byte[] combinedKeyBytes = new byte[macKeyBytes.length + encKeyBytes.length];

        System.arraycopy(macKeyBytes, 0, combinedKeyBytes, 0, macKeyBytes.length);
        System.arraycopy(encKeyBytes, 0, combinedKeyBytes, macKeyBytes.length, encKeyBytes.length);

        return new SecretKeySpec(combinedKeyBytes, getName());
    }

    protected byte[] generateHmacKeyBytes() {
        SecretKey macKey = MacProvider.generateKey(SIGALG);
        return macKey.getEncoded();
    }

    @Override
    protected EncryptionResult doEncrypt(EncryptionRequest<SecretKey> req) throws Exception {

        //Ensure IV:
        byte[] iv = ensureEncryptionIv(req);

        //Ensure Key:
        byte[] keyBytes = assertKeyBytes(req);

        //See if there is any AAD:
        byte[] aad = getAAD(req); //can be null if request associated data does not exist or is empty

        int halfCount = keyBytes.length / 2; // https://tools.ietf.org/html/rfc7518#section-5.2
        byte[] macKeyBytes = Arrays.copyOfRange(keyBytes, 0, halfCount);
        keyBytes = Arrays.copyOfRange(keyBytes, halfCount, keyBytes.length);

        final SecretKey encryptionKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = createCipher(Cipher.ENCRYPT_MODE, encryptionKey, iv);

        byte[] plaintext = req.getPlaintext();
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] tag = sign(aad, iv, ciphertext, macKeyBytes);

        return new DefaultAuthenticatedEncryptionResult(iv, ciphertext, tag);
    }

    private byte[] sign(byte[] aad, byte[] iv, byte[] ciphertext, byte[] macKeyBytes) {

        long aadLength = length(aad);
        long aadLengthInBits = aadLength * Byte.SIZE;
        long aadLengthInBitsAsUnsignedInt = aadLengthInBits & 0xffffffffL;
        byte[] AL = toBytes(aadLengthInBitsAsUnsignedInt);

        byte[] toHash = new byte[(int) aadLength + iv.length + ciphertext.length + AL.length];

        if (aad != null) {
            System.arraycopy(aad, 0, toHash, 0, aad.length);
            System.arraycopy(iv, 0, toHash, aad.length, iv.length);
            System.arraycopy(ciphertext, 0, toHash, aad.length + iv.length, ciphertext.length);
            System.arraycopy(AL, 0, toHash, aad.length + iv.length + ciphertext.length, AL.length);
        } else {
            System.arraycopy(iv, 0, toHash, 0, iv.length);
            System.arraycopy(ciphertext, 0, toHash, iv.length, ciphertext.length);
            System.arraycopy(AL, 0, toHash, iv.length + ciphertext.length, AL.length);
        }

        MacSigner macSigner = new MacSigner(SIGALG, macKeyBytes);

        byte[] digest = macSigner.sign(toHash);

        // https://tools.ietf.org/html/rfc7518#section-5.2.2.1 #5 requires truncating the signature
        // to be the same length as the macKey/encKey:
        return Arrays.copyOfRange(digest, 0, macKeyBytes.length);
    }

    private static byte[] toBytes(long l) {
        byte[] b = new byte[8];
        for (int i = 7; i > 0; i--) {
            b[i] = (byte) l;
            l >>>= 8;
        }
        b[0] = (byte) l;
        return b;
    }

    @Override
    protected byte[] doDecrypt(DecryptionRequest<SecretKey> dreq) throws Exception {

        Assert.isInstanceOf(AuthenticatedDecryptionRequest.class, dreq,
                "AES_CBC_HMAC_SHA2 encryption always authenticates and therefore requires that DecryptionRequests " +
                        "are AuthenticatedDecryptionRequest instances.");
        AuthenticatedDecryptionRequest<SecretKey> req = (AuthenticatedDecryptionRequest<SecretKey>) dreq;

        byte[] tag = req.getAuthenticationTag();
        Assert.notEmpty(tag, "AuthenticatedDecryptionRequests must include a non-empty authentication tag.");

        byte[] iv = assertDecryptionIv(req);

        //Ensure Key:
        byte[] keyBytes = assertKeyBytes(req);

        //See if there is any AAD:
        byte[] aad = getAAD(req); //can be null if request associated data does not exist or is empty

        int halfCount = keyBytes.length / 2; // https://tools.ietf.org/html/rfc7518#section-5.2
        byte[] macKeyBytes = Arrays.copyOfRange(keyBytes, 0, halfCount);
        keyBytes = Arrays.copyOfRange(keyBytes, halfCount, keyBytes.length);

        final SecretKey key = new SecretKeySpec(keyBytes, "AES");

        final byte[] ciphertext = req.getCiphertext();

        Cipher cipher = createCipher(Cipher.DECRYPT_MODE, key, iv);

        // Assert that the aad + iv + ciphertext provided, when signed, equals the tag provided,
        // thereby indicating none of it has been tampered with:
        byte[] digest = sign(aad, iv, ciphertext, macKeyBytes);
        if (!Arrays.equals(digest, tag)) {
            String msg = "Ciphertext decryption failed: HMAC digest verification failed.";
            throw new CryptoException(msg);
        }

        return cipher.doFinal(ciphertext);
    }
}
