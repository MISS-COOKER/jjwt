package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AssociatedDataSource;
import io.jsonwebtoken.security.CryptoException;
import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.DecryptionRequest;
import io.jsonwebtoken.security.EncryptionRequest;
import io.jsonwebtoken.security.EncryptionResult;
import io.jsonwebtoken.security.SymmetricEncryptionAlgorithm;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static io.jsonwebtoken.lang.Arrays.*;

/**
 * @since JJWT_RELEASE_VERSION
 */
public abstract class AbstractAesEncryptionAlgorithm implements SymmetricEncryptionAlgorithm {

    protected static final int AES_BLOCK_SIZE_BYTES = 16;
    protected static final int AES_BLOCK_SIZE_BITS = AES_BLOCK_SIZE_BYTES * Byte.SIZE;
    public static final String INVALID_GENERATED_IV_LENGTH =
            "generatedIvLengthInBits must be a positive number <= " + AES_BLOCK_SIZE_BITS;

    protected static final String DECRYPT_NO_IV = "This EncryptionAlgorithm implementation rejects decryption " +
            "requests that do not include initialization vectors.  AES ciphertext without an IV is weak and should " +
            "never be used.";

    private final String name;
    private final String transformationString;
    private final int generatedIvByteLength;
    private final int requiredKeyByteLength;
    private final int requiredKeyBitLength;

    public AbstractAesEncryptionAlgorithm(String name, String transformationString, int generatedIvLengthInBits, int requiredKeyLengthInBits) {

        Assert.hasText(name, "Name cannot be null or empty.");
        this.name = name;

        this.transformationString = transformationString;

        Assert.isTrue(generatedIvLengthInBits > 0 && generatedIvLengthInBits <= AES_BLOCK_SIZE_BITS, INVALID_GENERATED_IV_LENGTH);
        Assert.isTrue((generatedIvLengthInBits % Byte.SIZE) == 0, "generatedIvLengthInBits must be evenly divisible by 8.");
        this.generatedIvByteLength = generatedIvLengthInBits / Byte.SIZE;

        Assert.isTrue(requiredKeyLengthInBits > 0, "requiredKeyLengthInBits must be greater than zero.");
        Assert.isTrue((requiredKeyLengthInBits % Byte.SIZE) == 0, "requiredKeyLengthInBits must be evenly divisible by 8.");
        this.requiredKeyBitLength = requiredKeyLengthInBits;
        this.requiredKeyByteLength = requiredKeyLengthInBits / Byte.SIZE;
    }

    public int getRequiredKeyByteLength() {
        return this.requiredKeyByteLength;
    }

    @Override
    public SecretKey generateKey() {
        try {
            return doGenerateKey();
        } catch (Exception e) {
            throw new CryptoException("Unable to generate a new " + getName() + " SecretKey: " + e.getMessage(), e);
        }
    }

    protected SecretKey doGenerateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(this.requiredKeyBitLength);
        return keyGenerator.generateKey();
    }

    @Override
    public String getName() {
        return this.name;
    }

    protected Cipher createCipher(int mode, Key key, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance(this.transformationString);

        AlgorithmParameterSpec spec = createAlgorithmParameterSpec(iv);

        cipher.init(mode, key, spec);

        return cipher;
    }

    protected AlgorithmParameterSpec createAlgorithmParameterSpec(byte[] iv) {
        return new IvParameterSpec(iv);
    }

    @Override
    public EncryptionResult encrypt(EncryptionRequest<SecretKey> req) throws CryptoException {
        try {
            Assert.notNull(req, "EncryptionRequest cannot be null.");
            return doEncrypt(req);
        } catch (Exception e) {
            String msg = "Unable to perform encryption: " + e.getMessage();
            throw new CryptoException(msg, e);
        }
    }

    protected byte[] generateInitializationVector(SecureRandom random) {
        byte[] iv = new byte[this.generatedIvByteLength];
        random.nextBytes(iv);
        return iv;
    }

    protected SecureRandom getSecureRandom(EncryptionRequest<SecretKey> request) {
        SecureRandom random = request.getSecureRandom();
        return random != null ? random : Randoms.secureRandom();
    }

    protected byte[] assertKeyBytes(CryptoRequest<SecretKey> request) {
        SecretKey key = assertKey(request);
        return key.getEncoded();
    }

    protected SecretKey assertKey(CryptoRequest<SecretKey> request) {
        SecretKey key = request.getKey();
        return assertKeyLength(key);
    }

    protected SecretKey assertKeyLength(SecretKey key) {
        int length = length(key.getEncoded());
        if (length != requiredKeyByteLength) {
            throw new CryptoException("The " + getName() + " algorithm requires that keys have a key length of " +
                    "(preferably secure-random) " + requiredKeyBitLength + " bits (" +
                requiredKeyByteLength + " bytes). The provided key has a length of " + length * Byte.SIZE
                    + " bits (" + length + " bytes).");
        }
        return key;
    }

    protected byte[] ensureEncryptionIv(EncryptionRequest<SecretKey> req) {

        final SecureRandom random = getSecureRandom(req);

        byte[] iv = req.getInitializationVector();

        int ivLength = length(iv);
        if (ivLength == 0) {
            iv = generateInitializationVector(random);
        }

        return iv;
    }

    protected byte[] assertDecryptionIv(DecryptionRequest<SecretKey> req) throws IllegalArgumentException {
        byte[] iv = req.getInitializationVector();
        Assert.notEmpty(iv, DECRYPT_NO_IV);
        return iv;
    }

    protected byte[] getAAD(CryptoRequest<SecretKey> request) {
        if (request instanceof AssociatedDataSource) {
            byte[] aad = ((AssociatedDataSource) request).getAssociatedData();
            return io.jsonwebtoken.lang.Arrays.clean(aad);
        }
        return null;
    }

    protected abstract EncryptionResult doEncrypt(EncryptionRequest<SecretKey> req) throws Exception;


    @Override
    public byte[] decrypt(DecryptionRequest<SecretKey> req) throws CryptoException {
        try {
            Assert.notNull(req, "DecryptionRequest cannot be null.");
            return doDecrypt(req);
        } catch (Exception e) {
            String msg = "Unable to perform decryption: " + e.getMessage();
            throw new CryptoException(msg, e);
        }
    }

    protected abstract byte[] doDecrypt(DecryptionRequest<SecretKey> req) throws Exception;
}
