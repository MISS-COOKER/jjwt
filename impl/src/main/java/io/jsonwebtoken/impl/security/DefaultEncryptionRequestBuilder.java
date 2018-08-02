/*
 * Copyright (C) 2016 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.EncryptionRequest;
import io.jsonwebtoken.security.EncryptionRequestBuilder;

import java.security.Key;
import java.security.SecureRandom;

import static io.jsonwebtoken.lang.Arrays.*;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultEncryptionRequestBuilder<T extends Key> implements EncryptionRequestBuilder<T> {

    private SecureRandom secureRandom;
    private byte[] iv;
    private T key;
    private byte[] plaintext;
    private byte[] aad;

    @Override
    public EncryptionRequestBuilder<T> setSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
        return this;
    }

    @Override
    public EncryptionRequestBuilder<T> setInitializationVector(byte[] iv) {
        this.iv = clean(iv);
        return this;
    }

    @Override
    public EncryptionRequestBuilder<T> setKey(T key) {
        this.key = Assert.notNull(key, "Encryption key cannot be null.");
        return this;
    }

    @Override
    public EncryptionRequestBuilder<T> setPlaintext(byte[] plaintext) {
        Assert.notEmpty(plaintext, "Plaintext cannot be null or empty.");
        this.plaintext = plaintext;
        return this;
    }

    @Override
    public EncryptionRequestBuilder<T> setAdditionalAuthenticatedData(byte[] aad) {
        this.aad = clean(aad);
        return this;
    }

    @Override
    public EncryptionRequest<T> build() {
        Assert.notNull(key, "Encryption key cannot be null.");
        Assert.notEmpty(plaintext, "Plaintext cannot be null or empty.");

        if (aad != null) {
            return new DefaultAuthenticatedEncryptionRequest<>(secureRandom, key, iv, plaintext, aad);
        }

        return new DefaultEncryptionRequest<>(secureRandom, key, iv, plaintext);
    }
}
