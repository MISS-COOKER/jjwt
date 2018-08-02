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
import io.jsonwebtoken.security.DecryptionRequest;
import io.jsonwebtoken.security.DecryptionRequestBuilder;

import java.security.Key;

import static io.jsonwebtoken.lang.Arrays.*;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultDecryptionRequestBuilder<T extends Key> implements DecryptionRequestBuilder<T> {

    public static final String AAD_NEEDS_TAG_MSG = "If you specify additional authentication data during " +
            "decryption, you must also specify the authentication tag " +
            "computed during encryption.";

    private byte[] iv;
    private T key;
    private byte[] ciphertext;
    private byte[] aad;
    private byte[] tag;

    @Override
    public DecryptionRequestBuilder setInitializationVector(byte[] iv) {
        this.iv = clean(iv);
        return this;
    }

    @Override
    public DecryptionRequestBuilder setKey(T key) {
        this.key = Assert.notNull(key, "Decryption key cannot be null.");
        return this;
    }

    public DecryptionRequestBuilder setCiphertext(byte[] ciphertext) {
        Assert.notEmpty(ciphertext, "Ciphertext cannot be null or empty.");
        this.ciphertext = ciphertext;
        return this;
    }

    @Override
    public DecryptionRequestBuilder setAdditionalAuthenticatedData(byte[] aad) {
        this.aad = clean(aad);
        return this;
    }

    @Override
    public DecryptionRequestBuilder setAuthenticationTag(byte[] tag) {
        this.tag = clean(tag);
        return this;
    }

    @Override
    public DecryptionRequest<T> build() {
        Assert.notNull(key, "Decryption key cannot be null.");
        Assert.notEmpty(ciphertext, "Ciphertext cannot be null or empty.");

        if (aad != null && tag == null) {
            String msg = AAD_NEEDS_TAG_MSG;
            throw new IllegalArgumentException(msg);
        }

        if (aad != null || tag != null) {
            return new DefaultAuthenticatedDecryptionRequest<T>(key, iv, ciphertext, aad, tag);
        }

        return new DefaultDecryptionRequest<T>(key, iv, ciphertext);
    }

}
