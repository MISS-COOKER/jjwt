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
import io.jsonwebtoken.security.AuthenticatedDecryptionRequest;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultAuthenticatedDecryptionRequest<T extends Key> extends DefaultDecryptionRequest<T>
        implements AuthenticatedDecryptionRequest<T> {

    private final byte[] aad;

    private final byte[] tag;

    public DefaultAuthenticatedDecryptionRequest(T key, byte[] iv, byte[] ciphertext, byte[] aad, byte[] tag) {
        super(key, iv, ciphertext);
        Assert.notEmpty(tag, "Authentication tag cannot be null or empty.");
        this.aad = aad;
        this.tag = tag;
    }

    @Override
    public byte[] getAssociatedData() {
        return this.aad;
    }

    @Override
    public byte[] getAuthenticationTag() {
        return this.tag;
    }
}
