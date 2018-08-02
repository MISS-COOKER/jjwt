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
package io.jsonwebtoken.impl.security

import org.junit.Test

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

import static org.junit.Assert.*

/**
 * @since JJWT_RELEASE_VERSION
 */
class DefaultDecryptionRequestBuilderTest {

    private byte[] generateData() {
        byte[] data = new byte[32];
        new Random().nextBytes(data) //does not need to be secure for this test
        return data;
    }

    private SecretKey generateKey() {
        return new SecretKeySpec(generateData(), "AES")
    }

    @Test
    void testWithoutAadAndWithoutTag() {

        def key = generateKey()
        def iv = generateData()
        def ciphertext = generateData()

        def req = new DefaultDecryptionRequestBuilder()
                .setKey(key).setInitializationVector(iv).setCiphertext(ciphertext).build()

        assertTrue req instanceof DefaultDecryptionRequest
        assertSame key, req.getKey()
        assertSame iv, req.getInitializationVector()
        assertSame ciphertext, req.getCiphertext()
    }

    @Test
    void testAadWithoutTag() {
        try {
            new DefaultDecryptionRequestBuilder()
                    .setCiphertext(generateData())
                    .setKey(generateKey())
                    .setAdditionalAuthenticatedData(generateData()).build()
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals(DefaultDecryptionRequestBuilder.AAD_NEEDS_TAG_MSG, expected.getMessage())
        }
    }

    @Test
    void testSetInitializationVectorWithEmptyArray() {
        def b = new DefaultDecryptionRequestBuilder().setInitializationVector(new byte[0])
        assertNull b.iv
    }

    @Test
    void testSetKeyWithNullKey() {
        try {
            new DefaultDecryptionRequestBuilder().setKey(null)
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testSetAdditionalAuthenticatedDataWithEmptyArray() {
        def b = new DefaultDecryptionRequestBuilder().setAdditionalAuthenticatedData(new byte[0])
        assertNull b.aad
    }

    @Test
    void testSetAuthenticationTagWithEmptyArray() {
        def b = new DefaultDecryptionRequestBuilder().setAuthenticationTag(new byte[0])
        assertNull b.tag
    }
}
