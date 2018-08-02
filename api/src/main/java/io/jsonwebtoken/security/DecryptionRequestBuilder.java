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
package io.jsonwebtoken.security;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface DecryptionRequestBuilder<T extends Key> {

    DecryptionRequestBuilder<T> setInitializationVector(byte[] iv);

    DecryptionRequestBuilder<T> setKey(T key);

    DecryptionRequestBuilder<T> setCiphertext(byte[] plaintext);

    DecryptionRequestBuilder<T> setAdditionalAuthenticatedData(byte[] aad);

    DecryptionRequestBuilder<T> setAuthenticationTag(byte[] tag);

    DecryptionRequest<T> build();
}
