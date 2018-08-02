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
import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface EncryptionRequestBuilder<T extends Key> {

    EncryptionRequestBuilder<T> setSecureRandom(SecureRandom secureRandom);

    EncryptionRequestBuilder<T> setInitializationVector(byte[] iv);

    EncryptionRequestBuilder<T> setKey(T key);

    EncryptionRequestBuilder<T> setPlaintext(byte[] plaintext);

    EncryptionRequestBuilder<T> setAdditionalAuthenticatedData(byte[] aad);

    EncryptionRequest<T> build();

}
