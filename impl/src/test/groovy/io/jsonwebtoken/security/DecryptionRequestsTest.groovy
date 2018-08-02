package io.jsonwebtoken.security

import io.jsonwebtoken.impl.security.DefaultDecryptionRequestBuilder
import io.jsonwebtoken.lang.Classes
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.junit.Assert.assertTrue

/**
 * @since JJWT_RELEASE_VERSION
 */
@RunWith(PowerMockRunner)
@PrepareForTest([Classes, DecryptionRequests])
class DecryptionRequestsTest {

    @Test
    void testPrivateCtor() { //for code coverage only
        new DecryptionRequests()
    }

    @Test
    void testBuilder() {
        assertTrue DecryptionRequests.symmetric() instanceof DefaultDecryptionRequestBuilder
    }
}
