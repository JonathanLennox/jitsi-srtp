/*
 * Copyright @ 2016 - present 8x8, Inc
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
package org.jitsi.srtp.crypto;

import org.junit.jupiter.api.*;

import javax.crypto.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the checks the OpenSSL ciphers make of the ranges they are given. A {@link Cipher} makes most of these
 * checks itself before it calls its provider, so the tests call the checks directly. They do not need the native
 * library.
 */
public class OpenSslAesCipherSpiTest
{
    private static final byte[] ARRAY = new byte[32];

    @Test
    public void inputRangeInsideArray()
    {
        OpenSslAesCipherSpi.checkInput(ARRAY, 0, 32);
        OpenSslAesCipherSpi.checkInput(ARRAY, 12, 20);
        OpenSslAesCipherSpi.checkInput(ARRAY, 0, 0);
        OpenSslAesCipherSpi.checkInput(ARRAY, 32, 0);
    }

    @Test
    public void inputRangeOutsideArray()
    {
        assertThrows(IllegalArgumentException.class, () -> OpenSslAesCipherSpi.checkInput(ARRAY, 0, 33));
        assertThrows(IllegalArgumentException.class, () -> OpenSslAesCipherSpi.checkInput(ARRAY, 13, 20));
        assertThrows(IllegalArgumentException.class, () -> OpenSslAesCipherSpi.checkInput(ARRAY, 33, 0));
        assertThrows(IllegalArgumentException.class, () -> OpenSslAesCipherSpi.checkInput(ARRAY, -1, 20));
        assertThrows(IllegalArgumentException.class, () -> OpenSslAesCipherSpi.checkInput(ARRAY, 0, -1));
        /* The offset plus the length overflows. */
        assertThrows(IllegalArgumentException.class,
            () -> OpenSslAesCipherSpi.checkInput(ARRAY, 16, Integer.MAX_VALUE));
    }

    @Test
    public void outputWithRoom() throws Exception
    {
        /* In place, as SRTP uses the ciphers. */
        OpenSslAesCipherSpi.checkBuffers(ARRAY, 0, 16, ARRAY, 0, 32);
        OpenSslAesCipherSpi.checkBuffers(ARRAY, 12, 4, ARRAY, 12, 20);
        OpenSslAesCipherSpi.checkBuffers(ARRAY, 0, 16, new byte[16], 0, 16);
        OpenSslAesCipherSpi.checkBuffers(ARRAY, 0, 0, ARRAY, 32, 0);
    }

    @Test
    public void outputWithoutRoom()
    {
        assertThrows(ShortBufferException.class,
            () -> OpenSslAesCipherSpi.checkBuffers(ARRAY, 0, 17, ARRAY, 0, 33));
        assertThrows(ShortBufferException.class,
            () -> OpenSslAesCipherSpi.checkBuffers(ARRAY, 12, 5, ARRAY, 12, 21));
        assertThrows(ShortBufferException.class,
            () -> OpenSslAesCipherSpi.checkBuffers(ARRAY, 0, 16, new byte[15], 0, 16));
        /* An offset after the end of the array. */
        assertThrows(ShortBufferException.class,
            () -> OpenSslAesCipherSpi.checkBuffers(ARRAY, 0, 0, ARRAY, 33, 0));
        /* The length of the input plus the length of the tag overflowed. */
        assertThrows(ShortBufferException.class,
            () -> OpenSslAesCipherSpi.checkBuffers(ARRAY, 0, 16, ARRAY, 0, Integer.MAX_VALUE + 16));
    }

    @Test
    public void rangesOutsideArrays()
    {
        assertThrows(IllegalArgumentException.class,
            () -> OpenSslAesCipherSpi.checkBuffers(ARRAY, 0, 16, ARRAY, -1, 16));
        assertThrows(IllegalArgumentException.class,
            () -> OpenSslAesCipherSpi.checkBuffers(ARRAY, 0, 33, new byte[64], 0, 33));
        assertThrows(IllegalArgumentException.class,
            () -> OpenSslAesCipherSpi.checkBuffers(ARRAY, -1, 16, ARRAY, 0, 16));
    }
}
