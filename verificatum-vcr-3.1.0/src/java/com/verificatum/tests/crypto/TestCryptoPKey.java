
/* Copyright 2008-2019 Douglas Wikstrom
 *
 * This file is part of Verificatum Core Routines (VCR).
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.verificatum.tests.crypto;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.crypto.CryptoKeyGen;
import com.verificatum.crypto.CryptoKeyPair;
import com.verificatum.crypto.CryptoPKey;
import com.verificatum.crypto.CryptoPKeyNaorYung;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.Marshalizer;
import com.verificatum.test.TestClass;
import com.verificatum.test.TestParameters;

// FB_ANNOTATION import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;


/**
 * Tests {@link CryptoPKey}.
 *
 * @author Douglas Wikstrom
 */
// FB_ANNOTATION @SuppressFBWarnings(value = "RV_RETURN_VALUE_IGNORED")
public class TestCryptoPKey extends TestClass {

    /**
     * Key generator used for testing.
     */
    final CryptoKeyGen keyGen;

    /**
     * Public key used for testing.
     */
    final CryptoPKey pkey;

    /**
     * Construct test.
     *
     * @param tp Test parameters.
     * @param keyGen Key generator.
     * @throws ArithmFormatException If the test cannot be constructed.
     */
    public TestCryptoPKey(final TestParameters tp,
                          final CryptoKeyGen keyGen)
        throws ArithmFormatException {
        super(tp);
        this.keyGen = keyGen;
        final CryptoKeyPair keyPair = keyGen.gen(rs, 10);
        this.pkey = keyPair.getPKey();
    }

    /**
     * Exercise toString.
     */
    public void excToString() {
        pkey.toString();
    }

    /**
     * Exercise humanDescription.
     */
    public void excHumanDescription() {
        pkey.humanDescription(true);
    }

    /**
     * Exercise hashCode.
     */
    public void excHashcode() {
        pkey.hashCode();
    }

    /**
     * Exercise encryption.
     */
    public void excEncryption() {
        final int size = 200;
        final byte[] message = rs.getBytes(size);
        final byte[] label = rs.getBytes(size);
        pkey.encrypt(label, message, rs, 10);
    }

    /**
     * Equals.
     *
     * @throws EIOException If a test fails.
     */
    public void equality()
        throws EIOException {

        final ByteTreeBasic bt = Marshalizer.marshal(pkey);
        final ByteTreeReader btr = bt.getByteTreeReader();
        final CryptoPKeyNaorYung pkeyCopy =
            (CryptoPKeyNaorYung)
            Marshalizer.unmarshalAux_CryptoPKey(btr, rs, 10);

        assert pkey.equals(pkey) : "Equality by reference failed!";
        assert pkey.equals(pkeyCopy) : "Equality by value failed!";

        final CryptoKeyPair keyPair2 = keyGen.gen(rs, 10);
        final CryptoPKey pkey2 = keyPair2.getPKey();

        assert !pkey.equals(pkey2) : "Inequality by value failed!";

        assert !pkey.equals(new Object())
            : "Inequality with instance of different class failed!";
    }
}
