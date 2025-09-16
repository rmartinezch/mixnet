
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

package com.verificatum.crypto;

import com.verificatum.eio.ByteTree;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.ExtIO;
import com.verificatum.eio.Marshalizer;
import com.verificatum.ui.Util;

/**
 * A "random oracle" which can be instantiated with a given length
 * output and based on any underlying hashfunction. The
 * "random oracle" first evaluates the length concatenated with its
 * input using the underlying hashfunction. This gives a digest. The
 * output bytes are then derived by concatenating the result of
 * repeatedly evaluating the digest concatenated with an integer
 * counter that is initially set to zero and incremented by one
 * inbetween calls. The resulting output is then truncated to the
 * correct byte length and as many bits as needed in the first output
 * byte are set to zero.
 *
 * @author Douglas Wikstrom
 */
public final class RandomOracle implements Hashfunction {

    /**
     * Underlying hashfunction.
     */
    Hashfunction roHashfunction;

    /**
     * Output bit length.
     */
    int outputLength;

    /**
     * Constructs an instance following the instructions in the input
     * <code>ByteTree</code>.
     *
     * @param btr Instructions for construction of an instance.
     * @param rs Random source used to probabilistically check the
     * validity of an input.
     * @param certainty Certainty with which an input is deemed
     * correct, i.e., an incorrect input is accepted with
     * probability at most 2<sup>- <code>certainty</code>
     * </sup>.
     * @return Random oracle represented by the input.
     * @throws CryptoFormatException If the input does not represent
     *  an instance.
     */
    public static RandomOracle newInstance(final ByteTreeReader btr,
                                           final RandomSource rs,
                                           final int certainty)
        throws CryptoFormatException {
        try {

            final Hashfunction roHashfunction = Marshalizer
                .unmarshalAux_Hashfunction(btr.getNextChild(), rs,
                                           certainty);
            final int outputLength = btr.getNextChild().readInt();

            return new RandomOracle(roHashfunction, outputLength);

        } catch (final EIOException eioe) {
            throw new CryptoFormatException("Unable to interpret!", eioe);
        }
    }

    /**
     * Creates an instance using the given hashfunction and with the
     * given output bit length.
     *
     * @param roHashfunction Underlying hashfunction.
     * @param outputLength Output bit length.
     */
    public RandomOracle(final Hashfunction roHashfunction,
                        final int outputLength) {
        this.roHashfunction = roHashfunction;
        this.outputLength = outputLength;
    }

    // Documented in Hashfunction.java.

    @Override
    public int getOutputLength() {
        return outputLength;
    }

    @Override
    public byte[] hash(final byte[]... datas) {

        final Hashdigest d = getDigest();
        for (int i = 0; i < datas.length; i++) {
            d.update(datas[i]);
        }
        return d.digest();
    }

    @Override
    public Hashdigest getDigest() {
        return new HashdigestRandomOracle(roHashfunction, outputLength);
    }

    // Documented in Marshalizable.java

    @Override
    public ByteTreeBasic toByteTree() {
        return new ByteTreeContainer(Marshalizer.marshal(roHashfunction),
                                     ByteTree.intToByteTree(outputLength));
    }

    @Override
    public String humanDescription(final boolean verbose) {
        return Util.className(this, verbose) + "("
            + roHashfunction.humanDescription(verbose) + ")";
    }

    // Documented in Object.java

    @Override
    public int hashCode() {
        final HashfunctionHeuristic hh = new HashfunctionHeuristic("SHA-256");
        final Hashdigest h = hh.getDigest();
        toByteTree().update(h);
        final byte[] d = h.digest();
        return ExtIO.readInt(d, 0);
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RandomOracle)) {
            return false;
        }
        final RandomOracle ro = (RandomOracle) obj;
        return roHashfunction.equals(ro.roHashfunction)
            && outputLength == ro.outputLength;
    }
}
