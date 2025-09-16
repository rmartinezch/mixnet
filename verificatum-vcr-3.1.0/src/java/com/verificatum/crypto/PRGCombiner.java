
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

import java.util.Arrays;

import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.ui.Util;
import com.verificatum.util.Functions;


/**
 * Implements a combiner of pseudo-random generators (PRG) and/or
 * other random sources. If the PRGs are independent, then the output
 * is at least as hard to distinguish from random as any of its
 * underlying PRGs. The combiner simply takes the xor of the PRGs it
 * combines.
 *
 * <p>
 *
 * This class allows combining instances of <code>RandomSource</code>
 * as well.
 *
 * @author Douglas Wikstrom
 */
public final class PRGCombiner extends PRG {

    /**
     * Underlying combiner.
     */
    RandomSourceCombiner combiner;

    /**
     * Constructs an instance from the given representation.
     *
     * @param btr Representation of an instance.
     * @return Instance represented by the input.
     * @throws CryptoFormatException If the input does not represent
     *  an instance.
     */
    public static PRGCombiner newInstance(final ByteTreeReader btr)
        throws CryptoFormatException {
        return new PRGCombiner(new RandomSourceCombiner(btr));
    }

    /**
     * Creates an instance with the given underlying combiner.
     *
     * @param combiner Underlying combiner.
     */
    protected PRGCombiner(final RandomSourceCombiner combiner) {
        this.combiner = combiner;
    }

    /**
     * Creates an instance.
     *
     * @param randomSources Instances wrapped by this one.
     */
    public PRGCombiner(final RandomSource... randomSources) {
        combiner = new RandomSourceCombiner(randomSources);
    }

    /**
     * Constructs an instance from the given representation.
     *
     * @param btr Representation of an instance.
     * @throws CryptoFormatException If the input does not represent
     *  an instance.
     */
    public PRGCombiner(final ByteTreeReader btr) throws CryptoFormatException {
        combiner = new RandomSourceCombiner(btr);
    }

    // Documented in PRG.java

    @Override
    public void setSeed(final byte[] seed) {

        if (seed.length >= minNoSeedBytes()) {
            int offset = 0;
            for (int i = 0; i < combiner.randomSources.length; i++) {

                if (combiner.randomSources[i] instanceof PRG) {

                    final int end = offset
                        + ((PRG) combiner.randomSources[i]).minNoSeedBytes();

                    final byte[] tmpSeed =
                        Arrays.copyOfRange(seed, offset, end);

                    ((PRG) combiner.randomSources[i]).setSeed(tmpSeed);
                    offset += tmpSeed.length;
                }
            }
        } else {
            throw new CryptoError("Seed is too short!");
        }
    }

    @Override
    public int minNoSeedBytes() {
        int total = 0;
        for (int i = 0; i < combiner.randomSources.length; i++) {
            if (combiner.randomSources[i] instanceof PRG) {
                total += ((PRG) combiner.randomSources[i]).minNoSeedBytes();
            }
        }
        return total;
    }

    // Documented in RandomSource.java

    @Override
    public void getBytes(final byte[] array) {
        combiner.getBytes(array);
    }

    // Documented in Marshalizable.java

    @Override
    public ByteTreeBasic toByteTree() {
        return combiner.toByteTree();
    }

    @Override
    public String humanDescription(final boolean verbose) {
        final StringBuilder sb = new StringBuilder();

        sb.append(Util.className(this, verbose));
        sb.append('(');
        sb.append(combiner.randomSources[0].humanDescription(verbose));
        for (int i = 1; i < combiner.randomSources.length; i++) {
            sb.append(", ");
            sb.append(combiner.randomSources[i].humanDescription(verbose));
        }
        sb.append(')');

        return sb.toString();
    }

    @Override
    public int hashCode() {
        return Functions.hashCode(this);
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PRGCombiner)) {
            return false;
        }
        return combiner.equals(((PRGCombiner) obj).combiner);
    }
}
