
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

package com.verificatum.arithm;

import java.util.Arrays;

import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.ByteTreeReader;


/**
 * Represents an immutable permutation stored in memory which allows
 * the permutation and its inverse to be applied to arrays of
 * elements.
 *
 * @author Douglas Wikstrom
 */
public final class PermutationIM extends Permutation {

    /**
     * Generates an instance represented by the input.
     *
     * @param table Representation of a permutation.
     */
    protected PermutationIM(final LargeIntegerArray table) {
        super(table);
    }

    /**
     * Generates the identity permutation of a given size.
     *
     * @param numberOfElements Number of elements to permute.
     */
    public PermutationIM(final int numberOfElements) {
        super(numberOfElements);
    }

    /**
     * Creates a permutation from the input representation.
     *
     * @param size Expected size of the permutation.
     * @param btr Representation of permutation.
     * @throws ArithmFormatException If the input is incorrect or has
     *  wrong size.
     */
    public PermutationIM(final int size, final ByteTreeReader btr)
        throws ArithmFormatException {
        super(size, btr);
    }

    /**
     * Generates a random permutation of suitable size using the given
     * source of randomness.
     *
     * @param numberOfElements Number of elements to permute.
     * @param statDist Decides the statistical distance from the
     * uniform distribution.
     * @param randomSource Source of randomness used to generate the
     * permutation.
     */
    public PermutationIM(final int numberOfElements,
                         final RandomSource randomSource,
                         final int statDist) {

        final int aprLog = MathExt.log2c(numberOfElements);

        // The union bound gives this overly conservative bit size.
        final int bits = statDist + aprLog + aprLog;

        final PermutationPair[] randomTable =
            new PermutationPair[numberOfElements];

        for (int i = 0; i < numberOfElements; i++) {
            randomTable[i] = new PermutationPair(i, bits, randomSource);
        }

        Arrays.sort(randomTable);

        final LargeInteger[] integers = new LargeInteger[numberOfElements];
        for (int i = 0; i < numberOfElements; i++) {
            integers[i] = randomTable[i].index;
        }
        table = LargeIntegerArray.toLargeIntegerArray(integers);
    }

    @Override
    public Permutation inv() {
        final LargeInteger[] invtable = new LargeInteger[table.size()];
        final LargeInteger[] orig = table.integers();

        for (int i = 0; i < orig.length; i++) {
            invtable[orig[i].intValue()] = new LargeInteger(i);
        }
        return new PermutationIM(new LargeIntegerArrayIM(invtable));
    }

    @Override
    public Permutation shrink(final int size) {

        final LargeInteger outside = new LargeInteger(table.size());

        final LargeInteger[] tmpTable = new LargeInteger[table.size()];
        Arrays.fill(tmpTable, outside);
        final LargeInteger[] orig = table.integers();

        for (int i = 0; i < size; i++) {
            tmpTable[orig[i].intValue()] = new LargeInteger(i);
        }

        final LargeInteger[] newTable = new LargeInteger[size];

        int l = 0;
        for (int i = 0; i < tmpTable.length; i++) {
            if (tmpTable[i].compareTo(outside) != 0) {
                newTable[tmpTable[i].intValue()] = new LargeInteger(l);
                l++;
            }
        }

        return new PermutationIM(new LargeIntegerArrayIM(newTable));
    }

    /**
     * Applies this permutation to the elements in the first input
     * array and stores the result in the second input. The arrays
     * must have the same size as this permutation.
     *
     * @param array Array to be permuted.
     * @param permutedArray Stores the result.
     */
    public void applyPermutation(final Object[] array,
                                 final Object[] permutedArray) {
        final LargeInteger[] integers = table.integers();
        for (int i = 0; i < array.length; i++) {
            permutedArray[integers[i].intValue()] = array[i];
        }
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof PermutationIM)) {
            return false;
        }
        final LargeIntegerArray otherTable = ((PermutationIM) obj).table;

        return table.equals(otherTable);
    }
}

/**
 * Class used to sample a uniformly random permutation.
 *
 * @author Douglas Wikstrom
 */
class PermutationPair implements Comparable<PermutationPair> {

    /**
     * Randomly chosen prefix used for ordering instances.
     */
    LargeInteger randomPrefix;

    /**
     * Index of this instance.
     */
    LargeInteger index;

    /**
     * Creates an instance with the given index and a randomly chosen
     * random prefix of the given bitlength. The bitlength determines
     * the statistical distance from the uniform distribution of the
     * resulting permutation.
     *
     * @param index Index of this instance.
     * @param bits Bitlength of random prefix used for sorting.
     * @param randomSource Source of randomness.
     */
    PermutationPair(final int index,
                    final int bits,
                    final RandomSource randomSource) {
        this.randomPrefix = new LargeInteger(bits, randomSource);
        this.index = new LargeInteger(index);
    }

    @Override
    public int compareTo(final PermutationPair permutationPair) {
        return randomPrefix.compareTo(permutationPair.randomPrefix);
    }

    @Override
    public int hashCode() {
        return randomPrefix.intValue();
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PermutationPair)) {
            return false;
        }
        final PermutationPair pp = (PermutationPair) obj;

        return index == pp.index && randomPrefix.equals(pp.randomPrefix);
    }
}
