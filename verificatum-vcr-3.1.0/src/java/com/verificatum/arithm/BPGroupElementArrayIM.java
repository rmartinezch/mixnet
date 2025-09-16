
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

import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.EIOException;

/**
 * In-memory implementation of an array of {@link BPGroupElement} of a
 * {@link BPGroup}. This is a wrapper of a primitive array of {@link
 * BPGroupElement}-instances.
 *
 * @author Douglas Wikstrom
 */
public class BPGroupElementArrayIM extends PGroupElementArray {

    /**
     * Representation of this instance.
     */
    protected PGroupElement[] values;

    /**
     * Constructs an array of elements of the given group.
     *
     * @param pGroup Group to which the elements of this array belong.
     * @param values Elements of this array.
     */
    protected BPGroupElementArrayIM(final PGroup pGroup,
                                    final PGroupElement[] values) {
        super(pGroup);
        this.values = Arrays.copyOfRange(values, 0, values.length);
    }

    /**
     * Constructs an array of elements from the given representation.
     *
     * @param pGroup Group to which the elements of this array belong.
     * @param size Expected number of elements in array.
     * @param btr Representation of an instance.
     * @param safe Indicates if the input elements should be verified.
     *
     * @throws ArithmFormatException If the input does not represent
     * an instance.
     */
    protected BPGroupElementArrayIM(final PGroup pGroup,
                                    final int size,
                                    final ByteTreeReader btr,
                                    final boolean safe)
        throws ArithmFormatException {
        super(pGroup);

        int actualSize = size;
        if (actualSize == 0) {
            actualSize = btr.getRemaining();
        }

        if (btr.getRemaining() != actualSize) {
            throw new ArithmFormatException("Unexpected size!");
        }

        this.values = new PGroupElement[actualSize];

        try {
            for (int i = 0; i < actualSize; i++) {
                values[i] = pGroup.unsafeToElement(btr.getNextChild());
            }
            if (safe) {
                ((BPGroup) this.pGroup).verifyUnsafe(values);
            }
        } catch (final EIOException eioe) {
            throw new ArithmFormatException("Malformed array!", eioe);
        }
    }

    // Documented in PGroupElementArray.java

    @Override
    public ByteTreeBasic toByteTree() {
        return new ByteTreeContainer(values);
    }

    @Override
    public PGroupElement[] elements() {
        return Arrays.copyOf(values, values.length);
    }

    @Override
    public PGroupElementIterator getIterator() {
        return new BPGroupElementIteratorIM(this);
    }

    @Override
    public PGroupElement get(final int index) {
        return values[index];
    }

    @Override
    public PGroupElementArray mul(final PGroupElementArray factorsArray) {
        if (factorsArray.getPGroup().equals(pGroup)) {
            final PGroupElement[] factors =
                ((BPGroupElementArrayIM) factorsArray).values;
            return new BPGroupElementArrayIM(pGroup,
                                             pGroup.mul(values, factors));
        } else {
            throw new ArithmError(PGroup.MISMATCHING_GROUPS);
        }
    }

    @Override
    public PGroupElementArray inv() {
        return new BPGroupElementArrayIM(pGroup, pGroup.inv(values));
    }

    @Override
    public PGroupElementArray exp(final PRingElementArray exponentsArray) {
        if (exponentsArray.getPRing().equals(pGroup.getPRing())) {
            final PFieldElement[] exponents =
                ((PFieldElementArray) exponentsArray).elements();
            return new BPGroupElementArrayIM(pGroup,
                                             pGroup.exp(values, exponents));
        } else {
            throw new ArithmError(PGroup.MISMATCHING_GROUP_RING);
        }
    }

    @Override
    public PGroupElementArray exp(final PRingElement exponent) {
        if (exponent.getPRing().equals(pGroup.getPRing())) {
            return new BPGroupElementArrayIM(pGroup,
                                             pGroup.exp(values, exponent));
        } else {
            throw new ArithmError(PGroup.MISMATCHING_GROUP_RING);
        }
    }

    @Override
    public PGroupElement prod() {
        return pGroup.prod(values);
    }

    @Override
    public PGroupElement expProd(final PRingElementArray exponentsArray) {
        if (exponentsArray.getPRing().equals(pGroup.getPRing())) {
            final PFieldElement[] exponents =
                ((PFieldElementArray) exponentsArray).elements();
            return pGroup.expProd(values, exponents);
        } else {
            throw new ArithmError(PGroup.MISMATCHING_GROUP_RING);
        }
    }

    @Override
    public int compareTo(final PGroupElementArray array) {
        if (array.getPGroup().equals(pGroup)) {
            return pGroup.compareTo(values,
                                    ((BPGroupElementArrayIM) array).values);
        } else {
            throw new ArithmError(PGroup.MISMATCHING_GROUPS);
        }
    }

    @Override
    public boolean equals(final Object otherArray) {
        if (otherArray == this) {
            return true;
        }
        if (!(otherArray instanceof BPGroupElementArrayIM)) {
            return false;
        }
        return Arrays.equals(values,
                             ((BPGroupElementArrayIM) otherArray).values);
    }

    @Override
    public boolean[] equalsAll(final PGroupElementArray otherArray) {
        if (otherArray.getPGroup().equals(pGroup)) {
            final PGroupElement[] others =
                ((BPGroupElementArrayIM) otherArray).values;
            return pGroup.equalsAll(values, others);
        } else {
            throw new ArithmError("Illegal comparison!");
        }
    }

    @Override
    public int size() {
        return values.length;
    }

    @Override
    public PGroupElementArray permute(final Permutation permutation) {
        final PGroupElement[] permuted = new PGroupElement[values.length];
        ((PermutationIM) permutation).applyPermutation(values, permuted);
        return new BPGroupElementArrayIM(pGroup, permuted);
    }

    @Override
    public PGroupElementArray shiftPush(final PGroupElement el) {
        if (el.getPGroup().equals(pGroup)) {
            return new BPGroupElementArrayIM(pGroup,
                                             pGroup.shiftPush(values, el));
        } else {
            throw new ArithmError(PGroup.MISMATCHING_GROUPS);
        }
    }

    @Override
    public PGroupElementArray copyOfRange(final int startIndex,
                                          final int endIndex) {
        return new BPGroupElementArrayIM(pGroup,
                                         Arrays.copyOfRange(values,
                                                            startIndex,
                                                            endIndex));
    }

    @Override
    public PGroupElementArray extract(final boolean[] valid) {

        if (valid.length != size()) {
            throw new ArithmError("Wrong size of characteristic vector!");
        }

        // Number of elements to extract.
        int count = 0;
        for (int i = 0; i < valid.length; i++) {
            if (valid[i]) {
                count++;
            }
        }

        // Extract.
        final PGroupElement[] res = new PGroupElement[count];
        for (int i = 0, j = 0; i < valid.length; i++) {
            if (valid[i]) {
                res[j++] = values[i];
            }
        }
        return new BPGroupElementArrayIM(pGroup, res);
    }

    @Override
    public void free() {
    }
}
