
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

package com.verificatum.tests.arithm;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.ArithmError;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElement;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.eio.ByteTree;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.test.TestClass;
import com.verificatum.test.TestParameters;
import com.verificatum.util.Timer;

// FB_ANNOTATION import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;


/**
 * Tests {@link PRing}.
 *
 * @author Douglas Wikstrom
 */
// FB_ANNOTATION @SuppressFBWarnings(value = "RV_RETURN_VALUE_IGNORED")
public class TestPRing extends TestClass {

    /**
     * Ring used for testing.
     */
    protected PRing pRing;

    /**
     * Secondary ring used for failure testing.
     */
    protected PRing pRing2;

    /**
     * Ring of different class used for failure testing.
     */
    protected PRing otherPRing;

    /**
     * Constructs test.
     *
     * @param pRing Ring used for testing.
     * @param pRing2 Secondary ring used for failure testing.
     * @param otherPRing Ring from other class used for failure
     * testing.
     * @param tp Test parameters.
     * @throws ArithmFormatException If construction of the test
     * failed.
     */
    protected TestPRing(final PRing pRing,
                        final PRing pRing2,
                        final PRing otherPRing,
                        final TestParameters tp)
        throws ArithmFormatException {
        super(tp);
        this.pRing = pRing;
        this.pRing2 = pRing2;
        this.otherPRing = otherPRing;
    }

    /**
     * Exercise toString.
     */
    public void excToString() {
        pRing.toString();
    }

    /**
     * Exercise getCharacteristic.
     */
    public void excGetCharacteristic() {
        pRing.getCharacteristic();
    }

    /**
     * Exercise toString.
     */
    public void excContains() {
        final PRingElement a = pRing.randomElement(rs, 10);
        pRing.contains(a);

        final PRingElement b = pRing2.randomElement(rs, 10);
        pRing.contains(b);
    }

    /**
     * Excercise hashCode.
     */
    public void excHashCode() {
        pRing.hashCode();
    }

    /**
     * Excercise getPRing.
     */
    public void excGetPRing() {
        pRing.getPRing();
    }

    /**
     * Equals.
     */
    public void equality() {

        assert pRing.equals(pRing) : "Equality failed!";
        assert !pRing.equals(pRing2) : "Inequality failed!";
        assert !pRing.equals(new Object()) : "Field equals object!";
    }

    /**
     * Byte tree.
     *
     * @throws ArithmFormatException If a test failed.
     */
    public void arrayByteTree()
        throws ArithmFormatException {

        final Timer timer = new Timer(testTime);

        final int size = 1;

        while (!timer.timeIsUp()) {

            final PRingElement[] xs = pRing.randomElements(size, rs, 10);
            final ByteTreeBasic btb = pRing.toByteTree(xs);

            final ByteTreeReader btr = btb.getByteTreeReader();
            final PRingElement[] ys = pRing.toElements(size + 1, btr);
            for (int i = 0; i < size; i++) {
                assert xs[i].equals(ys[i])
                    : "Failed to recover array from byte tree!";
            }
        }

        final PRingElement[] xs = pRing.randomElements(2, rs, 10);
        final ByteTreeBasic btb = pRing.toByteTree(xs);

        // Fail on too many elements.
        boolean invalid = false;
        try {
            final ByteTreeReader btr = btb.getByteTreeReader();
            pRing.toElements(1, btr);
        } catch (final ArithmFormatException afe) {
            invalid = true;
        }
        assert invalid : "Failed to fail on too many elements!";

        // Fail on bad byte tree.
        invalid = false;
        try {
            final ByteTree bt = new ByteTree(new byte[2]);
            final ByteTreeReader btr = bt.getByteTreeReader();
            pRing.toElements(2, btr);
        } catch (final ArithmFormatException afe) {
            invalid = true;
        }
        assert invalid : "Failed to fail on bad byte tree!";
    }

    /**
     * Unsafe toElement.
     *
     * @throws ArithmFormatException If a test fails.
     */
    public void unsafeToElement()
        throws ArithmFormatException {

        final PRingElement x = pRing.randomElement(rs, 10);
        ByteTreeReader btr = x.toByteTree().getByteTreeReader();
        final PRingElement y = pRing.toElement(btr);
        assert x.equals(y) : "Unsafe element from byte tree failed!";

        boolean invalid = false;
        try {
            final byte[] data = new byte[5];
            final ByteTree bt =
                new ByteTree(new ByteTree(data), new ByteTree(data));
            btr = bt.getByteTreeReader();
            pRing.unsafeToElement(btr);
        } catch (final ArithmError ae) {
            invalid = true;
        }
        assert invalid : "Failed to fail on bad byte tree!";
    }

    /**
     * Unsafe toElementArray.
     */
    public void unsafeToElementArray() {

        final int size = 10;

        final PRingElementArray x = pRing.randomElementArray(size, rs, 10);
        ByteTreeReader btr = x.toByteTree().getByteTreeReader();
        final PRingElementArray y = pRing.unsafeToElementArray(0, btr);
        btr.close();
        assert x.equals(y) : "Unsafe element array from byte tree failed!";
        x.free();
        y.free();

        boolean invalid = false;
        try {
            final byte[] data = new byte[5];
            final ByteTree bt =
                new ByteTree(new ByteTree(data), new ByteTree(data));
            btr = bt.getByteTreeReader();
            pRing.unsafeToElementArray(0, btr);
        } catch (final ArithmError ae) {
            invalid = true;
        }
        assert invalid : "Failed to fail on bad byte tree!";
    }

    /**
     * Arithmetic sugar.
     */
    public void arithmeticSugar() {

        final Timer timer = new Timer(testTime);

        int size = 1;

        while (!timer.timeIsUp()) {

            final PRingElement[] xs = pRing.randomElements(size, rs, 10);
            final PRingElementArray x = pRing.toElementArray(xs);

            final PRingElement[] ys = pRing.randomElements(size, rs, 10);
            final PRingElementArray y = pRing.toElementArray(ys);

            final PRingElement p = x.innerProduct(y);
            final PRingElement pp = pRing.innerProduct(xs, ys);

            assert pp.equals(p) : "Inner product failed!";

            final PRingElementArray r = x.mulAdd(p, y);
            final PRingElement[] rr = pRing.mulAdd(xs, p, ys);
            final PRingElementArray rrr = pRing.toElementArray(rr);

            assert rrr.equals(r) : "Mul-add failed!";

            x.free();
            y.free();
            rrr.free();
            size++;
        }
    }
}
