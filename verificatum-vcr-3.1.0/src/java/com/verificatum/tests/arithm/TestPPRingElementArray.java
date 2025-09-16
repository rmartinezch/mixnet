
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


import com.verificatum.arithm.ArithmException;
import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.SafePrimeTable;
import com.verificatum.arithm.PField;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElement;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.arithm.PPRing;
import com.verificatum.arithm.PPRingElementArray;
import com.verificatum.test.TestParameters;
import com.verificatum.util.Pair;
import com.verificatum.util.Timer;


/**
 * Tests {@link PPRingElementArray}.
 *
 * @author Douglas Wikstrom
 */
public final class TestPPRingElementArray extends TestPRingElementArray {

    /**
     * Constructs test.
     *
     * @param tp Test parameters.
     * @throws ArithmFormatException If construction of the test
     * failed.
     */
    public TestPPRingElementArray(final TestParameters tp)
        throws ArithmFormatException {
        super(TestPPRing.genPRing(512),
              TestPPRing.genPRing(640),
              new PField(SafePrimeTable.safePrime(512)),
              tp);
    }

    /**
     * Product and project.
     */
    public void productProject() {

        final PPRing pPRingA = new PPRing(pRing.getPField(), pRing, pRing);
        final PRing[] pRings = pPRingA.getFactors();

        final int size = 5;

        // Form element from parts.
        final PRingElementArray[] xs = new PRingElementArray[pRings.length];
        for (int i = 0; i < pRings.length; i++) {
            xs[i] = pRings[i].randomElementArray(size, rs, 10);
        }
        final PPRingElementArray x = pPRingA.product(xs);

        // Project to components.
        for (int i = 0; i < xs.length; i++) {
            assert x.project(i).equals(xs[i]) : "Simple projection failed!";
        }

        x.free();
    }

    /**
     * Arithmetic.
     *
     * @throws ArithmException If a test failed.
     */
    public void arithmetic()
        throws ArithmException {
        super.arithmetic();

        final Timer timer = new Timer(testTime);

        int size = 1;
        final int width = 3;
        while (!timer.timeIsUp()) {

            final PPRing pPRing = new PPRing(pRing, width);
            final PPRingElementArray x =
                (PPRingElementArray) pPRing.randomElementArray(size, rs, 10);
            final PRingElementArray y = pRing.randomElementArray(size, rs, 10);

            final PRingElementArray[] xs = x.getFactors();

            final PRingElementArray[] us = new PRingElementArray[width];
            final PRingElementArray[] vs = new PRingElementArray[width];
            final PRingElement[] ws = new PRingElement[width];
            for (int i = 0; i < width; i++) {
                us[i] = xs[i].add(y);
                vs[i] = xs[i].mul(y);
                ws[i] = xs[i].innerProduct(y);
            }

            final PRingElementArray u = pPRing.product(us);
            final PRingElementArray v = pPRing.product(vs);
            final PRingElement w = pPRing.product(ws);

            final PRingElementArray uu = x.add(y);
            final PRingElementArray vv = x.mul(y);
            final PRingElement ww = x.innerProduct(y);

            assert uu.equals(u) : "Subring addition failed for array!";
            assert vv.equals(v) : "Subring addition failed for array!";
            assert ww.equals(w) : "Subring addition failed for array!";

            x.free();
            y.free();

            u.free();
            v.free();

            uu.free();
            vv.free();

            size++;
        }
    }

    /**
     * Exercises modular recursive linear expression appearing in some
     * zero knowledge proofs.
     */
    public void excRecLin() {
        super.excRecLin();

        final PPRing pPRing = new PPRing(pRing, 3);

        final int size = 10;

        final PRingElementArray x = pPRing.randomElementArray(size, rs, 10);

        final PRingElementArray y = pRing.randomElementArray(size, rs, 10);
        final Pair<PRingElementArray, PRingElement> pair = x.recLin(y);
        y.free();
        pair.first.free();
        x.free();
    }
}
