
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

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.SafePrimeTable;
import com.verificatum.eio.Marshalizer;
import com.verificatum.ui.gen.GenException;
import com.verificatum.ui.gen.Generator;
import com.verificatum.ui.gen.GeneratorTool;
import com.verificatum.ui.opt.Opt;

/**
 * Generates a human oriented string representation of a
 * <code>PRGElGamal</code> suitable for initialization files. Using
 * {@link com.verificatum.ui.gen.GeneratorTool} this functionality can be
 * invoked from the command line.
 *
 * @author Douglas Wikstrom
 */
public final class PRGElGamalGen implements Generator {

    /**
     * Determines the probability that a non-safeprime is accepted as
     * a safeprime. This probability is bounded by 2<sup>-{@link
     * #CERTAINTY}</sup>.
     */
    static final int CERTAINTY = 100;

    /**
     * Generates an option instance containing suitable options and
     * description.
     *
     * @return Option instance representing valid inputs to this
     *         instance.
     */
    protected Opt opt() {
        final Opt opt =
            GeneratorTool.defaultOpt(PRGElGamal.class.getSimpleName(), 2);

        opt.setUsageComment("(where " + PRGElGamal.class.getSimpleName()
                            + " = " + PRGElGamal.class.getName() + ")");

        opt.addParameter("modulus",
                         "Modulus in hexadecimal twos complement "
                         + "representation.");
        opt.addParameter("bitLen", "Bits in modulus.");

        opt.addOption("-fixed", "",
                      "Fixed modulus of given size from table in class "
                      + "com.verificatum.arithm.SafePrimeTable.");
        opt.addOption("-explic", "", "Explicit modulus.");
        opt.addOption("-width", "width",
                      "Number of generators in internal state.");
        opt.addOption("-statDist", "bits", "Statistical parameter.");
        opt.addOption("-cert",
                      "value",
                      "Certainty with which probabilistically checked "
                      + "parameters are verified, i.e., the probability of an "
                      + "error is bounded by 2^(-certainty). Default value "
                      + "is " + CERTAINTY + ".");

        final String s =
            "Generates an instance of a provably secure pseudo-random "
            + "generator based on the Decision Diffie-Hellman assumption (DDH) "
            + "in the multiplicative group modulo a safe prime. The parameter "
            + "<width> does not influence security. It decides the number of "
            + "group elements in the internal state of the generator. The "
            + "default width is " + PRGElGamal.DEFAULT_WIDTH + ".";

        opt.appendToUsageForm(1, "-explic#-width,-statDist,-cert#modulus#");
        opt.appendToUsageForm(2, "-fixed#-width,-statDist,-cert#bitLen#");

        opt.appendDescription(s);

        return opt;
    }

    // Documented in com.verificatum.crypto.Generator.java.

    @Override
    public String gen(final RandomSource randomSource, final String[] args)
        throws GenException {

        final Opt opt = opt();

        final String res = GeneratorTool.defaultProcess(opt, args);
        if (res != null) {
            return res;
        }

        int certainty = CERTAINTY;
        if (opt.valueIsGiven("-cert")) {
            certainty = opt.getIntValue("-cert");
            if (certainty <= 0) {
                throw new GenException("Certainty must be positive!");
            }
        }

        LargeInteger modulus = null;

        if (opt.getBooleanValue("-explic")) {
            final String hex = opt.getStringValue("modulus");
            modulus = new LargeInteger(hex, 16);
        } else {

            final int bitLen = opt.getIntValue("bitLen");

            try {
                modulus = SafePrimeTable.safePrime(bitLen);
            } catch (final ArithmFormatException afe) {
                throw new GenException("Invalid bit length!", afe);
            }
        }

        final int width = opt.getIntValue("-width", PRGElGamal.DEFAULT_WIDTH);
        final int statDist = opt
            .getIntValue("-statDist", PRGElGamal.DEFAULT_STATDIST);

        final PRGElGamal prg = new PRGElGamal(modulus, width, statDist);
        return Marshalizer.marshalToHexHuman(prg, opt.getBooleanValue("-v"));
    }

    @Override
    public String briefDescription() {
        return "Pseudo random generator based on DDH in multiplicative "
            + "group modulo a safe prime.";
    }
}
