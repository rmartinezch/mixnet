
/* Copyright 2008-2019 Douglas Wikstrom
 *
 * This file is part of Verificatum Mix-Net (VMN).
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

package com.verificatum.protocol.hvzk;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.LargeIntegerArray;
import com.verificatum.arithm.PField;
import com.verificatum.arithm.PFieldElement;
import com.verificatum.arithm.PFieldElementArray;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElement;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.arithm.Permutation;
import com.verificatum.crypto.PRG;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.EIOException;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.util.Pair;

/**
 * Implements the basic functionality of a variation of Terelius and
 * Wikstrom's proof of a shuffle.
 *
 * <p>
 *
 * For clarity, each method is labeled BOTH, PROVER, or VERIFIER
 * depending on which parties normally call the method.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.VariableNamingConventions",
                   "PMD.MethodNamingConventions",
                   "PMD.SingletonClassReturningNewInstanceRule"})
public final class PoSBasicTW {

    // ####################### Context ############################

    /**
     * Source of random bits.
     */
    private final RandomSource randomSource;

    /**
     * Size of the set that is permuted.
     */
    int size;

    /**
     * Bit length of the challenge.
     */
    int vbitlen;

    /**
     * Bit length of each element in the batching vector.
     */
    int ebitlen;

    /**
     * Pseudo-random generator used to derive the random vector.
     */
    PRG prg;

    /**
     * Decides the statistical distance from the uniform distribution.
     */
    int rbitlen;

    /**
     * Underlying group.
     */
    PGroup pGroup;

    /**
     * Ring associated with the group.
     */
    PRing pRing;

    /**
     * Field associated with the ring.
     */
    PField pField;

    // ################### Instance and witness ###################

    /**
     * Standard generator of the group.
     */
    PGroupElement g;

    /**
     * Array of "independent" generators.
     */
    PGroupElementArray h;

    /**
     * Random exponents used to form the permutation commitment.
     */
    PRingElementArray r;

    /**
     * Permutation committed to.
     */
    Permutation pi;

    /**
     * Public key used to re-encrypt.
     */
    PPGroupElement pkey;

    /**
     * Input ciphertexts.
     */
    PGroupElementArray w;

    /**
     * Output ciphertexts.
     */
    PGroupElementArray wp;

    /**
     * Random exponents used to form the output ciphertexts.
     */
    PRingElementArray s;

    // ################# Message 0 (prover) #######################

    /**
     * Commitment of a permutation.
     */
    PGroupElementArray u;

    // ################# Message 1 (verifier) #####################

    /**
     * Vector of random exponents.
     */
    PFieldElementArray e;

    // ################# Message 2 (prover) #######################

    /**
     * Batched permutation commitments.
     */
    PGroupElement pA;

    /**
     * Bridging commitments used to build up a product in the
     * exponent.
     */
    PGroupElementArray pgeaB;

    /**
     * Product of components of permutation commitment and independent
     * generators.
     */
    PGroupElement pC;

    /**
     * Last bridging commitment with product of batching elements
     * eliminated in the exponent.
     */
    PGroupElement pgeD;

    /**
     * Batched input ciphertexts computed in pre-computation phase.
     */
    PGroupElement pgeF;

    /**
     * Proof commitment used for the bridging commitments.
     */
    PGroupElement pgeAp;

    /**
     * Proof commitments for the bridging commitments.
     */
    PGroupElementArray pgeBp;

    /**
     * Proof commitment for proving sum of random components.
     */
    PGroupElement pgeCp;

    /**
     * Proof commitment for proving product of random components.
     */
    PGroupElement pgeDp;

    /**
     * Proof commitment.
     */
    PGroupElement pgeFp;

    // ########### Secret values for bridging commitment #######

    /**
     * Inversely permuted random vector.
     */
    PFieldElementArray ipe;

    /**
     * Randomness to form the bridging commitments.
     */
    PRingElementArray pB;

    /**
     * Randomness to form the last bridging commitment in a different
     * way.
     */
    PRingElement pD;

    // ######### Randomizers and blinders of the prover ########

    /**
     * Randomizer for inner product of r and ipe.
     */
    PRingElement alpha;

    /**
     * Randomizer for b.
     */
    PRingElementArray beta;

    /**
     * Randomizer for sum of the elements in r.
     */
    PRingElement gamma;

    /**
     * Randomizer for opening last element of B.
     */
    PRingElement delta;

    /**
     * Randomizer for inverse permuted batching vector.
     */
    PFieldElementArray epsilon;

    /**
     * Randomizer for f.
     */
    PRingElement phi;

    // ################## Message 3 (Verifier) ##################

    /**
     * Challenge from the verifier.
     */
    PFieldElement v;

    // ################## Message 4 (Prover) ##################

    /**
     * Reply for bridging commitment blinder.
     */
    PRingElement kA;

    /**
     * Reply for bridging commitments blinders.
     */
    PRingElementArray kB;

    /**
     * Reply for sum of random vector components blinder.
     */
    PRingElement kC;

    /**
     * Reply for product of random vector components blinder.
     */
    PRingElement kD;

    /**
     * Reply for the inverse permuted random vector.
     */
    PFieldElementArray kE;

    /**
     * Reply inner product of s and e.
     */
    PRingElement kF;

    /**
     * BOTH: Constructor to instantiate the protocol.
     *
     * @param vbitlen Bit length of the challenge.
     * @param ebitlen Bit length of each component in random
     * vector.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     * @param prg Pseudo-random generator used to derive random prime
     * vector.
     * @param randomSource Source of randomness.
     */
    public PoSBasicTW(final int vbitlen,
                      final int ebitlen,
                      final int rbitlen,
                      final PRG prg,
                      final RandomSource randomSource) {
        this.vbitlen = vbitlen;
        this.ebitlen = ebitlen;
        this.rbitlen = rbitlen;
        this.prg = prg;
        this.randomSource = randomSource;

        // This is not needed, but it make things more explicit.
        this.e = null;
        this.pgeaB = null;
        this.pgeAp = null;
        this.pgeBp = null;
        this.pgeCp = null;
        this.pgeDp = null;
        this.ipe = null;
        this.pB = null;
        this.pD = null;
        this.alpha = null;
        this.beta = null;
        this.gamma = null;
        this.delta = null;
        this.epsilon = null;
        this.kA = null;
        this.kB = null;
        this.kC = null;
        this.kD = null;
        this.kE = null;
    }

    /**
     * Returns the standard generator used.
     *
     * @return Standard generator.
     */
    public PGroupElement getg() {
        return g;
    }

    /**
     * Returns the independent generators used.
     *
     * @return Independent generators.
     */
    public PGroupElementArray geth() {
        return h;
    }

    /**
     * Returns the permutation commitment.
     *
     * @return Permutation commitment.
     */
    public PGroupElementArray getu() {
        return u;
    }

    /**
     * VERIFIER: Perform precomputation.
     *
     * @param g Standard generator used in permutation commitments.
     * @param h "Independent" generators used in permutation
     * commitments.
     */
    public void precompute(final PGroupElement g, final PGroupElementArray h) {
        this.size = h.size();
        this.pGroup = g.getPGroup();
        this.pRing = pGroup.getPRing();
        this.pField = pRing.getPField();

        this.g = g;
        this.h = h;
    }

    /**
     * VERIFIER: Compute A and F in parallel with prover.
     */
    public void computeAF() {
        pA = u.expProd(e);
        pgeF = w.expProd(e);
    }

    /**
     * VERIFIER: Initializes the instance.
     *
     * @param pkey Public key used to re-encrypt.
     * @param w List of ciphertexts.
     * @param wp List of ciphertexts.
     */
    public void setInstance(final PGroupElement pkey,
                            final PGroupElementArray w,
                            final PGroupElementArray wp) {
        this.pkey = (PPGroupElement) pkey;
        this.w = w;
        this.wp = wp;
        this.s = null;
    }

    /**
     * PROVER: Perform precomputation.
     *
     * @param g Standard generator used in permutation commitments.
     * @param h "Independent" generators used in permutation
     * commitments.
     * @param pi Permutation.
     */
    public void precompute(final PGroupElement g,
                           final PGroupElementArray h,
                           final Permutation pi) {
        precompute(g, h);
        this.pi = pi;

        this.r = pRing.randomElementArray(size, randomSource, rbitlen);
        final PGroupElementArray tmp1 = g.exp(r);
        final PGroupElementArray tmp2 = h.mul(tmp1);
        tmp1.free();

        u = tmp2.permute(pi);
        tmp2.free();

        // During verification, the verifier computes:
        //
        // A = \prod u_i^{e_i} (3)
        //
        // and requires that it equals:
        //
        // g^{<r,e'>} * \prod h_i^{e_i'} (4)
        //
        // We must show that we can open (3) as (4). For that purpose
        // we generate randomizers.

        alpha = pRing.randomElement(randomSource, rbitlen);

        // The bit length of each component of e (and e') is
        // bounded. Thus, we can sample its randomizers as follows.

        final int epsilonBitLength = ebitlen + vbitlen + rbitlen;

        final LargeIntegerArray epsilonIntegers =
            LargeIntegerArray.random(size, epsilonBitLength, randomSource);
        epsilon = pField.toElementArray(epsilonIntegers);
        epsilonIntegers.free();

        pgeAp = g.exp(alpha).mul(h.expProd(epsilon));
    }

    /**
     * PROVER: Initializes the instance.
     *
     * @param pkey Public key used to re-encrypt.
     * @param w List of ciphertexts.
     * @param wp List of ciphertexts.
     * @param s Random exponents used to process ciphertexts.
     */
    public void setInstance(final PGroupElement pkey,
                            final PGroupElementArray w,
                            final PGroupElementArray wp,
                            final PRingElementArray s) {
        setInstance(pkey, w, wp);
        this.s = s;
    }

    /**
     * Initialize permutation commitment.
     *
     * @param btr Representation of permutation commitment.
     */
    public void setPermutationCommitment(final ByteTreeReader btr) {
        try {
            u = pGroup.toElementArray(h.size(), btr);
        } catch (final ArithmFormatException afe) {

            // If something goes wrong we initialize to the trivial
            // commitment of the identity permutation.
            u = h.copyOfRange(0, h.size());
        }
    }

    /**
     * Returns the permutation commitment.
     *
     * @return Permutation commitment of this instance.
     */
    public PGroupElementArray getPermutationCommitment() {
        return u;
    }

    /**
     * BOTH: Extracts the random vector from a seed. This is useful
     * when the honest verifier is replaced by a coin tossing protocol
     * or when this protocol is used as a subprotocol.
     *
     * @param prgSeed Seed to the pseudorandom generator used to
     * extract the random vector.
     */
    public void setBatchVector(final byte[] prgSeed) {
        prg.setSeed(prgSeed);
        final LargeIntegerArray lia =
            LargeIntegerArray.random(size, ebitlen, prg);
        this.e = pField.unsafeToElementArray(lia);
    }

    /**
     * PROVER: Generates the commitment of the prover.
     *
     * @param prgSeed Seed used to extract the random vector.
     * @return Representation of the commitments.
     */
    public ByteTreeBasic commit(final byte[] prgSeed) {

        setBatchVector(prgSeed);

        // ################# Permuted Batching Vector #############

        final Permutation piinv = pi.inv();
        ipe = e.permute(piinv);
        piinv.free();

        // ################# Bridging Commitments #################

        // When using Pedersen commitments we use the standard
        // generator g and the first element in the list of
        // "independent generators.

        final PGroupElement h0 = h.get(0);

        // The array of bridging commitments is of the form:
        //
        // B_0 = g^{b_0} * h0^{e_0'} (1)
        // B_i = g^{b_i} * B_{i-1}^{e_i'} (2)
        //
        // where we generate the b array as follows:

        pB = pRing.randomElementArray(size, randomSource, rbitlen);

        final Pair<PRingElementArray, PRingElement> p = pB.recLin(ipe);
        final PRingElementArray x = p.first;
        pD = p.second;

        // Compute aggregated products:
        //
        // e_0', e_0'*e_1', e_0'*e_1'*e_2', ...
        //
        final PRingElementArray y = ipe.prods();

        final PGroupElementArray gExpX = g.exp(x);

        final PGroupElementArray h0ExpY = h0.exp(y);

        pgeaB = gExpX.mul(h0ExpY);

        // Free temporary variables.
        gExpX.free();
        h0ExpY.free();

        // ################# Proof Commitments ####################

        // During verification, the verifier also requires that (1)
        // and (2) holds. Thus, we choose new randomizers,

        beta = pRing.randomElementArray(size, randomSource, rbitlen);

        final PRingElementArray xp = x.shiftPush(x.getPRing().getZERO());
        final PRingElementArray yp = y.shiftPush(y.getPRing().getONE());
        y.free();
        x.free();

        final PRingElementArray xpMulEpsilon = xp.mul(epsilon);
        final PRingElementArray betaAddProd = beta.add(xpMulEpsilon);
        final PGroupElementArray gExpBetaAddProd = g.exp(betaAddProd);
        final PRingElementArray ypMulEpsilon = yp.mul(epsilon);
        final PGroupElementArray h0ExpYpMulEpsilon = h0.exp(ypMulEpsilon);

        pgeBp = gExpBetaAddProd.mul(h0ExpYpMulEpsilon);

        h0ExpYpMulEpsilon.free();
        ypMulEpsilon.free();
        gExpBetaAddProd.free();
        betaAddProd.free();
        xpMulEpsilon.free();
        yp.free();
        xp.free();

        gamma = pRing.randomElement(randomSource, rbitlen);
        pgeCp = g.exp(gamma);

        delta = pRing.randomElement(randomSource, rbitlen);
        pgeDp = g.exp(delta);

        // We must show that we can open F = \prod w_i^{e_i} as F = Enc_pk(1,-f)\prod (w_i')^{e_i'} where f=<s,e>.
        final PRing ciphPRing = pkey.project(0).getPGroup().getPRing();
        phi = ciphPRing.randomElement(randomSource, rbitlen);

        pgeFp = pkey.exp(phi.neg()).mul(wp.expProd(epsilon));

        // ################### Byte tree ##########################

        return new ByteTreeContainer(pgeaB.toByteTree(),
                                     pgeAp.toByteTree(),
                                     pgeBp.toByteTree(),
                                     pgeCp.toByteTree(),
                                     pgeDp.toByteTree(),
                                     pgeFp.toByteTree());
    }

    /**
     * Return the value of B in the protocol.
     *
     * @return Value of B in the protocol.
     */
    public PGroupElementArray getB() {
        return pgeaB;
    }

    /**
     * Return the value of A in the protocol.
     *
     * @return Value of A in the protocol.
     */
    public PGroupElement getA() {
        return pA;
    }

    /**
     * Return the value of A' in the protocol.
     *
     * @return Value of A' in the protocol.
     */
    public PGroupElement getAp() {
        return pgeAp;
    }

    /**
     * Return the value of B' in the protocol.
     *
     * @return Value of B' in the protocol.
     */
    public PGroupElementArray getBp() {
        return pgeBp;
    }

    /**
     * Return the value of C' in the protocol.
     *
     * @return Value of C' in the protocol.
     */
    public PGroupElement getCp() {
        return pgeCp;
    }

    /**
     * Return the value of D' in the protocol.
     *
     * @return Value of D' in the protocol.
     */
    public PGroupElement getDp() {
        return pgeDp;
    }

    /**
     * Return the value of F in the protocol.
     *
     * @return Value of F in the protocol.
     */
    public PGroupElement getF() {
        return pgeF;
    }

    /**
     * Return the value of F' in the protocol.
     *
     * @return Value of F' in the protocol.
     */
    public PGroupElement getFp() {
        return pgeFp;
    }

    /**
     * VERIFIER: Sets the commitment.
     *
     * @param btr Commitment from the prover.
     * @return Representation of the commitments.
     */
    public ByteTreeBasic setCommitment(final ByteTreeReader btr) {

        final PGroup ciphPGroup = pkey.getPGroup();

        boolean malformed = false;
        try {

            pgeaB = pGroup.toElementArray(size, btr.getNextChild());
            pgeAp = pGroup.toElement(btr.getNextChild());
            pgeBp = pGroup.toElementArray(size, btr.getNextChild());
            pgeCp = pGroup.toElement(btr.getNextChild());
            pgeDp = pGroup.toElement(btr.getNextChild());
            pgeFp = ciphPGroup.toElement(btr.getNextChild());

        } catch (final EIOException | ArithmFormatException eioe) {
            malformed = true;
        }

        // If anything is malformed we set it to suitable
        // predetermined trivial value.
        if (malformed) {

            pgeaB.free();
            pgeaB = pGroup.toElementArray(size, pGroup.getONE());

            pgeAp = pGroup.getONE();

            pgeBp.free();
            pgeBp = pGroup.toElementArray(size, pGroup.getONE());

            pgeCp = pGroup.getONE();
            pgeDp = pGroup.getONE();
            pgeFp = ciphPGroup.getONE();
        }

        return new ByteTreeContainer(pgeaB.toByteTree(),
                                     pgeAp.toByteTree(),
                                     pgeBp.toByteTree(),
                                     pgeCp.toByteTree(),
                                     pgeDp.toByteTree(),
                                     pgeFp.toByteTree());
    }

    /**
     * Returns the bit length of challenges.
     *
     * @return Bit length of challenge.
     */
    public int getVbitlen() {
        return vbitlen;
    }

    /**
     * VERIFIER: Sets the challenge. This is useful if the challenge
     * is generated jointly.
     *
     * @param integerChallenge Challenge of verifier.
     */
    public void setChallenge(final LargeInteger integerChallenge) {

        if (!(0 <= integerChallenge.compareTo(LargeInteger.ZERO)
              && integerChallenge.bitLength() <= vbitlen)) {
            throw new ProtocolError("Malformed challenge!");
        }
        this.v = pField.toElement(integerChallenge);
    }

    /**
     * Computes the reply of the prover to the given challenge, i.e.,
     * the second message of the prover.
     *
     * @param integerChallenge Challenge of verifier.
     * @return Reply of prover.
     */
    public ByteTreeBasic reply(final LargeInteger integerChallenge) {

        setChallenge(integerChallenge);

        // Initialize the special exponents.
        final PRingElement a = r.innerProduct(ipe);
        final PRingElement c = r.sum();
        final PRingElement f = s.innerProduct(e);

        // Compute the replies as:
        //
        // k_A = a * v + \alpha
        // k_{B,i} = vb_i + \beta_i
        // k_C = vc + \gamma
        // k_D = vd + \delta
        // k_{E,i} = ve_i' + \epsilon_i
        //
        kA = a.mulAdd(v, alpha);
        kB = pB.mulAdd(v, beta);
        kC = c.mulAdd(v, gamma);
        kD = pD.mulAdd(v, delta);
        kE = (PFieldElementArray) ipe.mulAdd(v, epsilon);
        kF = f.mulAdd(v, phi);

        return
            new ByteTreeContainer(kA.toByteTree(),
                                  kB.toByteTree(),
                                  kC.toByteTree(),
                                  kD.toByteTree(),
                                  kE.toByteTree(),
                                  kF.toByteTree());
    }

    /**
     * A component of reply.
     *
     * @return A component of reply.
     */
    public PRingElement getkA() {
        return kA;
    }

    /**
     * B component of reply.
     *
     * @return B component of reply.
     */
    public PRingElementArray getkB() {
        return kB;
    }

    /**
     * C component of reply.
     *
     * @return C component of reply.
     */
    public PRingElement getkC() {
        return kC;
    }

    /**
     * D component of reply.
     *
     * @return D component of reply.
     */
    public PRingElement getkD() {
        return kD;
    }

    /**
     * E component of reply.
     *
     * @return E component of reply.
     */
    public PRingElementArray getkE() {
        return kE;
    }

    /**
     * F component of reply.
     *
     * @return F component of reply.
     */
    public PRingElement getkF() {
        return kF;
    }

    /**
     * C component of reply.
     *
     * @return C component of reply.
     */
    public PGroupElement getC() {
        return pC;
    }

    /**
     * D component of reply.
     *
     * @return D component of reply.
     */
    public PGroupElement getD() {
        return pgeD;
    }

    /**
     * Parse replies of prover.
     *
     * @param ciphPRing Group containing ciphertexts.
     * @param btr Source of replies.
     * @return True or false depending on if the replies were parsed
     * correctly.
     */
    private boolean parseReplies(final PRing ciphPRing,
                                   final ByteTreeReader btr) {

        // Read and parse the replies.
        try {

            kA = pRing.toElement(btr.getNextChild());
            kB = pRing.toElementArray(size, btr.getNextChild());
            kC = pRing.toElement(btr.getNextChild());
            kD = pRing.toElement(btr.getNextChild());
            kE = pField.toElementArray(size, btr.getNextChild());
            kF = ciphPRing.toElement(btr.getNextChild());

            return true;

        } catch (final EIOException | ArithmFormatException eio) {
            return false;
        }
    }

    /**
     * VERIFIER: Verifies the reply of the prover and outputs true or
     * false depending on if the reply was accepted or not.
     *
     * @param btr Reply of the prover.
     * @return <code>true</code> if the reply is accepted and
     *         <code>false</code> otherwise.
     */
    public boolean verify(final ByteTreeReader btr) {

        final PRing ciphPRing = pkey.project(0).getPGroup().getPRing();

        final boolean parseValue =
            parseReplies(ciphPRing, btr);
        if (!parseValue) {
            return false;
        }

        final PGroupElement h0 = h.get(0);

        // Compute C and D.
        pC = u.prod().div(h.prod());
        pgeD = pgeaB.get(size - 1).div(h0.exp(e.prod()));

        final boolean verdictA =
            pA.expMul(v, pgeAp).equals(g.exp(kA).mul(h.expProd(kE)));

        final PGroupElementArray BExpV = pgeaB.exp(v);
        final PGroupElementArray leftSide = BExpV.mul(pgeBp);
        final PGroupElementArray gExpkB = g.exp(kB);
        final PGroupElementArray bShift = pgeaB.shiftPush(h0);
        final PGroupElementArray bShiftExpkE = bShift.exp(kE);
        final PGroupElementArray rightSide = gExpkB.mul(bShiftExpkE);

        final boolean verdictB = leftSide.equals(rightSide);

        BExpV.free();
        leftSide.free();
        gExpkB.free();
        bShift.free();
        bShiftExpkE.free();
        rightSide.free();

        // Verify that prover knows c=\sum r_i such that: C = \prod u_i / \prod h_i = g^c
        final boolean verdictC = pC.expMul(v, pgeCp).equals(g.exp(kC));


        // Verify that prover knows d such that: D = B_{N-1} / g^{\prod e_i} = g^d
        final boolean verdictD = pgeD.expMul(v, pgeDp).equals(g.exp(kD));


        final boolean verdictF =
            pgeF.expMul(v, pgeFp).equals(pkey.exp(kF.neg()).mul(wp.expProd(kE)));

        return verdictA && verdictB && verdictC && verdictD && verdictF;
    }

    /**
     * VERIFIER: Returns the reply that must already have been
     * processed.
     *
     * @return Reply processed by the verifier.
     */
    public ByteTreeBasic getReply() {
        return new ByteTreeContainer(kA.toByteTree(),
                                     kB.toByteTree(),
                                     kC.toByteTree(),
                                     kD.toByteTree(),
                                     kE.toByteTree(),
                                     kF.toByteTree());
    }

    /**
     * Explicitly free resources allocated by this instance. It is the
     * responsibility of the programmer to not call this method and
     * then later use the instance.
     */
    public void free() {

        PRingElementArray.free(r);
        PGroupElementArray.free(u);
        PRingElementArray.free(e);
        PRingElementArray.free(pB);
        PGroupElementArray.free(pgeaB);
        PGroupElementArray.free(pgeBp);
        PRingElementArray.free(ipe);
        PRingElementArray.free(beta);
        PRingElementArray.free(epsilon);
        PRingElementArray.free(kB);
        PRingElementArray.free(kE);
    }
}
