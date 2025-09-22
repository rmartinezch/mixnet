
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

package com.verificatum.protocol.mixnet;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.BiExp;
import com.verificatum.arithm.BiPRingPGroup;
import com.verificatum.arithm.HomPRingPGroup;
import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.arithm.PPGroupElementArray;
import com.verificatum.eio.ByteTree;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.ByteTreeReaderF;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.ExtIO;
import com.verificatum.eio.Hex;
import com.verificatum.protocol.Protocol;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.protocol.distr.IndependentGeneratorsRO;
import com.verificatum.protocol.elgamal.DistrElGamal;
import com.verificatum.protocol.elgamal.DistrElGamalSession;
import com.verificatum.protocol.elgamal.DistrElGamalSessionBasic;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.protocol.hvzk.CCPoSBasicW;
import com.verificatum.protocol.hvzk.CCPoSW;
import com.verificatum.protocol.hvzk.ChallengerRO;
import com.verificatum.protocol.hvzk.PoSBasicTW;
import com.verificatum.protocol.hvzk.PoSCBasicTW;
import com.verificatum.protocol.hvzk.PoSCTW;
import com.verificatum.protocol.hvzk.PoSTW;
import com.verificatum.protocol.secretsharing.PolynomialInExponent;
import com.verificatum.vcr.VCR;


/**
 * Used to verify a mixing, shuffling, or decryption session.
 *
 * @author Douglas Wikstrom
 */
public final class MixNetElGamalVerifyFiatShamirSession {
    private static final String DONE_MSG = "done.";
    private static final String DECRYPTION = "decryption";
    /**
     * Main verifier.
     */
    MixNetElGamalVerifyFiatShamir v;

    /**
     * Proof directory.
     */
    File nizkp;

    /**
     * Inner proof directory.
     */
    File proofs;

    /**
     * Type of proof.
     */
    String type;

    /**
     * Auxiliary session identifier.
     */
    String auxsid;

    /**
     * Width of input ciphertexts.
     */
    int width;

    /**
     * Full El Gamal public key.
     */
    PPGroupElement elGamalFullPKey;

    /**
     * El Gamal public keys of the mix-servers.
     */
    PGroupElement[] elGamalPKeys;

    /**
     * Global prefix used as input to random oracles and used to
     * derive independent generators.
     */
    byte[] globalPrefix;

    /**
     * Random oracle based challenger used in Fiat-Shamir proofs.
     */
    ChallengerRO challenger;

    /**
     * Independent generators used for proof of shuffle.
     */
    PGroupElementArray generators;

    /**
     * Polynomial in exponent which defines the public keys of the
     * mix-servers.
     */
    PolynomialInExponent polynomialInExponent;

    /**
     * Creates a verifier of a session stored in the given directory
     * with the given parent verifier.
     *
     * @param v Parent verifier.
     * @param nizkp Location of non-interactive proofs.
     */
    public MixNetElGamalVerifyFiatShamirSession(
                                      final MixNetElGamalVerifyFiatShamir v,
                                      final File nizkp) {

        this.v = v;
        this.nizkp = nizkp;
        this.proofs = new File(nizkp, "proofs");
    }

    /**
     * Set global prefix.
     */
    protected void setGlobalPrefix() {

        final String rosid = v.sid + "." + auxsid;

        v.checkPrintTestVector("par.sid", v.sid);

        final ByteTree versionBT =
            new ByteTree(ExtIO.getBytes(VCR.version()));
        final ByteTree rosidBT = new ByteTree(ExtIO.getBytes(rosid));
        final ByteTree rbitlenBT = ByteTree.intToByteTree(v.rbitlen);
        final ByteTree vbitlenroBT = ByteTree.intToByteTree(v.vbitlenro);
        final ByteTree ebitlenroBT = ByteTree.intToByteTree(v.ebitlenro);
        final ByteTree prgStringBT = new ByteTree(ExtIO.getBytes(v.prgString));
        final ByteTree pGroupStringBT =
            new ByteTree(ExtIO.getBytes(v.pGroupString));
        final ByteTree roHashfunctionStringBT =
            new ByteTree(ExtIO.getBytes(v.roHashfunctionString));

        final ByteTree bt =
            new ByteTree(versionBT,
                         rosidBT,
                         rbitlenBT,
                         vbitlenroBT,
                         ebitlenroBT,
                         prgStringBT,
                         pGroupStringBT,
                         roHashfunctionStringBT);

        globalPrefix = v.roHashfunction.hash(bt.toByteArray());

        v.checkPrintTestVector("der.rho", Hex.toHexString(globalPrefix));
    }

    /**
     * Read full El Gamal public key.
     */
    void readFullPKey() {

        v.print("Read joint public key... ");

        final File file = DistrElGamal.fpkFile(nizkp);

        if (!file.exists()) {
            v.failStop("Joint public key file " + file.toString()
                       + " can not be found!");
        }

        final PGroup ciphPGroup =
            ProtocolElGamal.getCiphPGroup(v.plainPGroup, 1);

        final ByteTreeReader btr = new ByteTreeReaderF(file);
        ArithmFormatException afe = null;
        try {

            elGamalFullPKey = (PPGroupElement) ciphPGroup.toElement(btr);

            v.checkPrintTestVector("bas.pk", elGamalFullPKey.toString());

        } catch (final ArithmFormatException afee) {
            afe = afee;
        } finally {
            btr.close();
        }

        if (afe != null) {
            v.failStop("Could not read full El Gamal public key from "
                       + "file! (" + file.toString() + ")");
        }

        // Verify joint public key.
        final PGroupElement basicPublicKey = elGamalFullPKey.project(0);
        if (!basicPublicKey.equals(v.plainPGroup.getg())) {
            v.failStop("Basic public key is not the standard generator!");
        }

        v.println(DONE_MSG);
    }

    /**
     * Read El Gamal public keys of the mix-servers.
     */
    void readMixServerPKeys() {

        v.print("Read polynomial in exponent... ");

        final File file = DistrElGamal.pieFile(proofs);

        final ByteTreeReaderF btr = new ByteTreeReaderF(file);

        final BiPRingPGroup bi = new BiExp(v.plainPGroup);
        final HomPRingPGroup hom = bi.restrict(v.plainPGroup.getg());

        try {
            polynomialInExponent =
                new PolynomialInExponent(hom, v.threshold - 1, btr);
        } catch (final ProtocolFormatException pfe) {
            v.failStop("Unable to read polynomial in exponent from file! ("
                       + file.toString() + ")");
        }
        v.println(DONE_MSG);

        btr.close();

        elGamalPKeys = new PGroupElement[v.k + 1];

        for (int l = 1; l <= v.k; l++) {
            elGamalPKeys[l] = polynomialInExponent.evaluate(l);
        }

        v.print("Verify relation between public keys... ");
        if (!elGamalFullPKey.project(1).
            equals(polynomialInExponent.getElement(0))) {

            v.failStop("Mismatching public keys!");
        }
        v.println(DONE_MSG);

        if (v.checkTestVector("bas.y_l")) {
            final StringBuilder sb =
                new StringBuilder("(" + elGamalPKeys[1].toString());
            for (int i = 2; i <= v.threshold; i++) {
                sb.append(',');
                sb.append(elGamalPKeys[i].toString());
            }
            sb.append(')');

            v.printTestVector("bas.y_l", sb.toString());
        }

    }

    /**
     * Verifies that the version of the package used to generate the
     * proof matches the version of this package.
     *
     * @param nizkp Proof directory.
     */
    void verifyVersion(final File nizkp) {
        // Version of proof.
        String version = null;
        v.print("Read version from file... ");
        try {

            version = ExtIO.readString(MixNetElGamalSession.getVFile(nizkp));

            if (!VCR.version().equals(version)) {
                v.failStop("Expected package version "
                           + VCR.version()
                           + " but the proof was created by a package "
                           + "with version " + version + "!");
            }

            v.checkPrintTestVector("par.version", version);

        } catch (final FileNotFoundException fnfe) {
            v.failStop("Can not find version file in proof directory!");
        } catch (final IOException ioe) {
            v.failStop("Can not read version from file!", ioe);
        }
        v.println(DONE_MSG);
    }

    /**
     * Reads proof type from the proof and if the expected type is not
     * null it verifies that the types match.
     *
     * @param expectedType Expected type or null if no type is expected.
     * @return Type of proof to verify.
     */
    String determineType(final String expectedType) {

        String actualType = null;
        v.print("Determine type of proof... ");

        // Read type from proof directory.
        try {

            actualType = ExtIO.readString(MixNetElGamalSession.getTFile(nizkp));

        } catch (final FileNotFoundException fnfe) {
            v.failStop("Can not find type file in proof directory!");
        } catch (final IOException ioe) {
            v.failStop("Can not read type from type file!", ioe);
        }

        // Check that the type is valid and matches the expected type.
        if (!(actualType.equals(MixNetElGamalSession.MIX_TYPE)
              || actualType.equals(MixNetElGamalSession.SHUFFLE_TYPE)
              || actualType.equals(MixNetElGamalSession.DECRYPT_TYPE))) {
            v.failStop("Unknown type of proof! (" + actualType + ")");
        }
        if (expectedType != null && !actualType.equals(expectedType)) {

            v.failStop("Attempting to verify proof of " + expectedType
                       + ", but proof is a proof of " + actualType + "!");
        }

        v.println(DONE_MSG);

        return actualType;
    }

    /**
     * Reads the auxiliary session identifier from the proof and if
     * the expected auxiliary session identifier is not null, then it
     * checks that they match.
     *
     * @param expectedAuxsid Expected auxiliary session identifier or
     * null if none in particular is expected.
     * @return Auxiliary session identifier.
     */
    String determineAuxsid(final String expectedAuxsid) {

        String actualAuxsid = null;
        v.print("Determine auxiliary session identifier... ");

        // Read auxiliary session identifier from proof directory.
        try {

            actualAuxsid = ExtIO.readString(MixNetElGamalSession.getAFile(nizkp));
            Protocol.validateSid(actualAuxsid);

        } catch (final FileNotFoundException fnfe) {
            v.failStop("Can not find auxsid file in proof directory!");
        } catch (final IOException ioe) {
            v.failStop("Can not read auxsid from file!", ioe);
        }

        // Check auxiliary session identifier.
        if (expectedAuxsid != null && !actualAuxsid.equals(expectedAuxsid)) {

            v.failStop("The given auxiliary session identifier does "
                       + "not match the one in the proof!");
        }

        v.println(DONE_MSG);

        return actualAuxsid;
    }

    /**
     * Reads the width from the proof. If the expected width is
     * negative, then the width read from the proof is returned. If
     * the expected width is zero, then the width is matched against
     * the default width in the protocol info. If the expected width
     * is positive, then it is matched against the width.
     *
     * @param expectedWidth Expected width or zero none in particular
     * is expected.
     * @return Width of ciphertexts.
     */
    int determineWidth(final int expectedWidth) {

        int actualWidth = 0;

        v.print("Determine width of ciphertexts... ");

        // Read width of ciphertexts from proof.
        try {

            final String widthString =
                ExtIO.readString(MixNetElGamalSession.getWFile(nizkp));
            actualWidth = Integer.parseInt(widthString);

        } catch (final FileNotFoundException fnfe) {
            v.failStop("Can not find width file in proof directory!");
        } catch (final IOException ioe) {
            v.failStop("Can not read width from file!", ioe);
        } catch (final NumberFormatException nfe) {
            v.failStop("Can not parse width given in file!", nfe);
        }

        // Check the width.
        if (expectedWidth > 0) {

            if (actualWidth != expectedWidth) {

                v.failStop("The given width does not match the width in the "
                           + "proof!");
            }

        } else if (expectedWidth == 0
                   && actualWidth != v.defaultWidth) {

            v.failStop("The width in proof does not match the width in "
                       + "the protocol info file! Use the \"-width\" "
                       + "option to specify the width for which "
                       + "verification is performed.");
        }

        if (actualWidth <= 0) {
            v.failStop("Width is not positive!");
        }

        v.println(DONE_MSG);

        v.checkPrintTestVector("par.omega", actualWidth);

        return actualWidth;
    }

    /**
     * Reads the active threshold for the proof.
     *
     * @param threshold Threshold of mix-servers needed to decrypt.
     * @return Threshold of active mix-servers.
     */
    int determineActiveThreshold(final int threshold) {

        v.print("Determine active threshold of ciphertexts... ");

        // Read width of ciphertexts from proof.
        int activeThreshold = 0;
        try {

            final String activeThresholdString =
                ExtIO.readString(ShufflerElGamalSession.atFile(proofs));
            activeThreshold = Integer.parseInt(activeThresholdString);

        } catch (final FileNotFoundException fnfe) {
            v.failStop("Can not find active threshold file in proof "
                       + "directory!");
        } catch (final IOException ioe) {
            v.failStop("Can not read active threshold from file!", ioe);
        } catch (final NumberFormatException nfe) {
            v.failStop("Can not parse active threshold given in file!", nfe);
        }

        // Check the width.
        if (activeThreshold > v.k) {

            v.failStop("Active threshold is larger than the number of "
                       + "mix-servers!");
        }
        if (activeThreshold < v.threshold) {

            v.failStop("Active threshold is smaller than threshold!");
        }
        v.println(DONE_MSG);

        v.checkPrintTestVector("par.lambda", activeThreshold);

        return activeThreshold;
    }

    /**
     * Read number of ciphertexts for which pre-computation is performed.
     *
     * @return Maximal number of ciphertexts for which pre-computation
     * is performed.
     */
    int readMaxciph() {

        final File maxciphFile = ShufflerElGamalSession.mcFile(proofs);

        try {

            final String maxciphString = ExtIO.readString(maxciphFile);
            final int maxciph = Integer.parseInt(maxciphString);

            v.checkPrintTestVector("par.N_0", maxciph);

            return maxciph;

        } catch (final FileNotFoundException fnfe) {
            v.failStop("Can not find maxciph file in proof directory!");
        } catch (final IOException ioe) {
            v.failStop("Can not read from maxciph file!", ioe);
        } catch (final NumberFormatException nfe) {
            v.failStop("Can not parse maxciph file!", nfe);
        }
        return 0; // Compiler complains without this.
    }

    /**
     * Determines the maximal number of ciphertexts. If no
     * precomputation was performed, then this is simply the number of
     * input ciphertexts.
     *
     * @param ciphertexts Input ciphertexts.
     * @param precomp Indicates if precomputation was performed or not.
     * @return Maximal number of ciphertexts.
     */
    private int getMaxciph(final boolean precomp,
                           final PGroupElementArray ciphertexts) {
        if (precomp) {
            return readMaxciph();
        } else {
            return ciphertexts.size();
        }
    }

    /**
     * Derives independent generators for the given auxiliary session
     * identifier.
     *
     * @param maxciph Number of generators that are generated.
     */
    void deriveGenerators(final int maxciph) {
        if (generators == null) {

            v.print("Derive independent generators... ");
            final IndependentGeneratorsRO igRO =
                new IndependentGeneratorsRO("generators",
                                            v.roHashfunction,
                                            globalPrefix,
                                            v.rbitlen);
            generators = igRO.generate(null, v.pGroup, maxciph);
            v.println(DONE_MSG);

            v.checkPrintTestVector("bas.h", generators);

        } else {

            if (maxciph > generators.size()) {
                v.failStop("Too few generators have been derived!");
            }
        }
    }

    /**
     * Returns the array stored in the given file.
     *
     * @param size Expected size of the array, or zero if the size
     * should be derived.
     * @param pGroup Group to which the elements in the file should
     * belong.
     * @param arrayFile File containing the array.
     * @return Read array of group elements.
     */
    PGroupElementArray readArray(final int size,
                                 final PGroup pGroup,
                                 final File arrayFile) {

        if (!arrayFile.exists()) {
            v.failStop("Can not find array file! ("
                       + arrayFile.toString() + ")");
        }

        PGroupElementArray array = null;
        final ByteTreeReaderF btr = new ByteTreeReaderF(arrayFile);
        ArithmFormatException afe = null;
        try {

            array = pGroup.toElementArray(size, btr);

        } catch (final ArithmFormatException afee) {
            afe = afee;
        } finally {
            btr.close();
        }

        if (afe != null) {
            v.failStop("Unable to read array "
                       + arrayFile.getName() + "!", afe);
        }

        return array;
    }

    /**
     * Returns the permutation commitment of the mix-server of the
     * given index.
     *
     * @param size Expected size of permutation commitment.
     * @param l Index of party that produced the commitment.
     * @return Read permutation commitment.
     */
    PGroupElementArray readPermutationCommitment(final int size, final int l) {

        v.print("Read permutation commitment... ");

        final File file = PermutationCommitment.pcFile(proofs, l);
        if (!file.exists()) {
            v.failStop("Can not find permutation commitment! ("
                       + file.toString() + ")");
        }
        final PGroupElementArray permutationCommitment =
            readArray(size, v.pGroup, file);

        v.println(DONE_MSG);

        return permutationCommitment;
    }

    /**
     * Verifies the proof of a shuffle of commitments.
     *
     * @param l Index of mix-server that produced the permutation
     * commitment.
     * @param permutationCommitment Permutation commitment.
     * @return True or false depending on if the proof is valid or
     * not.
     */
    boolean verifyPoSC(final int l,
                       final PGroupElementArray permutationCommitment) {

        // Initialize proof.
        final PoSCBasicTW poSCBasicTW =
            new PoSCBasicTW(v.vbitlenro, v.ebitlenro, v.rbitlen, v.prg,
                            null);
        final PGroupElement g = v.pGroup.getg();
        poSCBasicTW.setInstance(g, generators, permutationCommitment);

        // Generate and set batching vector.
        ByteTreeContainer challengeData =
            new ByteTreeContainer(g.toByteTree(),
                                  generators.toByteTree(),
                                  permutationCommitment.toByteTree());
        final byte[] prgSeed = challenger.challenge(challengeData,
                                                    8 * v.prg.minNoSeedBytes(),
                                                    v.rbitlen);

        v.checkPrintTestVector("PoSC.s", Hex.toHexString(prgSeed));

        poSCBasicTW.setBatchVector(prgSeed);

        // Read commitment.
        File file = PoSCTW.poSCCFile(proofs, l);
        final ByteTreeReader commitmentReader = new ByteTreeReaderF(file);
        final ByteTreeBasic commitment = poSCBasicTW.setCommitment(commitmentReader);
        commitmentReader.close();

        // Generate a challenge.
        challengeData =
            new ByteTreeContainer(new ByteTree(prgSeed), commitment);
        final byte[] challengeBytes =
            challenger.challenge(challengeData, v.vbitlenro, v.rbitlen);
        final LargeInteger integerChallenge =
            LargeInteger.toPositive(challengeBytes);

        v.checkPrintTestVector("PoSC.v", integerChallenge.toString());

        // Set the commitment and challenge.
        poSCBasicTW.setChallenge(integerChallenge);

        // Read and verify reply.
        file = PoSCTW.poSCRFile(proofs, l);
        final ByteTreeReader replyReader = new ByteTreeReaderF(file);
        final boolean verdict = poSCBasicTW.verify(replyReader);
        replyReader.close();

        poSCBasicTW.free();

        return verdict;
    }

    /**
     * Shrinks the given permutation commitment of the party with the
     * given index to the new size.
     *
     * @param l Index of prover.
     * @param permComm Permutation commitment.
     * @param newSize New size of permutation commitment.
     * @return Shrunk permutation commitments.
     */
    PGroupElementArray shrinkPermComm(final int l,
                                      final PGroupElementArray permComm,
                                      final int newSize) {
        try {

            final File file = PermutationCommitment.kLfile(proofs, l);

            final ByteTreeReader btr = new ByteTreeReaderF(file);
            final boolean[] keepList = btr.readBooleans(permComm.size());
            btr.close();

            int total = 0;
            for (int i = 0; i < keepList.length; i++) {
                if (keepList[i]) {
                    total++;
                }
            }
            if (total != newSize) {
                v.failStop("Wrong number of true elements in keep list of "
                           + "Party " + l + "!");
                return null;
            }

            return permComm.extract(keepList);

        } catch (final EIOException eioe) {

            v.failStop("Unable to open keeplist of Party " + l + "!");
            return null;
        }
    }

    /**
     * Verifies the commitment-consistent proof of a shuffle.
     *
     * @param l Index of mix-server that produced the output.
     * @param shrunkGenerators Generators.
     * @param shrunkPermutationCommitment Permutation commitment.
     * @param input Input ciphertexts.
     * @param output Output ciphertexts.
     * @return True or false depending on if the proof is valid or
     * not.
     */
    boolean verifyCCPoS(final int l,
                        final PGroupElementArray shrunkGenerators,
                        final PGroupElementArray shrunkPermutationCommitment,
                        final PGroupElementArray input,
                        final PGroupElementArray output) {

        final PGroupElement wideElGamalFullPKey =
            ProtocolElGamal.getWidePublicKey(elGamalFullPKey, width);

        // Initialize proof.
        final CCPoSBasicW ccPoSBasicW =
            new CCPoSBasicW(v.vbitlenro, v.ebitlenro, v.rbitlen, v.prg);
        final PGroupElement g = v.pGroup.getg();
        ccPoSBasicW.setInstance(g,
                      shrunkGenerators,
                      shrunkPermutationCommitment,
                      wideElGamalFullPKey,
                      input,
                      output);

        // Generate and set batching vector.
        ByteTreeContainer challengeData =
            new ByteTreeContainer(g.toByteTree(),
                                  shrunkGenerators.toByteTree(),
                                  shrunkPermutationCommitment.toByteTree(),
                                  wideElGamalFullPKey.toByteTree(),
                                  input.toByteTree(),
                                  output.toByteTree());
        final byte[] prgSeed = challenger.challenge(null,
                                                    challengeData,
                                                    8 * v.prg.minNoSeedBytes(),
                                                    v.rbitlen);

        v.checkPrintTestVector("CCPoS.s", Hex.toHexString(prgSeed));

        ccPoSBasicW.setBatchVector(prgSeed);

        // Compute A and B.
        ccPoSBasicW.computeAB(null);

        // Read commitment.
        File file = CCPoSW.ccPoSCFile(proofs, l);

        final ByteTreeReader commitmentReader = new ByteTreeReaderF(file);
        final ByteTreeBasic commitment = ccPoSBasicW.setCommitment(commitmentReader);
        commitmentReader.close();


        // Generate a challenge.
        challengeData =
            new ByteTreeContainer(new ByteTree(prgSeed), commitment);
        final byte[] challengeBytes = challenger.challenge(null,
                                                           challengeData,
                                                           v.vbitlenro,
                                                           v.rbitlen);
        final LargeInteger integerChallenge =
            LargeInteger.toPositive(challengeBytes);

        v.checkPrintTestVector("CCPoS.v", integerChallenge.toString());

        // Set the commitment and challenge.
        ccPoSBasicW.setChallenge(integerChallenge);


        // Read and verify reply.
        file = CCPoSW.ccPoSRFile(proofs, l);
        final ByteTreeReader replyReader = new ByteTreeReaderF(file);
        final boolean verdict = ccPoSBasicW.verify(replyReader, null, null);
        replyReader.close();

        ccPoSBasicW.free();

        return verdict;
    }

    /**
     * Verify proof of a shuffle.
     *
     * @param l Index of prover.
     * @param g Standard generator.
     * @param generators Independent generators.
     * @param input Input list of ciphertexts.
     * @param output Output list of ciphertexts.
     * @return True or false depending on if the proof is valid or
     * not.
     */
    boolean verifyPoS(final int l,
                      final PGroupElement g,
                      final PGroupElementArray generators,
                      final PGroupElementArray input,
                      final PGroupElementArray output) {

        final PGroupElement wideElGamalFullPKey =
            ProtocolElGamal.getWidePublicKey(elGamalFullPKey, width);

        final PoSBasicTW poSBasicTW = new PoSBasicTW(v.vbitlenro,
                                            v.ebitlenro,
                                            v.rbitlen,
                                            v.prg,
                                            null);
        poSBasicTW.precompute(g, generators);
        poSBasicTW.setInstance(wideElGamalFullPKey, input, output);

        // Read and set the permutation commitment of the prover.
        File file = PoSTW.pcfile(proofs, l);
        final ByteTreeReader permutationCommitmentReader =
            new ByteTreeReaderF(file);
        poSBasicTW.setPermutationCommitment(permutationCommitmentReader);
        permutationCommitmentReader.close();

        // Generate a seed to the PRG for batching.
        ByteTreeContainer challengeData =
            new ByteTreeContainer(g.toByteTree(),
                                  generators.toByteTree(),
                                  poSBasicTW.getPermutationCommitment().toByteTree(),
                                  wideElGamalFullPKey.toByteTree(),
                                  input.toByteTree(),
                                  output.toByteTree());
        final byte[] prgSeed = challenger.challenge(null,
                                                    challengeData,
                                                    8 * v.prg.minNoSeedBytes(),
                                                    v.rbitlen);

        v.checkPrintTestVector("PoS.s", Hex.toHexString(prgSeed));

        poSBasicTW.setBatchVector(prgSeed);

        // Compute A and F.
        poSBasicTW.computeAF();

        v.checkPrintTestVector("PoS.A", poSBasicTW.getA().toString());
        v.checkPrintTestVector("PoS.F", poSBasicTW.getF().toString());

        // Read and set the commitment of the prover.
        file = PoSTW.poSCFile(proofs, l);
        final ByteTreeReader commitmentReader = new ByteTreeReaderF(file);
        final ByteTreeBasic commitment = poSBasicTW.setCommitment(commitmentReader);
        commitmentReader.close();

        v.checkPrintTestVector("PoS.B", poSBasicTW.getB());
        v.checkPrintTestVector("PoS.Ap", poSBasicTW.getAp().toString());
        v.checkPrintTestVector("PoS.Bp", poSBasicTW.getBp());
        v.checkPrintTestVector("PoS.Cp", poSBasicTW.getCp().toString());
        v.checkPrintTestVector("PoS.Dp", poSBasicTW.getDp().toString());
        v.checkPrintTestVector("PoS.Fp", poSBasicTW.getFp().toString());

        // Generate a challenge
        challengeData =
            new ByteTreeContainer(new ByteTree(prgSeed), commitment);
        final byte[] challengeBytes = challenger.challenge(null,
                                                           challengeData,
                                                           v.vbitlenro,
                                                           v.rbitlen);
        final LargeInteger integerChallenge =
            LargeInteger.toPositive(challengeBytes);

        v.checkPrintTestVector("PoS.v", integerChallenge.toString());

        // Set the commitment and challenge.
        poSBasicTW.setChallenge(integerChallenge);

        // Read and verify reply.
        file = PoSTW.poSRFile(proofs, l);
        final ByteTreeReader replyReader = new ByteTreeReaderF(file);

        final boolean verdict = poSBasicTW.verify(replyReader);
        replyReader.close();

        v.checkPrintTestVector("PoS.C", poSBasicTW.getC().toString());
        v.checkPrintTestVector("PoS.D", poSBasicTW.getD().toString());

        v.checkPrintTestVector("PoS.k_A", poSBasicTW.getkA().toString());
        v.checkPrintTestVector("PoS.k_B", poSBasicTW.getkB());
        v.checkPrintTestVector("PoS.k_C", poSBasicTW.getkC().toString());
        v.checkPrintTestVector("PoS.k_D", poSBasicTW.getkD().toString());
        v.checkPrintTestVector("PoS.k_F", poSBasicTW.getkF().toString());

        poSBasicTW.free();

        return verdict;
    }

    /**
     * Returns true if and only if the proof of a shuffle was using
     * pre-computation.
     *
     * @return True if and only if the proof of a shuffle was using
     * pre-computation.
     */
    public boolean precomp() {
        return ShufflerElGamalSession.mcFile(proofs).exists();
    }

    /**
     * Returns true if and only if the party with the given index was
     * active during the pre-computation.
     *
     * @param l Index of party.
     * @return True if and only if the party with the given index was
     * active during the pre-computation.
     */
    public boolean getPoSCActive(final int l) {

        final File file = PermutationCommitment.pcFile(proofs, l);
        return file.exists();
    }

    /**
     * Returns true if and only if the party with the given index was
     * active during the shuffling.
     *
     * @param l Index of party.
     * @return True if and only if the party with the given index was
     * active during the shuffling.
     */
    public boolean getCCPoSActive(final int l) {

        return CCPoSW.ccPoSCFile(proofs, l).exists()
            || PoSTW.poSCFile(proofs, l).exists();
    }

    /**
     * Determine actual session parameters.
     *
     * @param expectedParams Expected nominal session parameters.
     * @return Expected nominal session parameters.
     */
    private SessionParams
        determineSessionParams(final SessionParams expectedParams) {

        final String stype = determineType(expectedParams.type);
        final String sauxsid = determineAuxsid(expectedParams.auxsid);
        int iwidth = expectedParams.width;

        boolean dec = expectedParams.dec;
        boolean posc = expectedParams.posc;
        boolean ccpos = expectedParams.ccpos;
        if ("shuffling".equals(stype)) {
            dec = false;
        } else if (DECRYPTION.equals(stype)) {
            posc = false;
            ccpos = false;
        }

        if (ccpos || dec) {
            iwidth = determineWidth(expectedParams.width);
        }

        return new SessionParams(stype, sauxsid, iwidth, dec, posc, ccpos);
    }

    /**
     * Reads the input ciphertexts.
     *
     * @param sp Session parameters.
     * @param type Type of proof.
     * @param ciphPGroup Group to which the ciphertexts belong.
     * @param activeThreshold Active threshold used during the shuffling.
     * @return Input ciphertexts.
     */
    private PGroupElementArray readCiphertexts(final SessionParams sp,
                                               final String type,
                                               final PGroup ciphPGroup,
                                               final int activeThreshold) {
        PGroupElementArray ciphertexts = null;

        if (sp.ccpos || DECRYPTION.equals(type)) {

            // Read the original ciphertexts.
            final File file = MixNetElGamalSession.getLFile(nizkp);
            ciphertexts = readArray(0, ciphPGroup, file);

        } else {

            // If we are verifying decryption and not the shuffling,
            // but there was shuffling, then we need to start from the
            // end of the shuffling when verifying the decryption.
            final File file =
                ShufflerElGamalSession.lFile(proofs, activeThreshold);

            if (file.exists()) {
                ciphertexts = readArray(0, ciphPGroup, file);
            }
        }

        if (ciphertexts != null) {
            v.checkPrintTestVector("bas.L_0", ciphertexts);
        }
        return ciphertexts;
    }

    /**
     * If precomputation was performed and a commitment-consistent
     * proof of a shuffle is verified, then it returns a list of
     * independent generators shrunk to the actual number of
     * ciphertexts, and otherwise it returns null.
     *
     * @param sp Session parameters.
     * @param precomp Indicates if precomputation was performed or not.
     * @param ciphertexts Input ciphertexts.
     * @return Shrunk list of generators.
     */
    private PGroupElementArray
        getShrunkGenerators(final SessionParams sp,
                            final boolean precomp,
                            final PGroupElementArray ciphertexts) {
        if (sp.ccpos && precomp) {
            return generators.copyOfRange(0, ciphertexts.size());
        } else {
            return null;
        }
    }

    /**
     * Frees resources allocated by the array of independent
     * generators and the shrunk array of independent generators.
     *
     * @param generators Independent generators
     * @param shrunkGenerators Shrunk independent generators.
     */
    void freeGenerators(final PGroupElementArray generators,
                        final PGroupElementArray shrunkGenerators) {

        if (generators != null) {
            generators.free();
        }

        if (shrunkGenerators != null) {
            shrunkGenerators.free();
        }
    }

    /**
     * Read the arrays of decryption factors.
     *
     * @param ciphertexts Ciphertext with which the decryption factors
     * must be compatible.
     * @return Arrays of decryption factors deemed to be correct so
     * far.
     */
    PGroupElementArray[]
        getDecryptionFactors(final PGroupElementArray ciphertexts) {

        final PPGroup ciphPGroup = (PPGroup) ciphertexts.getPGroup();

        final PGroupElementArray[] decryptionFactors =
            new PGroupElementArray[v.k + 1];

        v.print("Read decryption factors... ");
        for (int l = 1; l <= v.k; l++) {
            final File dffile = DistrElGamalSession.dfFile(proofs, l);
            decryptionFactors[l] = readArray(ciphertexts.size(),
                                             ciphPGroup.project(0),
                                             dffile);
        }
        v.println(DONE_MSG);
        return decryptionFactors;
    }

    /**
     * Creates a byte tree of an array of arrays of decryption factors.
     *
     * @param decryptionFactors Decryption factors to be converted.
     * @return Byte tree of the input arrays of decryption factors.
     */
    ByteTreeBasic
        getDecryptionFactorsBT(final PGroupElementArray[] decryptionFactors) {

        final ByteTreeBasic[] decryptionFactorsBT = new ByteTreeBasic[v.k];
        for (int i = 0; i < v.k; i++) {
            decryptionFactorsBT[i] = decryptionFactors[i + 1].toByteTree();
        }
        return new ByteTreeContainer(decryptionFactorsBT);
    }

    /**
     * Returns the list of indices for which the decryption factors
     * are claimed to be correct.
     *
     * @return List of indices for which the decryption factors are
     * claimed to be correct.
     */
    boolean[] getIndicesOfCorrectDecryptionFactors() {

        final File crfile = DistrElGamalSession.crFile(proofs);
        boolean[] correct = null;
        try {
            correct = ByteTree.byteTreeToBooleanArray(new ByteTree(crfile));
        } catch (final IOException | EIOException ioe) {
            v.failStop("Failed to read indices of correct decryption factors!");
        }
        v.println(DONE_MSG);
        return correct;
    }

    /**
     * Verifies that the list of indices for which the data are
     * claimed to be correct contains at least as many indices as the
     * threshold number of parties needed to decrypt.
     *
     * @param correct Indices of decryption factors claimed to be
     * correct.
     * @return Number of correct indices.
     */
    int sanityCheckCorrect(final boolean[] correct) {
        int count = 0;
        for (int l = 1; l <= v.k; l++) {
            if (correct[l]) {
                count++;
            }
        }
        if (count < v.threshold) {
            v.failStop("Too few correct decryption factors!");
        }
        return count;
    }

    /**
     * Reads the commitments for proofs of correct decryption into the
     * underlying implementation of the proof verifier.
     *
     * @param basic Underlying implementation of proof verifier.
     */
    void readCommitments(final DistrElGamalSessionBasic basic) {
        for (int l = 1; l <= v.k; l++) {

            final File file = DistrElGamalSession.dfcFile(proofs, l);
            final ByteTreeReader btr = new ByteTreeReaderF(file);
            basic.setCommitment(l, btr);
            btr.close();
        }
    }

    /**
     * Read replies of all parties.
     *
     * @param basic Underlying implementation of the decryption
     * protocol.
     */
    void readReplies(final DistrElGamalSessionBasic basic) {
        for (int l = 1; l <= v.k; l++) {

            final File file = DistrElGamalSession.dfrFile(proofs, l);
            final ByteTreeReader btr = new ByteTreeReaderF(file);
            basic.setReply(l, btr);
            btr.close();
        }
    }

    /**
     * Verifies the combined proof of decryption.
     *
     * @param basic Underlying implementation of the decryption
     * protocol.
     * @param integerChallenge Challenge in zero-knowledge proofs.
     */
    void verifyCombined(final DistrElGamalSessionBasic basic,
                        final LargeInteger integerChallenge) {

        v.print("Verify combined proof of decryption... ");
        if (basic.verifyCombined(integerChallenge)) {

            v.println(DONE_MSG);

        } else {

            v.failStop("failed!");

        }
    }

    /**
     * Free resources allocated by the input arrays of elements.
     *
     * @param decryptionFactors Decryption factors of all parties.
     */
    void freeDecryptionFactors(final PGroupElementArray[] decryptionFactors) {
        for (int l = 1; l <= v.k; l++) {
            decryptionFactors[l].free();
        }
    }

    /**
     * Verify that the plaintexts are identical to the computed
     * plaintexts.
     *
     * @param plaintextElements Plaintext elements.
     * @param cPlaintextElements Plaintext elements computed
     * from the ciphertexts and decryption factors.
     */
    void matchComputedPlaintexts(final PGroupElementArray plaintextElements,
                                 final PGroupElementArray cPlaintextElements) {

        v.print("Match computed plaintexts with plaintexts... ");
        if (!plaintextElements.equals(cPlaintextElements)) {
            v.failStop("Plaintexts are incorrect!");
        }
        v.println(DONE_MSG);
    }

    /**
     * Compute plaintexts from the ciphertexts and the combined
     * decryption factors.
     *
     * @param ciphertexts Decrypted ciphertexts.
     * @param combinedDecryptionFactors Combined decryption factors.
     * @return Computed plaintexts.
     */
    PGroupElementArray
        computePlaintexts(final PGroupElementArray ciphertexts,
                          final PGroupElementArray combinedDecryptionFactors) {
        v.print("Compute plaintexts... ");
        final PGroupElementArray computedPlaintextElements =
            ((PPGroupElementArray) ciphertexts).project(1).
            mul(combinedDecryptionFactors);
        v.println(DONE_MSG);
        return computedPlaintextElements;
    }


    /**
     * Reads plaintexts from file.
     *
     * @param computedPlaintextElements Plaintexts computed from the
     * ciphertexts and the decryption factors.
     * @return Plaintexts read from file.
     */
     PGroupElementArray
        readPlaintexts(final PGroupElementArray computedPlaintextElements) {

        v.print("Read plaintexts... ");
        final File file = MixNetElGamalSession.getPFile(nizkp);
        final PGroupElementArray plaintextElements =
            readArray(computedPlaintextElements.size(),
                      computedPlaintextElements.getPGroup(),
                      file);
        v.println(DONE_MSG);
        return plaintextElements;
    }

    /**
     * Verify a proof. First derive type and auxiliary session
     * identifier. Then derive width and read keys and instantiate the
     * challenger. Finally, verify the proof. If the expected type is
     * null, then the type read from the proof is simply used and
     * otherwise it is verified that the expected type matches the
     * actual type. If the expected auxiliary session identifier is
     * null, then the auxiliary session identifier of the proof is
     * used, and otherwise the two are verified to be identical. If
     * the expected width is negative then the width of the proof is
     * used. If the expected width is zero, then the width of the
     * proof is checked to be equal to the default width of the
     * protocol info. Finally, if the expected width is positive it is
     * verified to be equal to the width in the proof.
     *
     * @param expectedParams Expected params.
     */
    @SuppressWarnings({"PMD.CyclomaticComplexity",
                       "PMD.NcssMethodCount"})
    void verify(final SessionParams expectedParams) {

        v.printHeader("Prepare to verify proof.");

        v.checkPrintTestVector("par.k", v.k);
        v.checkPrintTestVector("par.lambda", v.threshold);

        v.checkPrintTestVector("par.n_e", v.ebitlenro);
        v.checkPrintTestVector("par.n_r", v.rbitlen);
        v.checkPrintTestVector("par.n_v", v.vbitlenro);

        v.checkPrintTestVector("par.s_PRG", v.prgString);
        v.checkPrintTestVector("par.s_Gq", v.pGroupString);
        v.checkPrintTestVector("par.s_H", v.roHashfunctionString);

        // Verify that the version used to produce the proof is
        // compatible with the version of this package.
        verifyVersion(nizkp);

        // Determine session parameters.
        final SessionParams sp = determineSessionParams(expectedParams);
        type = sp.type;
        auxsid = sp.auxsid;
        width = sp.width;

        // Read public keys.
        readFullPKey();

        if (sp.dec) {
            readMixServerPKeys();
        }

        // Set up challenger.
        setGlobalPrefix();
        challenger = new ChallengerRO(v.roHashfunction, globalPrefix);


        final boolean precomp = precomp();

        int activeThreshold = determineActiveThreshold(v.threshold);
        if (DECRYPTION.equals(sp.type)) {
            activeThreshold = determineActiveThreshold(v.threshold);
        }

        // Read input ciphertexts.
        PPGroup ciphPGroup = null;
        PGroupElementArray ciphertexts = null;
        if (sp.ccpos || sp.dec) {

            ciphPGroup = ProtocolElGamal.getCiphPGroup(v.plainPGroup, width);

            v.checkPrintTestVector("bas.C_omega", ciphPGroup.toString());
            v.checkPrintTestVector("bas.R_omega",
                                   ciphPGroup.project(0).getPRing().toString());
            v.checkPrintTestVector("bas.M_omega",
                                   ciphPGroup.project(0).toString());

            ciphertexts =
                readCiphertexts(sp, type, ciphPGroup, activeThreshold);
        }

        if (sp.posc || sp.ccpos) {

            // Maximal number of ciphertexts.
            final int maxciph = getMaxciph(precomp, ciphertexts);

            // Derive independent generators.
            deriveGenerators(maxciph);

            // Extract shrunk generators.
            final PGroupElementArray shrunkGenerators =
                getShrunkGenerators(sp, precomp, ciphertexts);


            PGroupElementArray input = ciphertexts;

            int validProofs = 0;

            // Verify the shuffles.
            for (int l = 1; l <= activeThreshold; l++) {

                boolean verdict = true;

                if (sp.posc && precomp && !sp.ccpos && getPoSCActive(l)
                    || getCCPoSActive(l)) {

                    v.printHeader("Verify shuffle of Party " + l + ".");

                    v.checkPrintTestShuffleBegin("PoS", l);

                    PGroupElementArray permutationCommitment = null;

                    // Read permutation commitment.
                    permutationCommitment =
                        readPermutationCommitment(maxciph, l);

                    v.checkPrintTestVector("u", permutationCommitment);

                    if (sp.posc && precomp) {

                        // Verify proof of a shuffle for permutation
                        // commitment and set it to the array of
                        // generators if it fails.
                        v.print("Verify proof of shuffle of commitments... ");
                        if (verifyPoSC(l, permutationCommitment)) {

                            v.println(DONE_MSG);

                        } else {

                            verdict = false;

                            v.println("failed.");
                            v.failInfo("Setting permutation commitment to "
                                       + "list of generators.");
                            permutationCommitment.free();
                            permutationCommitment =
                                generators.copyOfRange(0, generators.size());
                        }
                    }


                    // Read output list.
                    PGroupElementArray output = null;
                    if (sp.ccpos) {

                        v.print("Read output of Party " + l + "... ");

                        File file = ShufflerElGamalSession.lFile(proofs, l);
                        if (l == activeThreshold && !file.exists()) {
                            file = MixNetElGamalSession.getLSFile(nizkp);
                        }

                        output = readArray(input.size(), ciphPGroup, file);

                        v.checkPrintTestVector("bas.L_l", l, output);

                        v.println(DONE_MSG);

                        if (precomp) {

                            // Shrink commitment.
                            v.print("Shrink permutation commitment... ");
                            final PGroupElementArray shrunkPermComm =
                                shrinkPermComm(l,
                                               permutationCommitment,
                                               shrunkGenerators.size());
                            permutationCommitment.free();
                            v.println(DONE_MSG);

                            // Verify commitment consistent proof of shuffle.
                            v.print("Verify commitment-consistent proof of "
                                    + "shuffle... ");
                            verdict &= verifyCCPoS(l,
                                                   shrunkGenerators,
                                                   shrunkPermComm,
                                                   input,
                                                   output);

                            shrunkPermComm.free();

                        } else {

                            v.print("Verify proof of shuffle... ");
                            verdict = verifyPoS(l,
                                                v.pGroup.getg(),
                                                generators,
                                                input,
                                                output);
                            permutationCommitment.free();
                        }

                        if (verdict) {

                            v.println(DONE_MSG);

                        } else {

                            v.println("failed.");
                            v.failInfo("Replacing output of Party "
                                       + l + " by its input.");
                            final PGroupElementArray tmp = output;
                            output = input.copyOfRange(0, input.size());
                            tmp.free();
                        }

                        // Free resources.
                        final PGroupElementArray tmp = input;
                        input = output;
                        tmp.free();
                    }

                    if (verdict) {
                        validProofs++;
                    }
                }

                if (v.checkTestVector("PoS")) {
                    v.printTestShuffleEnd(l);
                }
            }

            // Free resources.
            freeGenerators(generators, shrunkGenerators);

            if (sp.dec) {
                ciphertexts = input;
            } else {
                if (input != null) {
                    input.free();
                }
            }

            if (validProofs < v.threshold) {

                v.failInfo("Too few proofs are valid! (" + validProofs + ")");
            }
        }

        if (sp.dec) {

            // A public El Gamal key is a pair of group elements where
            // the second is a power of the first. We extract the
            // second.
            final PGroupElement publicKey =
                ((PPGroupElement) elGamalFullPKey).project(1);

            v.printHeader("Verify decryption.");

            final DistrElGamalSessionBasic basic =
                new DistrElGamalSessionBasic(0,
                                             v.k,
                                             v.threshold,
                                             v.ebitlenro,
                                             v.rbitlen,
                                             v.prg);

            // Read the indices of correct decryption factors.
            v.print("Read indices of correct decryption factors... ");
            final boolean[] correct = getIndicesOfCorrectDecryptionFactors();
            sanityCheckCorrect(correct);

            // Read the decryption factors of all parties.
            final PGroupElementArray[] decryptionFactors =
                getDecryptionFactors(ciphertexts);

            // Initialize decryption factors.
            final PGroupElementArray leftComponents =
                ((PPGroupElementArray) ciphertexts).project(0);

            v.print("Combine indicated decryption factors... ");
            final PGroupElementArray combinedDecryptionFactors =
                DistrElGamalSessionBasic.
                combineDecryptionFactors(decryptionFactors,
                                         correct,
                                         v.k,
                                         v.threshold);
            v.println(DONE_MSG);

            basic.setInstance(v.plainPGroup.getg(),
                              leftComponents,
                              elGamalPKeys,
                              decryptionFactors,
                              null,
                              publicKey,
                              combinedDecryptionFactors);

            // Build byte tree of all inputs.
            final ByteTreeBasic btIn =
                new ByteTreeContainer(v.plainPGroup.getg().toByteTree(),
                                      ciphertexts.toByteTree());

            // Turn public keys into a byte tree.
            final ByteTreeBasic pkBT = polynomialInExponent.toByteTree();

            // Turn decryption factors into a byte tree.
            final ByteTreeBasic dfBT =
                getDecryptionFactorsBT(decryptionFactors);

            // Build byte tree of all outputs.
            final ByteTreeBasic btOut = new ByteTreeContainer(pkBT, dfBT);

            // Build input to challenger.
            final ByteTreeBasic seedData = new ByteTreeContainer(btIn, btOut);

            // Generate a seed.
            final byte[] prgSeed =
                challenger.challenge(seedData,
                                     8 * v.prg.minNoSeedBytes(),
                                     v.rbitlen);

            v.checkPrintTestVector("Dec.s", Hex.toHexString(prgSeed));

            basic.setBatchVector(prgSeed);

            v.print("Batch input... ");
            basic.batchInput();
            v.println(DONE_MSG);

            v.print("Batch combined decryption factors... ");
            basic.batchCombined();
            v.println(DONE_MSG);

            // Read commitments.
            readCommitments(basic);

            final ByteTreeBasic challengeData =
                new ByteTreeContainer(new ByteTree(prgSeed),
                                      basic.getCommitment());

            final byte[] challengeBytes = challenger.challenge(challengeData,
                                                               v.vbitlenro,
                                                               v.rbitlen);
            final LargeInteger integerChallenge =
                LargeInteger.toPositive(challengeBytes);

            v.checkPrintTestVector("Dec.v", integerChallenge.toString());

            // Read reply.
            readReplies(basic);

            v.print("Combined proofs... ");
            basic.combine(correct);
            v.println(DONE_MSG);

            // Verify combined proof.
            verifyCombined(basic, integerChallenge);

            basic.free();

            // Recompute the combined decryption factors.
            freeDecryptionFactors(decryptionFactors);

            // Compute plaintext group elements.
            final PGroupElementArray computedPlaintextElements =
                computePlaintexts(ciphertexts, combinedDecryptionFactors);
            combinedDecryptionFactors.free();

            // Read plaintext group elements.
            final PGroupElementArray plaintextElements =
                readPlaintexts(computedPlaintextElements);

            // Check that computed plaintexts and read plaintexts
            // match.
            matchComputedPlaintexts(plaintextElements,
                                    computedPlaintextElements);
            plaintextElements.free();
            computedPlaintextElements.free();
            ciphertexts.free();
        }
    }
}
