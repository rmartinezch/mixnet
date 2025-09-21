
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

import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.ExtIO;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.elgamal.DistrElGamalSession;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.ui.Log;
import com.verificatum.vcr.VCR;


/**
 * Implements a single mix-net session of a mix-net as implemented in
 * {@link MixNetElGamal}.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings("PMD.MethodNamingConventions")
public final class MixNetElGamalSession extends ProtocolElGamal {
    private static final String SHUFFLE_PARAMETER = ".shuffle";
    private static final String PRECOMP_PARAMETER = ".precomp";
    private static final String DECRYPT_PARAMETER = ".decrypt";
    /**
     * Fiat-Shamir proof of a mixing.
     */
    public static final String MIX_TYPE = "mixing";

    /**
     * Fiat-Shamir proof of a shuffling without decryption.
     */
    public static final String SHUFFLE_TYPE = "shuffling";

    /**
     * Fiat-Shamir proof of a decryption without shuffling.
     */
    public static final String DECRYPT_TYPE = "decryption";

    /**
     * Shuffler session used to re-randomize and permute ciphertexts.
     */
    ShufflerElGamalSession segSession;

    /**
     * Distributed El Gamal session used to generate a key and to
     * decrypt.
     */
    DistrElGamalSession degSession;

    /**
     * Destination of core non-interactive zero-knowledge proofs.
     */
    File proofs;

    /**
     * Initializes a mix-net.
     *
     * @param sid Session identifier of this instance.
     * @param prot Protocol which invokes this one.
     * @param rosid Session identifier for random oracle proofs.
     * @param nizkp Destination directory for random oracle
     * proofs. Note that this directory is deleted when {@link
     * com.verificatum.protocol.Protocol#deleteState()} is called.
     */
    protected MixNetElGamalSession(final String sid,
                                   final MixNetElGamal prot,
                                   final String rosid,
                                   final File nizkp) {
        super(sid, prot, sid, nizkp);

        ExtIO.unsafeWriteString(getAFile(nizkp), sid);

        proofs = null;
        if (nizkp != null) {

            final File versionFile = getVFile(nizkp);
            ExtIO.unsafeWriteString(versionFile, VCR.version());

            proofs = new File(nizkp, "proofs");
            try {
                ExtIO.mkdirs(proofs);
            } catch (final EIOException eioe) {
                throw new ProtocolError("Unable to create proofs directory!",
                                        eioe);
            }
        }
        segSession = getMixNet().shufflerElGamal.getSession(rosid, proofs);

        // We only generate a decryption session if the public key was
        // generated (and not set using an external public key).
        if (getMixNet().distrElGamal != null) {
            degSession = getMixNet().distrElGamal.getSession(rosid, proofs);
        }
    }

    /**
     * Returns the mix-net that created this session.
     *
     * @return Mix-net that created this session.
     */
    protected MixNetElGamal getMixNet() {
        return (MixNetElGamal) parent;
    }

    /**
     * Delete the whole session. This allows running a new session
     * with the same non-interactive zero-knowlege session identifier.
     */
    @Override
    public void deleteState() {

        if (segSession != null) {
            segSession.deleteState();
        }

        if (degSession != null) {
            degSession.deleteState();
        }

        super.deleteState();
        if (fnizkp != null) {
            ExtIO.delete(fnizkp);
        }
    }

    /**
     * Perform pre-computation to speed up a call to {@link
     * #shuffle(Log,int,PGroupElementArray)}.
     *
     * @param log Logging context.
     * @param width Width of ciphertexts.
     * @param size Number of ciphertexts for which pre-computation is
     * performed.
     */
    public void precomp(final Log log, final int width, final int size) {
        if (readBoolean(PRECOMP_PARAMETER)
            || readBoolean(SHUFFLE_PARAMETER)
            || readBoolean(DECRYPT_PARAMETER)) {
            throw new ProtocolError("Attempting to pre-compute in a used "
                                    + "session!");
        } else {

            writeBoolean(PRECOMP_PARAMETER);
        }

        // Write width to proof directory to make it self-contained.
        if (fnizkp != null) {
            final File widthFile = getWFile(fnizkp);
            ExtIO.unsafeWriteInt(widthFile, width);
        }

        segSession.precomp(log, width, size);

        if (fnizkp != null) {

            ExtIO.unsafeWriteString(getTFile(fnizkp), SHUFFLE_TYPE);

            getMixNet().writeKeys(fnizkp, proofs);
        }
    }

    /**
     * Perform pre-computation to speed up a call to {@link
     * #shuffle(Log,int,PGroupElementArray)}.
     *
     * @param width Width of ciphertexts.
     * @param size Number of ciphertexts for which pre-computation is
     * performed.
     */
    public void precomp(final int width, final int size) {
        precomp(ui.getLog(), width, size);
    }

    /**
     * Shuffle the input ciphertexts.
     *
     * @param log Logging context.
     * @param width Width of ciphertexts.
     * @param ciphertexts Ciphertexts to be shuffled.
     * @return Resulting output ciphertexts.
     */
    public PGroupElementArray shuffle(final Log log,
                                      final int width,
                                      final PGroupElementArray ciphertexts) {

        if (readBoolean(SHUFFLE_PARAMETER) || readBoolean(DECRYPT_PARAMETER)) {
            throw new ProtocolError("Attempting to shuffle in a used session!");
        }
        writeBoolean(SHUFFLE_PARAMETER);

        if (fnizkp != null) {

            // Write width to proof directory to make it self-contained.
            final File widthFile = getWFile(fnizkp);
            ExtIO.unsafeWriteInt(widthFile, width);

            ciphertexts.toByteTree().unsafeWriteTo(getLFile(fnizkp));
        }

        PGroupElementArray shufCiphertexts;
        if (readBoolean(PRECOMP_PARAMETER)) {

            shufCiphertexts =
                segSession.committedShuffle(log, width, ciphertexts);
        } else {

            shufCiphertexts = segSession.shuffle(log, width, ciphertexts);
        }

        // Write output shuffled list of ciphertexts.
        if (fnizkp != null) {

            ExtIO.unsafeWriteString(getTFile(fnizkp), SHUFFLE_TYPE);

            shufCiphertexts.toByteTree().unsafeWriteTo(getLSFile(fnizkp));
            getMixNet().writeKeys(fnizkp, proofs);
        }

        return shufCiphertexts;
    }

    /**
     * Shuffle the input ciphertexts.
     *
     * @param width Width of ciphertexts.
     * @param ciphertexts Ciphertexts to be shuffled.
     * @return Shuffled output ciphertexts.
     */
    public PGroupElementArray shuffle(final int width,
                                      final PGroupElementArray ciphertexts) {
        return shuffle(ui.getLog(), width, ciphertexts);
    }

    /**
     * Decrypt input ciphertexts.
     *
     * @param log Logging context.
     * @param width Width of ciphertexts.
     * @param ciphertexts Ciphertexts to be decrypted.
     * @return Decrypted output elements.
     */
    public PGroupElementArray decrypt(final Log log,
                                      final int width,
                                      final PGroupElementArray ciphertexts) {

        if (degSession == null) {
            throw new ProtocolError("The public key of this mix-net was "
                                    + "generated externally, so no secret keys "
                                    + "have been generated. Thus, decryption "
                                    + "is not possible!");
        }
        if (readBoolean(DECRYPT_PARAMETER)) {
            throw new ProtocolError("Attempting to decrypt in a used session!");
        }
        if (readBoolean(PRECOMP_PARAMETER) && !readBoolean(SHUFFLE_PARAMETER)) {
            throw new ProtocolError("Performed pre-computation, but no "
                                    + "shuffling!");
        }
        writeBoolean(DECRYPT_PARAMETER);

        // Write width to proof directory to make it self-contained.
        if (fnizkp != null) {
            final File widthFile = getWFile(fnizkp);
            ExtIO.unsafeWriteInt(widthFile, width);

            // If we execute after shuffle, then we move its output
            // shuffled ciphertexts into the proofs directory.
            if (getLSFile(fnizkp).exists()) {

                ExtIO.unsafeWriteString(getTFile(fnizkp), MIX_TYPE);

                final File tmpFile =
                    ShufflerElGamalSession.Lfile(proofs, threshold);

                if (!getLSFile(fnizkp).renameTo(tmpFile)) {
                    throw new ProtocolError("Unable to rename file!");
                }

            } else {

                ExtIO.unsafeWriteString(getTFile(fnizkp), DECRYPT_TYPE);

                ciphertexts.toByteTree().unsafeWriteTo(getLFile(fnizkp));
            }
        }

        final PGroupElementArray plaintexts =
            degSession.decrypt(log, ciphertexts);

        // Write output.
        if (fnizkp != null) {
            plaintexts.toByteTree().unsafeWriteTo(getPFile(fnizkp));
            getMixNet().writeKeys(fnizkp, proofs);
        }

        return plaintexts;
    }

    /**
     * Decrypt input ciphertexts.
     *
     * @param width Width of ciphertexts.
     * @param ciphertexts Ciphertexts to be decrypted.
     * @return Decrypted output elements.
     */
    public PGroupElementArray decrypt(final int width,
                                      final PGroupElementArray ciphertexts) {
        return decrypt(ui.getLog(), width, ciphertexts);
    }

    /**
     * Returns the plaintexts of the given ciphertexts in random order.
     *
     * @param log Logging context.
     * @param width Width of ciphertexts.
     * @param ciphertexts Ciphertexts to be decrypted.
     * @return Mixed output elements.
     */
    public PGroupElementArray mix(final Log log,
                                  final int width,
                                  final PGroupElementArray ciphertexts) {
        final PGroupElementArray tmp = shuffle(log, width, ciphertexts);
        final PGroupElementArray plaintexts = decrypt(log, width, tmp);
        tmp.free();
        return plaintexts;
    }

    /**
     * Returns the plaintexts of the given ciphertexts in random order.
     *
     * @param width Width of ciphertexts.
     * @param ciphertexts Ciphertexts to be decrypted.
     * @return Mixed output elements.
     */
    public PGroupElementArray mix(final int width,
                                  final PGroupElementArray ciphertexts) {
        return mix(ui.getLog(), width, ciphertexts);
    }

    /**
     * Releases resources allocated by this instance.
     */
    public void free() {
        if (segSession != null) {
            segSession.free();
        }
    }

    /**
     * Name of file containing the auxiliary session identifier.
     *
     * @param nizkp Destination directory of list of ciphertexts.
     * @return File containing the auxiliary session identifier.
     */
    public static File getAFile(final File nizkp) {
        return new File(nizkp, "auxsid");
    }

    /**
     * Name of file containing the input list of ciphertexts.
     *
     * @param nizkp Destination directory of list of ciphertexts.
     * @return File containing input list of ciphertexts.
     */
    public static File getLFile(final File nizkp) {
        return new File(nizkp, "Ciphertexts.bt");
    }

    /**
     * Name of file containing the output list of ciphertexts of the
     * shuffle.
     *
     * @param nizkp Destination directory of list of ciphertexts.
     * @return File containing output list of ciphertexts from the
     * shuffle.
     */
    public static File getLSFile(final File nizkp) {
        return new File(nizkp, "ShuffledCiphertexts.bt");
    }

    /**
     * Name of file containing the decrypted plaintext elements.
     *
     * @param nizkp Destination directory.
     * @return File where the output plaintext elements are stored.
     */
    public static File getPFile(final File nizkp) {
        return new File(nizkp, "Plaintexts.bt");
    }

    /**
     * Name of file containing the type of proof.
     *
     * @param nizkp Destination directory.
     * @return File containing type of proof.
     */
    public static File getTFile(final File nizkp) {
        return new File(nizkp, "type");
    }

    /**
     * Name of file containing the width of ciphertexts processed by
     * the mix-net.
     *
     * @param nizkp Destination directory.
     * @return File containing width of ciphertexts.
     */
    public static File getWFile(final File nizkp) {
        return new File(nizkp, "width");
    }

    /**
     * Name of file containing the version of this package.
     *
     * @param nizkp Destination directory.
     * @return File containing the version of this package.
     */
    public static File getVFile(final File nizkp) {
        return new File(nizkp, "version");
    }
}
