
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

import com.verificatum.arithm.PGroupElement;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.protocol.elgamal.DistrElGamal;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.ui.Log;
import com.verificatum.ui.UI;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;

/**
 * Implements a mix-net based on the El Gamal cryptosystem.
 *
 * @author Douglas Wikstrom
 */
public class MixNetElGamal extends ProtocolElGamal {
    private static final String SET_PUBLIC_KEY_PARAMETER = ".setPublicKey";
    private static final String PUBLIC_KEY_PARAMETER = ".publicKey";
    /**
     * Name of default width tag.
     */
    public static final String WIDTH = "width";

    /**
     * Name of maximal number of ciphertexts tag tag.
     */
    public static final String MAXCIPH = "maxciph";

    /**
     * Number of bits in exponent used to squeeze lists into a single
     * list before verifying a commitment-consistent proof of a
     * shuffle.
     */
    public static final int RAISED_BITLENGTH = 50;

    /**
     * Distributed El Gamal used to generate keys and decrypt.
     */
    protected DistrElGamal distrElGamal;

    /**
     * Shuffler used to re-randomize and permute ciphertexts.
     */
    protected ShufflerElGamal shufflerElGamal;

    /**
     * Default width of ciphertexts processed by this mix-net.
     */
    protected int iwidth;

    /**
     * Default maximal number of ciphertexts.
     */
    protected int imaxciph;

    /**
     * Creates a mix-net.
     *
     * @param privateInfo Private info of this party.
     * @param protocolInfo Protocol info of this party.
     * @param ui User interface.
     *
     * @throws ProtocolFormatException If the mix-net can not be
     * instantiated from the input infos.
     */
    public MixNetElGamal(final PrivateInfo privateInfo,
                         final ProtocolInfo protocolInfo,
                         final UI ui)
        throws ProtocolFormatException {
        super(privateInfo, protocolInfo, ui);

        // Default number of ciphertexts processed in parallel, i.e.,
        // the "width" of the ciphertexts.
        iwidth = protocolInfo.getIntValue(WIDTH);

        // Default maximal number of ciphertexts for which
        // pre-computation is performed.
        imaxciph = protocolInfo.getIntValue(MAXCIPH);
    }

    @Override
    public void hookLogEntry() {
        final String s =
            "-----------------------------------------------------------\n"
            + ui.getDescrString(j) + "\n"
            + "-----------------------------------------------------------";
        ui.getLog().plainInfo(s);
    }

    /**
     * Creates a mix-net as a child of the given protocol.
     *
     * @param sid Session identifier of this instance.
     * @param prot Protocol which invokes this one.
     * @param rosid Session identifier for random oracle proofs.
     * @param nizkp Destination directory for random oracle
     * proofs. Note that this directory is deleted when {@link
     * #deleteState()} is called.
     * @param iwidth Default width of processed ciphertexts for which
     * pre-computation is performed.
     * @param imaxciph Default number of ciphertexts for which
     * precomputation is performed.
     */
    public MixNetElGamal(final String sid,
                         final ProtocolElGamal prot,
                         final String rosid,
                         final File nizkp,
                         final int iwidth,
                         final int imaxciph) {
        super(sid, prot, rosid, nizkp);
        this.iwidth = iwidth;
        this.imaxciph = imaxciph;
    }

    /**
     * Initializes this mix-net.
     *
     * @param log Logging context.
     */
    @Override
    public void setup(final Log log) {
        super.setup(log);

        writeBoolean(".setup");

        // Note that we let the two instances share their export
        // directories. This works, since the same public key is
        // guarantee to be used when we generate it in
        // generatePublicKey(Log) below.

        shufflerElGamal = new ShufflerElGamal("SEG", this, fnizkp);
        distrElGamal = new DistrElGamal("DEG", this, fnizkp);
    }

    /**
     * Initializes this mix-net.
     */
    public void setup() {
        setup(ui.getLog());
    }

    /**
     * Return the default width of the mix-net.
     *
     * @return Default width of the mix-net.
     */
    public int getDefaultWidth() {
        return iwidth;
    }

    /**
     * Return the default width of the mix-net.
     *
     * @return Default width of the mix-net.
     */
    public int getDefaultMaxCiph() {
        return imaxciph;
    }

    /**
     * Generates an El Gamal public key and initializes the mix-net to
     * use this public key.
     *
     * @param log Logging context.
     */
    public void generatePublicKey(final Log log) {

        if (readBoolean(SET_PUBLIC_KEY_PARAMETER)) {
            throw new ProtocolError("Attempting to generate public key "
                                    + "after the public key has been set!");
        }
        if (!readBoolean(".setup")) {
            throw new ProtocolError("Attempting to generate key before "
                                    + "calling setup!");
        }
        writeBoolean(PUBLIC_KEY_PARAMETER);

        distrElGamal.generatePublicKey(log);
        shufflerElGamal.setPublicKey(distrElGamal.getFullPublicKey());
    }

    /**
     * Generates an El Gamal public key and initializes the mix-net to
     * use this public key.
     */
    public void generatePublicKey() {
        generatePublicKey(ui.getLog());
    }

    /**
     * Sets the public key. This should only be used if the mix-net is
     * used to shuffle using an externally generated public key. Note
     * that if you call this method, then you can not let the mix-net
     * generate a public key later.
     *
     * @param publicKey Full El Gamal public key.
     */
    public void setPublicKey(final PGroupElement publicKey) {
        if (readBoolean(PUBLIC_KEY_PARAMETER)) {
            throw new ProtocolError("Attempting to set public key after the "
                                    + "public key has been generated!");
        }
        writeBoolean(SET_PUBLIC_KEY_PARAMETER);

        // Note that if this happens, then instantiating the
        // ShufflerElGamal and DistrElGamal in this way does not give
        // completely initialized subprotocols. This is still useful
        // to set a key without running the setup of the mix-net.
        if (shufflerElGamal == null) {
            shufflerElGamal = new ShufflerElGamal("SEG", this, fnizkp);
        }
        shufflerElGamal.setPublicKey(publicKey);
    }

    /**
     * Returns the full public key of this mix-net.
     *
     * @return Public key.
     */
    public PGroupElement getPublicKey() {

        if (!(readBoolean(PUBLIC_KEY_PARAMETER) || readBoolean(PUBLIC_KEY_PARAMETER))) {
            throw new ProtocolError("Requesting public key before it has "
                                    + "been set or generated!");
        }

        return shufflerElGamal.getPublicKey();
    }

    /**
     * Writes all the keys of this instance, including any recovered
     * secret keys, to the given directories.
     *
     * @param nizkp Destination of public key.
     * @param subnizkp Destination of other keys.
     */
    public void writeKeys(final File nizkp, final File subnizkp) {

        if (distrElGamal.keysAreGenerated()) {
            distrElGamal.writeKeys(nizkp, subnizkp);
        }

        // Store public key along with proof.
        if (shufflerElGamal.getPublicKey() != null) {

            final File file = DistrElGamal.fpkFile(nizkp);
            shufflerElGamal.getPublicKey().toByteTree().unsafeWriteTo(file);
        }
    }

    /**
     * Return a session that can be used to shuffle and decrypt
     * ciphertexts.
     *
     * @param auxsid Session identifier for random oracle proofs.
     * @return Mix-net session.
     */
    public MixNetElGamalSession getSession(final String auxsid) {

        if (!readBoolean(PUBLIC_KEY_PARAMETER) && !readBoolean(SET_PUBLIC_KEY_PARAMETER)) {
            throw new ProtocolError("Asking for session before any key has "
                                    + "been generated!");
        }

        File sessionNizk = null;
        final String sessionRosid = rosid + "." + auxsid;

        if (fnizkp != null) {
            sessionNizk = new File(fnizkp, auxsid);
        }

        // Note that if this happens, then instantiating the
        // ShufflerElGamal and DistrElGamal in this way does not give
        // completely initialized subprotocols. This is still useful
        // to be able to delete sessions without running the setup of
        // the mix-net.
        if (shufflerElGamal == null) {

            shufflerElGamal = new ShufflerElGamal("SEG", this, fnizkp);
            distrElGamal = new DistrElGamal("DEG", this, fnizkp);

        }

        return new MixNetElGamalSession(auxsid,
                                        this,
                                        sessionRosid,
                                        sessionNizk);
    }
}
