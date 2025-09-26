
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

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.arithm.PPGroupElementArray;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElement;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.demo.DemoError;
import com.verificatum.protocol.demo.DemoException;
import com.verificatum.protocol.demo.DemoProtocol;
import com.verificatum.protocol.demo.DemoProtocolElGamalFactory;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.ui.UI;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;

/**
 * Demonstrates {@link ShufflerElGamal}.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.SignatureDeclareThrowsException",
                   "PMD.AvoidCatchingThrowable"})
public class DemoShufflerElGamal extends DemoProtocolElGamalFactory {

    /**
     * Creates a root protocol.
     *
     */
    public DemoShufflerElGamal() {
        gen = new ShufflerElGamalGen();
    }

    // These methods are documented in DemoProtocolFactory.java.

    @Override
    public DemoProtocol newProtocol(final PrivateInfo privateInfo,
                                    final ProtocolInfo protocolInfo,
                                    final UI ui)
        throws Exception {
        return new ExecShufflerElGamal(privateInfo, protocolInfo, ui);
    }

    @Override
    public void verify(final DemoProtocol... servers) throws Exception {

        final ExecShufflerElGamal server = (ExecShufflerElGamal) servers[1];

        for (int l = 0; l < 4; l++) {
            if (server.plaintexts[l].equals(server.plaintextsOut[l])) {
                throw new DemoException("Shuffle modified plaintexts!");
            }
        }
    }

    /**
     * Turns {@link IndependentGenerator} into a runnable object.
     */
    static class ExecShufflerElGamal extends ShufflerElGamal
        implements DemoProtocol {

        /**
         * Plaintexts that are encrypted and shuffled during the
         * execution of the protocol.
         */
        protected PGroupElementArray[] plaintexts;

        /**
         * Output plaintexts.
         */
        protected PGroupElementArray[] plaintextsOut;

        /**
         * Creates a runnable wrapper for the protocol.
         *
         * @param privateInfo Information about this party.
         * @param protocolInfo Information about the protocol
         * executed, including information about other
         * parties.
         * @param ui User interface.
         * @throws ProtocolError If the info instances are malformed.
         */
        ExecShufflerElGamal(final PrivateInfo privateInfo,
                            final ProtocolInfo protocolInfo,
                            final UI ui)
            throws ProtocolError {
            super(privateInfo, protocolInfo, ui);
        }

        @Override
        public void run() {
            try {
                startServers();
                setup(ui.getLog());

                initializeArrays();

                final PRing pRing = pgPGroup.getPRing();
                final PPGroup pkPGroup = new PPGroup(pgPGroup, 2);

                PRingElement x = handlePublicKeyExchange(pRing, pkPGroup);

                // Ejecutar las pruebas con width = 1..4
                for (int l = 0; l < 4; l++) {
                    processWidth(l, x, pRing);
                }

                shutdown(ui.getLog());

            } catch (final Throwable e) {
                throw new DemoError("Unable to run demonstration!", e);
            }
        }

        private void readAndSetPublicKey(PPGroup pkPGroup, ByteTreeReader reader) {
            try (reader) { // se cierra automáticamente al salir del bloque
                setPublicKey(pkPGroup.toElement(reader));
            } catch (final ArithmFormatException afe) {
                throw new DemoError("Failed to read public key!", afe);
            }
        }

        private PGroupElementArray readCiphertexts(PPGroup ciphPGroup, ByteTreeReader reader) {
            try (reader) { // se cierra automáticamente al salir del bloque
                return ciphPGroup.toElementArray(0, reader);
            } catch (final ArithmFormatException afe) {
                throw new DemoError("Failed to read ciphertexts!", afe);
            }
        }

        private void initializeArrays() {
            plaintexts = new PGroupElementArray[4];
            plaintextsOut = new PGroupElementArray[4];
        }

        private PRingElement handlePublicKeyExchange(final PRing pRing,
                                                     final PPGroup pkPGroup) {
            PRingElement x = null;
            if (j == 1) {
                // Genera y publica la clave pública
                x = pRing.randomElement(randomSource, rbitlen);
                final PGroupElement y = pgPGroup.getg().exp(x);
                setPublicKey(pkPGroup.product(pgPGroup.getg(), y));

                ui.getLog().info("Publish demo public key.");
                bullBoard.publish("PublicKey", publicKey.toByteTree(), ui.getLog());
            } else {
                // Lee la clave pública publicada
                final ByteTreeReader publicKeyReader =
                        bullBoard.waitFor(1, "PublicKey", ui.getLog());
                readAndSetPublicKey(pkPGroup, publicKeyReader);
            }
            return x;
        }

        private void processWidth(final int l, final PRingElement x, final PRing pRing) {
            final int width = l + 1;
            final PGroup plainPGroup = getPlainPGroup(pgPGroup, width);
            final PRing plainPRing = plainPGroup.getPRing();
            final PPGroup ciphPGroup = getCiphPGroup(pgPGroup, width);

            if (j == 1) {
                handleLeaderCase(l, width, plainPGroup, plainPRing, ciphPGroup, x);
            } else {
                handleFollowerCase(l, width, ciphPGroup);
            }
        }

        private void handleLeaderCase(final int l,
                                      final int width,
                                      final PGroup plainPGroup,
                                      final PRing plainPRing,
                                      final PPGroup ciphPGroup,
                                      final PRingElement x) {

            // Generar plaintexts
            final PGroupElement[] plaintextArray = new PGroupElement[10];
            for (int i = 0; i < plaintextArray.length; i++) {
                plaintextArray[i] = plainPGroup.getg().exp(i);
            }
            plaintexts[l] = plainPGroup.toElementArray(plaintextArray);

            // Generar ciphertexts
            final PRingElementArray r = plainPRing.randomElementArray(10, randomSource, rbitlen);
            final PPGroupElement widePublicKey = ProtocolElGamal.getWidePublicKey(publicKey, width);

            final PGroupElementArray u = widePublicKey.project(0).exp(r);
            final PGroupElementArray t = widePublicKey.project(1).exp(r);
            final PGroupElementArray v = t.mul(plaintexts[l]);
            t.free();

            final PGroupElementArray ciphertexts = ciphPGroup.product(u, v);

            // Publicar ciphertexts
            ui.getLog().info("Publish demo ciphertexts.");
            bullBoard.publish("Ciphertexts" + l, ciphertexts.toByteTree(), ui.getLog());

            // Mezclar
            final ShufflerElGamalSession session = getSession("mysid" + l, fnizkp);
            final PPGroupElementArray ciphertextsOut;
            if (l < 2) {
                ciphertextsOut = (PPGroupElementArray) session.shuffle(ui.getLog(), width, ciphertexts);
            } else {
                session.precomp(ui.getLog(), width, 15);
                ciphertextsOut = (PPGroupElementArray)
                        session.committedShuffle(ui.getLog(), width, ciphertexts);
            }

            // Descifrar
            final PGroupElementArray decryptionFactors = ciphertextsOut.project(0).exp(x);
            plaintextsOut[l] = ciphertextsOut.project(1).mul(decryptionFactors);
        }

        private void handleFollowerCase(final int l,
                                        final int width,
                                        final PPGroup ciphPGroup) {
            // Leer ciphertexts
            final ByteTreeReader ciphertextsReader =
                    bullBoard.waitFor(1, "Ciphertexts" + l, ui.getLog());
            final PGroupElementArray ciphertexts = readCiphertexts(ciphPGroup, ciphertextsReader);

            // Ejecutar mezcla
            final ShufflerElGamalSession session = getSession("mysid" + l, fnizkp);
            if (l < 2) {
                session.shuffle(ui.getLog(), width, ciphertexts);
            } else {
                session.precomp(ui.getLog(), width, 15);
                session.committedShuffle(ui.getLog(), width, ciphertexts);
            }
        }

    }
}
