package com.verificatum.protocol.hvzk;

import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRingElement;

public record VerifyContext(PGroupElement g, PGroupElementArray h, PGroupElementArray u, PGroupElement pkey,
                            PGroupElementArray w, PGroupElementArray wp, PGroupElementArray raisedu,
                            PGroupElementArray raisedh, PRingElement raisedExponent) {
}
