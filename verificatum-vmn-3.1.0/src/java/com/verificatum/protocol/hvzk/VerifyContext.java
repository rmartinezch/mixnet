package com.verificatum.protocol.hvzk;

import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRingElement;

public final class VerifyContext {
    private final PGroupElement g;
    private final PGroupElementArray h;
    private final PGroupElementArray u;
    private final PGroupElement pkey;
    private final PGroupElementArray w;
    private final PGroupElementArray wp;
    private final PGroupElementArray raisedu;
    private final PGroupElementArray raisedh;
    private final PRingElement raisedExponent;

    public VerifyContext(PGroupElement g,
                         PGroupElementArray h,
                         PGroupElementArray u,
                         PGroupElement pkey,
                         PGroupElementArray w,
                         PGroupElementArray wp,
                         PGroupElementArray raisedu,
                         PGroupElementArray raisedh,
                         PRingElement raisedExponent) {
        this.g = g; this.h = h; this.u = u; this.pkey = pkey;
        this.w = w; this.wp = wp; this.raisedu = raisedu;
        this.raisedh = raisedh; this.raisedExponent = raisedExponent;
    }

    public PGroupElement getG() { return g; }
    public PGroupElementArray getH() { return h; }
    public PGroupElementArray getU() { return u; }
    public PGroupElement getPkey() { return pkey; }
    public PGroupElementArray getW() { return w; }
    public PGroupElementArray getWp() { return wp; }
    public PGroupElementArray getRaisedu() { return raisedu; }
    public PGroupElementArray getRaisedh() { return raisedh; }
    public PRingElement getRaisedExponent() { return raisedExponent; }
}
