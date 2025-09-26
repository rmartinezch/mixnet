package com.verificatum.protocol.hvzk;

import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.arithm.Permutation;
import com.verificatum.ui.Log;

public class ProveContext {
    private final Log log;
    private final PGroupElement g;
    private final PGroupElementArray h;
    private final PGroupElementArray u;
    private final PGroupElement pkey;
    private final PGroupElementArray w;
    private final PGroupElementArray wp;
    private final PRingElementArray r;
    private final Permutation pi;
    private final PRingElementArray s;

    public ProveContext(Log log,
                        PGroupElement g,
                        PGroupElementArray h,
                        PGroupElementArray u,
                        PGroupElement pkey,
                        PGroupElementArray w,
                        PGroupElementArray wp,
                        PRingElementArray r,
                        Permutation pi,
                        PRingElementArray s) {
        this.log = log;
        this.g = g;
        this.h = h;
        this.u = u;
        this.pkey = pkey;
        this.w = w;
        this.wp = wp;
        this.r = r;
        this.pi = pi;
        this.s = s;
    }

    public Log getLog() { return log; }
    public PGroupElement getG() { return g; }
    public PGroupElementArray getH() { return h; }
    public PGroupElementArray getU() { return u; }
    public PGroupElement getPkey() { return pkey; }
    public PGroupElementArray getW() { return w; }
    public PGroupElementArray getWp() { return wp; }
    public PRingElementArray getR() { return r; }
    public Permutation getPi() { return pi; }
    public PRingElementArray getS() { return s; }
}
