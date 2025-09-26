package com.verificatum.protocol.hvzk;

import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.arithm.Permutation;

public record InstanceContext(PGroupElement g, PGroupElementArray h, PGroupElementArray u, PGroupElement pkey,
                              PGroupElementArray w, PGroupElementArray wp, PRingElementArray r, Permutation pi,
                              PRingElementArray s) {
}
