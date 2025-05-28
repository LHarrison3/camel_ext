package camel;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * This class represents the structure of possible ballots in Camel.
 */
public class Ballot {

    // index of a ballot
    protected final int index;

    // components of a ballot
    protected final ECPoint[] b;
    protected final ECPoint[] y;
    protected final ECPoint[] e;
    protected final ECPoint[] z;

    public Ballot(int index, ECPoint[] b, ECPoint[] y, ECPoint[] e, ECPoint[] z) {
        this.index = index;
        this.b = b;
        this.y = y;
        this.e = e;
        this.z = z;
    }

    public int getIndex() {
        return this.index;
    }

    public ECPoint[] getB() {
        return this.b;
    }

    public ECPoint[] getY() {
        return this.y;
    }

    public ECPoint[] getE() {
        return this.e;
    }

    public ECPoint[] getZ() {
        return this.z;
    }

}
