package camel;

import java.math.BigInteger;

/**
 * This class represents the structure of possible ballots in Camel.
 */
public class Ballot {

    // index of a ballot
    protected final int index;

    // components of a ballot
    protected final BigInteger[] b;
    protected final BigInteger[] y;
    protected final BigInteger[] e;
    protected final BigInteger[] z;

    public Ballot(int index, BigInteger[] b, BigInteger[] y, BigInteger[] e, BigInteger[] z) {
        this.index = index;
        this.b = b;
        this.y = y;
        this.e = e;
        this.z = z;
    }

    public int getIndex() {
        return this.index;
    }

    public BigInteger[] getB() {
        return this.b;
    }

    public BigInteger[] getY() {
        return this.y;
    }

    public BigInteger[] getE() {
        return this.e;
    }

    public BigInteger[] getZ() {
        return this.z;
    }

    /*
    // display the b component of a ballot
    public void displayB() {

        for (int i = 0; i < b.length; i++) {
            for (int j = 0; j < b[i].length; j++) {

                if (j == b[i].length - 1) {
                    System.out.println(b[i][j].toString().substring(0,4));
                } else {
                    System.out.print(b[i][j].toString().substring(0,4) + ", ");
                } 

            }
        }

    }
    */

}
