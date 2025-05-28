package camel;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * This class represents storage of data for an election
 */
public class ElectionData {

    // plaintext votes
    int[] vote;

    // plaintext encodings
    int[] encoding;

    // randomnesses
    BigInteger[] x_bal;
    BigInteger[] x_enc;

    public ElectionData(int[] vote, int[] encoding, BigInteger[] x_bal, BigInteger[] x_enc) {
        this.vote = vote;
        this.encoding = encoding;
        this.x_bal = x_bal;
        this.x_enc = x_enc;
    }

    public int[] getVote() {
        return this.vote;
    }

    public int[] getEncoding() {
        return this.encoding;
    }

    public BigInteger[] getRandomnessesBal() {
        return this.x_bal;
    }

    public BigInteger[] getRandomnessesEnc() {
        return this.x_enc;
    }


}