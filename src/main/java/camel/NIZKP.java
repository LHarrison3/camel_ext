package camel;

import java.util.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * An abstract class for NIZKPs.
 * This class simply stores the cryptographic values necessary for a NIZKP to be generated and verified.
 */
public abstract class NIZKP {

    // storage of the ballot
    protected Ballot ballot;

    // number of candidates
    protected int num_candidates;

    // curve parameters
    protected ECCurve.Fp curve;
    protected BigInteger q;

    // the generators g0 and g1
    protected ECPoint g0;
    protected ECPoint g1;

    public NIZKP(ECCurve.Fp curve, ECPoint g0, ECPoint g1, int num_candidates, Ballot ballot) {

        this.curve = curve;
        this.q = curve.getQ();
        this.g0 = g0;
        this.g1 = g1;
        this.num_candidates = num_candidates;

        this.ballot = ballot;

    }

    // method to verify the NIZKP
    public abstract boolean verify();

    // get the associated ballot
    public Ballot getBallot() {
        return this.ballot;
    }

}