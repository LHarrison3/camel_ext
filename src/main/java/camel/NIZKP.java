package camel;

import java.util.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * An abstract class for NIZKPs.
 * This class simply stores the cryptographic values necessary for a NIZKP to be generated and verified.
 */
public abstract class NIZKP {

    // storage of the ballot
    protected Ballot ballot;

    // number of candidates
    protected int num_candidates;

    // the primes p and q
    protected BigInteger p;
    protected BigInteger q;

    // the generators g0 and g1
    protected BigInteger g0;
    protected BigInteger g1;

    public NIZKP(BigInteger p, BigInteger q, BigInteger g0, BigInteger g1, int num_candidates, Ballot ballot) {

        this.p = p;
        this.q = q;
        this.g0 = g0;
        this.g1 = g1;
        this.num_candidates = num_candidates;

        this.ballot = ballot;

    }

    // method to verify the NIZKP
    public abstract boolean verify();

    // generate a random number from Z^*_q
    protected BigInteger genRandomQ() {
        Random gen = new Random();
        BigInteger random;
        do {
            random = new BigInteger(q.bitLength(), gen);
        } while (random.compareTo(q) >= 0 || random.compareTo(BigInteger.ZERO) == 0);
        return random;
    }

}