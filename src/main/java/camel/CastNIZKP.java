package camel;

import java.util.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * This class represents the NIZKPs of well-formedness during the Vote Casting phase.
 */
public class CastNIZKP extends NIZKP {

    // this NIZKP has one conjunction
    // we store all the published values per conjunction
    private BigInteger[][] con;

    public CastNIZKP(BigInteger p, BigInteger q, BigInteger g0, BigInteger g1, int num_candidates, Ballot ballot, int[] vote, BigInteger[] x) {

        super(p, q, g0, g1, num_candidates, ballot);

        genCon(vote, x);

    }

    public boolean verify() {

        return verifyCon();

    }

    // generate the first conjunction 
    // /\ j in [1,n] U {0} : \/ i in [1,n] U {0} : log_g0 b_ik/g1^j = log_g1 y_ik
    private void genCon(int[] vote, BigInteger[] x) {

        // initialise storage for published values
        this.con = new BigInteger[num_candidates + 1][4 * (num_candidates + 1)];

        BigInteger[] b = ballot.getB();
        BigInteger[] y = ballot.getY();

        BigInteger id = BigInteger.valueOf(ballot.getIndex());

        // generate proof for each entry in the vector
        for (int j = 0; j <= num_candidates; j++) {

            BigInteger[] r = new BigInteger[num_candidates + 1];
            BigInteger[] t = new BigInteger[num_candidates + 1];
            BigInteger[] t_p = new BigInteger[num_candidates + 1];
            BigInteger[] c = new BigInteger[num_candidates + 1];
            BigInteger[] s = new BigInteger[num_candidates + 1];

            int marked_entry = (-1);
            for (int i = 0; i <= num_candidates; i++) {

                if (vote[i] == j) {

                    marked_entry = i;

                    r[i] = super.genRandomQ();
                    t[i] = g0.modPow(r[i], p);
                    t_p[i] = g1.modPow(r[i], p);

                } else {

                    c[i] = super.genRandomQ();
                    s[i] = super.genRandomQ();
                    t[i] = b[i].multiply(g1.modPow(BigInteger.valueOf(j), p).modInverse(p)).modPow(c[i], p).modInverse(p).multiply(g0.modPow(s[i], p)).mod(p);
                    t_p[i] = y[i].modInverse(p).modPow(c[i], p).multiply(g1.modPow(s[i], p)).mod(p);

                }

            }

            BigInteger ch;

            ArrayList<BigInteger> all = new ArrayList<BigInteger>();

            all.add(id);
            all.add(g0);
            all.add(g1);
            for (int i = 0; i <= num_candidates; i++) {
                all.add(b[i]);
                all.add(y[i]);
                all.add(t[i]);
                all.add(t_p[i]);
            }

            BigInteger[] arr = all.toArray(new BigInteger[all.size()]);
            ch = Election.hash(arr);

            // compute the challenge for the marked entry
            c[marked_entry] = ch;
            for (int i = 0; i <= num_candidates; i++) {
                if (i != marked_entry) {
                    c[marked_entry] = c[marked_entry].subtract(c[i]).mod(q);
                }
            }

            s[marked_entry] = r[marked_entry].add(x[marked_entry].multiply(c[marked_entry]).mod(q)).mod(q);

            // record all published values
            // t then tp then c then s
            int idx = 0;
            for (int i = 0; i <= num_candidates; i++) {
                con[j][idx] = t[i];
                idx++;
            }
            for (int i = 0; i <= num_candidates; i++) {
                con[j][idx] = t_p[i];
                idx++;
            }
            for (int i = 0; i <= num_candidates; i++) {
                con[j][idx] = c[i];
                idx++;
            }
            for (int i = 0; i <= num_candidates; i++) {
                con[j][idx] = s[i];
                idx++;
            }

        }

    }

    // verify the first conjunction
    private boolean verifyCon() {

        boolean hold = true;

        BigInteger[] t = new BigInteger[num_candidates + 1];
        BigInteger[] t_p = new BigInteger[num_candidates + 1];
        BigInteger[] c = new BigInteger[num_candidates + 1];
        BigInteger[] s = new BigInteger[num_candidates + 1];
        
        BigInteger[] b = super.ballot.getB();
        BigInteger[] y = super.ballot.getY();

        for (int j = 0; j <= num_candidates; j++) {

            int idx = 0;
            for (int i = 0; i <= num_candidates; i++) {
                t[i] = this.con[j][idx];
                idx++;
            }
            for (int i = 0; i <= num_candidates; i++) {
                t_p[i] = this.con[j][idx];
                idx++;
            }
            for (int i = 0; i <= num_candidates; i++) {
                c[i] = this.con[j][idx];
                idx++;
            }
            for (int i = 0; i <= num_candidates; i++) {
                s[i] = this.con[j][idx];
                idx++;
            }

            for (int i = 0; i <= num_candidates; i++) {

                BigInteger left0 = g0.modPow(s[i], p);
                BigInteger right0 = b[i].multiply(g1.modPow(BigInteger.valueOf(j),p).modInverse(p)).mod(p).modPow(c[i],p).multiply(t[i]).mod(p);  //b[i].modPow(c[i], p).multiply(g1.modPow(BigInteger.valueOf(j), p).modInverse(p)).mod(p).multiply(t[i]).mod(p);

                //System.out.println(left0.toString().substring(0,4) + " == " + right0.toString().substring(0,4));

                BigInteger left1 = g1.modPow(s[i], p);
                BigInteger right1 = y[i].modPow(c[i], p).multiply(t_p[i]).mod(p);

                if (left0.compareTo(right0) != 0 || left1.compareTo(right1) != 0) {
                    hold = false;
                }

            }

        }

        return hold;

    }

}