package camel;

import java.util.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * This class represents the NIZKPs of well-formedness during the Vote Casting phase.
 */
public class CastNIZKP extends NIZKP {

    // this NIZKP has one conjunction
    // we store all the published values per conjunction
    // we separate the commitments from the challenges and responses
    private ECPoint[][] con_t;
    private BigInteger[][] con_c; 
    private BigInteger[][] con_s;

    public CastNIZKP(ECCurve.Fp curve, ECPoint g0, ECPoint g1, int num_candidates, Ballot ballot, int[] vote, BigInteger[] x) {

        super(curve, g0, g1, num_candidates, ballot);

        genCon(vote, x);

    }

    public boolean verify() {

        return verifyCon();

    }

    
    // generate the first conjunction 
    // /\ j in [1,n] U {0} : \/ i in [1,n] U {0} : log_g0 b_ik/g1^j = log_g1 y_ik
    private void genCon(int[] vote, BigInteger[] x) {

        // initialise storage for published values
        this.con_t = new ECPoint[num_candidates + 1][2 * (num_candidates + 1)];
        this.con_c = new BigInteger[num_candidates + 1][num_candidates + 1];
        this.con_s = new BigInteger[num_candidates + 1][num_candidates + 1];

        ECPoint[] b = ballot.getB();
        ECPoint[] y = ballot.getY();

        BigInteger id = BigInteger.valueOf(ballot.getIndex());

        // generate proof for each entry in the vector
        for (int j = 0; j <= num_candidates; j++) {

            BigInteger[] r = new BigInteger[num_candidates + 1];
            ECPoint[] t = new ECPoint[num_candidates + 1];
            ECPoint[] t_p = new ECPoint[num_candidates + 1];
            BigInteger[] c = new BigInteger[num_candidates + 1];
            BigInteger[] s = new BigInteger[num_candidates + 1];

            int marked_entry = (-1);
            for (int i = 0; i <= num_candidates; i++) {

                if (vote[i] == j) {

                    marked_entry = i;

                    r[i] = Election.genRandom(q);
                    t[i] = g0.multiply(r[i]);  
                    t_p[i] = g1.multiply(r[i]);

                } else {

                    c[i] = Election.genRandom(q);
                    s[i] = Election.genRandom(q);
                    t[i] = (b[i].subtract(g1.multiply(BigInteger.valueOf(j)))).multiply(c[i].negate()).add(g0.multiply(s[i]));     
                    t_p[i] = (y[i]).multiply(c[i].negate()).add(g1.multiply(s[i]));

                }

            }

            BigInteger ch;

            ArrayList<ECPoint> all = new ArrayList<ECPoint>();

            all.add(g0.multiply(id));
            all.add(g0);
            all.add(g1);
            for (int i = 0; i <= num_candidates; i++) {
                all.add(b[i]);
                all.add(y[i]);
                all.add(t[i]);
                all.add(t_p[i]);
            }

            ECPoint[] arr = all.toArray(new ECPoint[all.size()]);
            ch = Election.hash(arr);

            // compute the challenge for the marked entry
            c[marked_entry] = ch;
            for (int i = 0; i <= num_candidates; i++) {
                if (i != marked_entry) {
                    c[marked_entry] = c[marked_entry].subtract(c[i]);
                }
            }

            s[marked_entry] = r[marked_entry].add(x[marked_entry].multiply(c[marked_entry]));

            // record all published values
            // t then tp then c then s
            int idx = 0;
            for (int i = 0; i <= num_candidates; i++) {
                con_t[j][idx] = t[i];
                idx++;
            }
            for (int i = 0; i <= num_candidates; i++) {
                con_t[j][idx] = t_p[i];
                idx++;
            }
            idx = 0;
            for (int i = 0; i <= num_candidates; i++) {
                con_c[j][idx] = c[i];
                idx++;
            }
            idx = 0;
            for (int i = 0; i <= num_candidates; i++) {
                con_s[j][idx] = s[i];
                idx++;
            }

        }

    }

    
    // verify the first conjunction
    private boolean verifyCon() {

        boolean hold = true;

        ECPoint[] t = new ECPoint[num_candidates + 1];
        ECPoint[] t_p = new ECPoint[num_candidates + 1];
        BigInteger[] c = new BigInteger[num_candidates + 1];
        BigInteger[] s = new BigInteger[num_candidates + 1];
        
        ECPoint[] b = super.ballot.getB();
        ECPoint[] y = super.ballot.getY();

        for (int j = 0; j <= num_candidates; j++) {

            int idx = 0;
            for (int i = 0; i <= num_candidates; i++) {
                t[i] = this.con_t[j][idx];
                idx++;
            }
            for (int i = 0; i <= num_candidates; i++) {
                t_p[i] = this.con_t[j][idx];
                idx++;
            }
            idx = 0;
            for (int i = 0; i <= num_candidates; i++) {
                c[i] = this.con_c[j][idx];
                idx++;
            }
            idx = 0;
            for (int i = 0; i <= num_candidates; i++) {
                s[i] = this.con_s[j][idx];
                idx++;
            }

            for (int i = 0; i <= num_candidates; i++) {

                ECPoint left0 = g0.multiply(s[i]); 
                ECPoint right0 = (b[i].subtract(g1.multiply(BigInteger.valueOf(j)))).multiply(c[i]).add(t[i]);   

                ECPoint left1 = g1.multiply(s[i]);
                ECPoint right1 = (y[i].multiply(c[i])).add(t_p[i]);  

                if (!left0.equals(right0) || !left1.equals(right1)) {
                    hold = false;
                }

            }

        }

        return hold;

    }
    
}