package camel;

import java.util.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;


/**
 * This class represents the NIZKPs of well-formedness during the Tallying phase.
 */
public class TallyNIZKP extends NIZKP {

    // this NIZKP must store an additional ballot for the previous round
    private Ballot prev_ballot;

    // the round number and eliminated choice
    private int round;
    private int alpha;
    private int limit_prev;
    private int limit_curr;
    private ArrayList<Integer> elims;

    // this NIZKP has two conjunctions
    // we store all the published values per conjunction
    private ECPoint[][] con11_t;
    private BigInteger[] con1_c;
    private BigInteger[] con1_s;
    private ECPoint[][][] con12_t;
    private BigInteger[][] con12_s;

    public TallyNIZKP(ECCurve.Fp curve, ECPoint g0, ECPoint g1, int num_candidates, Ballot ballot, int[] vote, BigInteger[] x, Ballot prev_ballot, int[] prev_vote, BigInteger[] prev_x, int round, int alpha, ArrayList<Integer> elims) {

        super(curve, g0, g1, num_candidates, ballot);

        this.prev_ballot = prev_ballot;

        this.round = round;
        this.alpha = alpha;
        this.limit_prev = prev_vote.length;
        this.limit_curr = limit_prev - 1;

        // we want a deep copy here
        this.elims = new ArrayList<Integer>();
        for (Integer c : elims) {
            this.elims.add(c);
        }

        genCon1(vote, x, prev_vote, prev_x);

    }

    public boolean verify() {

        return verifyCon1();

    }

    
    
    // generate nizkp for the first conjunction
    public void genCon1(int[] vote, BigInteger[] x, int[] prev_vote, BigInteger[] prev_x) {

        

        // initialise storage for published values
        this.con11_t = new ECPoint[limit_prev][2];
        this.con1_c = new BigInteger[limit_prev];
        this.con1_s = new BigInteger[limit_prev];

        this.con12_t = new ECPoint[limit_prev][limit_curr][2];
        this.con12_s = new BigInteger[limit_prev][limit_curr];

        ECPoint[] b = ballot.getB();
        ECPoint[] y = ballot.getY();
        BigInteger id = BigInteger.valueOf(ballot.getIndex());

        ECPoint[] prev_b = prev_ballot.getB();
        ECPoint[] prev_y = prev_ballot.getY();
        BigInteger prev_id = BigInteger.valueOf(prev_ballot.getIndex());

        int marked_entry = (-1);

        BigInteger[] r = new BigInteger[limit_prev];
        BigInteger[][] r_i = new BigInteger[limit_prev][limit_curr];
        ECPoint[] t = new ECPoint[limit_prev];
        ECPoint[] t_p = new ECPoint[limit_prev];
        ECPoint[][] t_i = new ECPoint[limit_prev][limit_curr];
        ECPoint[][] t_p_i = new ECPoint[limit_prev][limit_curr];
        BigInteger[] c = new BigInteger[limit_prev];
        BigInteger[] s = new BigInteger[limit_prev];
        BigInteger[][] s_i = new BigInteger[limit_prev][limit_curr];

        for (int l = 0; l < limit_prev; l++) {

            // shift happened at entry l
            if (prev_vote[l] == alpha) {

                marked_entry = l;

                r[l] = Election.genRandom(q);
                t[l] = g0.multiply(r[l]);
                t_p[l] = g1.multiply(r[l]);
                for (int i = 0; i < limit_curr; i++) {
                    r_i[l][i] = Election.genRandom(q);
                    t_i[l][i] = g0.multiply(r_i[l][i]);
                    t_p_i[l][i] = g1.multiply(r_i[l][i]);
                }

            } else {

                c[l] = Election.genRandom(q);
                s[l] = Election.genRandom(q);
                t[l] = (prev_b[l].subtract(g1.multiply(BigInteger.valueOf(alpha)))).multiply(c[l].negate()).add(g0.multiply(s[l]));
                t_p[l] = prev_y[l].multiply(c[l].negate()).add(g1.multiply(s[l]));
                for (int i = 0; i < limit_curr; i++) {
                    s_i[l][i] = Election.genRandom(q);
                }
                for (int i = 0; i < l; i++) {
                    t_i[l][i] = (b[i].subtract(prev_b[i])).multiply(c[l].negate()).add(g0.multiply(s_i[l][i]));
                    t_p_i[l][i] = (y[i].subtract(prev_y[i])).multiply(c[l].negate()).add(g1.multiply(s_i[l][i]));
                }
                for (int i = l; i < limit_curr; i++) {
                    t_i[l][i] = (b[i].subtract(prev_b[i+1])).multiply(c[l].negate()).add(g0.multiply(s_i[l][i]));
                    t_p_i[l][i] = (y[i].subtract(prev_y[i+1])).multiply(c[l].negate()).add(g1.multiply(s_i[l][i]));
                }

            }

        }

        BigInteger ch;

        ArrayList<ECPoint> all = new ArrayList<ECPoint>();

        all.add(g0.multiply(id));
        all.add(g0.multiply(prev_id));
        all.add(g0);
        all.add(g1);
        for (int l = 0; l < limit_prev; l++) {

            all.add(prev_b[l]);
            all.add(prev_y[l]);

            all.add(t[l]);
            all.add(t_p[l]);

            for (int i = 0; i < limit_curr; i++) {

                all.add(b[i]);
                all.add(y[i]);
                all.add(t_i[l][i]);
                all.add(t_p_i[l][i]);

            }

        }

        ECPoint[] arr = all.toArray(new ECPoint[all.size()]);
        ch = Election.hash(arr);

        c[marked_entry] = ch;
        for (int l = 0; l < limit_prev; l++) {
            if (l != marked_entry) {
                c[marked_entry] = c[marked_entry].subtract(c[l]);
            }
        }

        s[marked_entry] = r[marked_entry].add(prev_x[marked_entry].multiply(c[marked_entry]));

        for (int i = 0; i < marked_entry; i++) {
            s_i[marked_entry][i] = r_i[marked_entry][i].add(x[i].subtract(prev_x[i]).multiply(c[marked_entry]));
        }

        for (int i = marked_entry; i < limit_curr; i++) {
            s_i[marked_entry][i] = r_i[marked_entry][i].add(x[i].subtract(prev_x[i+1]).multiply(c[marked_entry]));
        }

        for (int l = 0; l < limit_prev; l++) {

            con11_t[l][0] = t[l];
            con11_t[l][1] = t_p[l];
            con1_c[l] = c[l];
            con1_s[l] = s[l];

            for (int i = 0; i < limit_curr; i++) {

                con12_t[l][i][0] = t_i[l][i];
                con12_t[l][i][1] = t_p_i[l][i];
                con12_s[l][i] = s_i[l][i];


            }

        }

    }

    
    // verify NIZKP for the second conjunction
    public boolean verifyCon1() {

        boolean hold = true;

        ECPoint[] b = ballot.getB();
        ECPoint[] y = ballot.getY();

        ECPoint[] prev_b = prev_ballot.getB();
        ECPoint[] prev_y = prev_ballot.getY();

        ECPoint[] t = new ECPoint[limit_prev];
        ECPoint[] t_p = new ECPoint[limit_prev];
        ECPoint[][] t_i = new ECPoint[limit_prev][limit_curr];
        ECPoint[][] t_p_i = new ECPoint[limit_prev][limit_curr];
        BigInteger[] c = new BigInteger[limit_prev];
        BigInteger[] s = new BigInteger[limit_prev];
        BigInteger[][] s_i = new BigInteger[limit_prev][limit_curr];

        for (int l = 0; l < limit_prev; l++) {

            t[l] = con11_t[l][0];
            t_p[l] = con11_t[l][1];
            c[l] = con1_c[l];
            s[l] = con1_s[l];

            ECPoint left0 = g0.multiply(s[l]);
            ECPoint right0 = (prev_b[l].subtract(g1.multiply(BigInteger.valueOf(alpha)))).multiply(c[l]).add(t[l]);  

            ECPoint left1 = g1.multiply(s[l]);
            ECPoint right1 = prev_y[l].multiply(c[l]).add(t_p[l]); 

            if (!left0.equals(right0) || !left1.equals(right1)) {
                hold = false;
            }

            for (int i = 0; i < limit_curr; i++) {

                t_i[l][i] = con12_t[l][i][0];
                t_p_i[l][i] = con12_t[l][i][1];
                s_i[l][i] = con12_s[l][i];

                if (i < l) {

                    ECPoint left2 = g0.multiply(s_i[l][i]);
                    ECPoint right2 = b[i].subtract(prev_b[i]).multiply(c[l]).add(t_i[l][i]); 

                    ECPoint left3 = g1.multiply(s_i[l][i]);
                    ECPoint right3 = y[i].subtract(prev_y[i]).multiply(c[l]).add(t_p_i[l][i]);

                    if (!left2.equals(right2) || !left3.equals(right3)) {
                        hold = false;
                    }

                } else {

                    ECPoint left4 = g0.multiply(s_i[l][i]);
                    ECPoint right4 = b[i].subtract(prev_b[i+1]).multiply(c[l]).add(t_i[l][i]); 

                    ECPoint left5 = g1.multiply(s_i[l][i]);
                    ECPoint right5 = y[i].subtract(prev_y[i+1]).multiply(c[l]).add(t_p_i[l][i]); 

                    if (!left4.equals(right4) || !left5.equals(right5)) {
                        hold = false;
                    }

                }


            }

        }

        return hold;

    }
    

}