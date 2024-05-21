package camel;

import java.util.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


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
    private BigInteger[][] con1;
    private BigInteger[][] con2;

    public TallyNIZKP(BigInteger p, BigInteger q, BigInteger g0, BigInteger g1, int num_candidates, Ballot ballot, int[] vote, BigInteger[] x, Ballot prev_ballot, int[] prev_vote, BigInteger[] prev_x, int round, int alpha, ArrayList<Integer> elims) {

        super(p, q, g0, g1, num_candidates, ballot);

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

        genCon1(vote, x);
        genCon2(vote, x, prev_vote, prev_x);

    }

    public boolean verify() {

        return verifyCon1() && verifyCon2();

    }

    // generate the first conjunction
    private void genCon1(int[] vote, BigInteger[] x) {

        ArrayList<Integer> remaining = new ArrayList<Integer>();
        for (int i = 0; i <= num_candidates; i++) {
            if (!elims.contains(i)) {
                remaining.add(i);
            }
        }

        int length = remaining.size();

        this.con1 = new BigInteger[length][4 * length];

        BigInteger[] b = super.ballot.getB();
        BigInteger[] y = super.ballot.getY();

        BigInteger id = BigInteger.valueOf(ballot.getIndex());

        BigInteger[] r = new BigInteger[length];
        BigInteger[] t = new BigInteger[length];
        BigInteger[] t_p = new BigInteger[length];
        BigInteger[] c = new BigInteger[length];
        BigInteger[] s = new BigInteger[length];

        // generate proof for each non-eliminated entry
        for (int j = 0; j < length; j++) {

            int marked_entry = (-1);

            for (int i = 0; i < length; i++) {

                if (vote[i] == remaining.get(j)) {

                    marked_entry = i;
                    r[i] = super.genRandomQ();
                    t[i] = g0.modPow(r[i], p);
                    t_p[i] = g1.modPow(r[i], p);

                } else {

                    c[i] = super.genRandomQ();
                    s[i] = super.genRandomQ();
                    t[i] = b[i].multiply(g1.modPow(BigInteger.valueOf(remaining.get(j)), p).modInverse(p)).modPow(c[i], p).modInverse(p).multiply(g0.modPow(s[i], p)).mod(p);
                    t_p[i] = y[i].modInverse(p).modPow(c[i], p).multiply(g1.modPow(s[i], p)).mod(p);

                }

            }

            BigInteger ch;

            ArrayList<BigInteger> all = new ArrayList<BigInteger>();

            all.add(id);
            all.add(g0);
            all.add(g1);
            for (int i = 0; i < length; i++) {
                all.add(b[i]);
                all.add(y[i]);
                all.add(t[i]);
                all.add(t_p[i]);
            }

            BigInteger[] arr = all.toArray(new BigInteger [all.size()]);
            ch = Election.hash(arr);

            // compute the challenge for the marked entry
            c[marked_entry] = ch;
            for (int i = 0; i < length; i++) {
                if (i != marked_entry) {
                    c[marked_entry] = c[marked_entry].subtract(c[i]).mod(q);
                }
            }

            s[marked_entry] = r[marked_entry].add(x[marked_entry].multiply(c[marked_entry]).mod(q)).mod(q);

            // record all published values
            for (int i = 0; i < length; i++) {
                con1[j][i] = t[i];
                con1[j][length + i] = t_p[i];
                con1[j][2*length + i] = c[i];
                con1[j][3*length + i] = s[i];
            }

        }

    }

    // verify the first conjunction
    private boolean verifyCon1() {

        boolean hold = true;

        ArrayList<Integer> remaining = new ArrayList<Integer>();
        for (int i = 0; i <= num_candidates; i++) {
            if (!elims.contains(i)) {
                remaining.add(i);
            }
        }

        int length = remaining.size();

        BigInteger[] b = super.ballot.getB();
        BigInteger[] y = super.ballot.getY();

        BigInteger[] t = new BigInteger[length];
        BigInteger[] t_p = new BigInteger[length];
        BigInteger[] c = new BigInteger[length];
        BigInteger[] s = new BigInteger[length];
        
        for (int j = 0; j < length; j++) {

            for (int i = 0; i < length; i++) {
                t[i] = con1[j][i];
                t_p[i] = con1[j][length + i];
                c[i] = con1[j][2*length + i];
                s[i] = con1[j][3*length + i];
            }

            for (int i = 0; i < length; i++) {

                BigInteger left0 = g0.modPow(s[i], p);
                BigInteger right0 = b[i].multiply(g1.modPow(BigInteger.valueOf(remaining.get(j)), p).modInverse(p)).modPow(c[i], p).multiply(t[i]).mod(p);;

                BigInteger left1 = g1.modPow(s[i], p);
                BigInteger right1 = y[i].modPow(c[i], p).multiply(t_p[i]).mod(p);

                if (left0.compareTo(right0) != 0) {
                    hold = false;
                }

            }

        }

        return hold;

    }

    // generate nizkp for the second conjunction
    public void genCon2(int[] vote, BigInteger[] x, int[] prev_vote, BigInteger[] prev_x) {

        // initialise storage for published values
        this.con2 = new BigInteger[limit_prev][4 + 3*limit_curr];

        BigInteger[] b = ballot.getB();
        BigInteger[] y = ballot.getY();
        BigInteger id = BigInteger.valueOf(ballot.getIndex());

        BigInteger[] prev_b = prev_ballot.getB();
        BigInteger[] prev_y = prev_ballot.getY();
        BigInteger prev_id = BigInteger.valueOf(prev_ballot.getIndex());

        int marked_entry = (-1);

        BigInteger[] r = new BigInteger[limit_prev];
        BigInteger[][] r_i = new BigInteger[limit_prev][limit_curr];
        BigInteger[] t = new BigInteger[limit_prev];
        BigInteger[] t_p = new BigInteger[limit_prev];
        BigInteger[][] t_i = new BigInteger[limit_prev][limit_curr];
        BigInteger[][] t_p_i = new BigInteger[limit_prev][limit_curr];
        BigInteger[] c = new BigInteger[limit_prev];
        BigInteger[] s = new BigInteger[limit_prev];
        BigInteger[][] s_i = new BigInteger[limit_prev][limit_curr];

        for (int l = 0; l < limit_prev; l++) {

            // shift happened at entry l
            if (prev_vote[l] == alpha) {

                marked_entry = l;

                r[l] = super.genRandomQ();
                t[l] = g0.modPow(r[l], p);
                t_p[l] = g1.modPow(r[l], p);
                for (int i = 0; i < limit_curr; i++) {
                    r_i[l][i] = super.genRandomQ();
                    t_i[l][i] = g0.modPow(r_i[l][i], p);
                    t_p_i[l][i] = g1.modPow(r_i[l][i], p);
                }

            } else {

                c[l] = super.genRandomQ();
                s[l] = super.genRandomQ();
                t[l] = prev_b[l].multiply(g1.modPow(BigInteger.valueOf(alpha), p).modInverse(p)).mod(p).modPow(c[l], p).modInverse(p).multiply(g0.modPow(s[l], p)).mod(p);
                t_p[l] = prev_y[l].modPow(c[l], p).modInverse(p).multiply(g1.modPow(s[l], p)).mod(p);
                for (int i = 0; i < limit_curr; i++) {
                    s_i[l][i] = super.genRandomQ();
                }
                for (int i = 0; i < l; i++) {
                    t_i[l][i] = b[i].multiply(prev_b[i].modInverse(p)).mod(p).modPow(c[l], p).modInverse(p).multiply(g0.modPow(s_i[l][i], p)).mod(p);
                    t_p_i[l][i] = y[i].multiply(prev_y[i].modInverse(p)).mod(p).modPow(c[l], p).modInverse(p).multiply(g1.modPow(s_i[l][i], p)).mod(p);
                }
                for (int i = l; i < limit_curr; i++) {
                    t_i[l][i] = b[i].multiply(prev_b[i+1].modInverse(p)).mod(p).modPow(c[l], p).modInverse(p).multiply(g0.modPow(s_i[l][i], p)).mod(p);
                    t_p_i[l][i] = y[i].multiply(prev_y[i+1].modInverse(p)).mod(p).modPow(c[l], p).modInverse(p).multiply(g1.modPow(s_i[l][i], p)).mod(p);
                }

            }

        }

        BigInteger ch;

        ArrayList<BigInteger> all = new ArrayList<BigInteger>();

        all.add(id);
        all.add(prev_id);
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

        BigInteger[] arr = all.toArray(new BigInteger[all.size()]);
        ch = Election.hash(arr);

        c[marked_entry] = ch;
        for (int l = 0; l < limit_prev; l++) {
            if (l != marked_entry) {
                c[marked_entry] = c[marked_entry].subtract(c[l]).mod(q);
            }
        }

        s[marked_entry] = r[marked_entry].add(prev_x[marked_entry].multiply(c[marked_entry]).mod(q)).mod(q);

        for (int i = 0; i < marked_entry; i++) {
            s_i[marked_entry][i] = r_i[marked_entry][i].add(x[i].subtract(prev_x[i]).mod(q).multiply(c[marked_entry]).mod(q)).mod(q);
        }

        for (int i = marked_entry; i < limit_curr; i++) {
            s_i[marked_entry][i] = r_i[marked_entry][i].add(x[i].subtract(prev_x[i+1]).mod(q).multiply(c[marked_entry]).mod(q)).mod(q);
        }

        for (int l = 0; l < limit_prev; l++) {

            con2[l][0] = t[l];
            con2[l][1] = t_p[l];
            con2[l][2] = c[l];
            con2[l][3] = s[l];

            for (int i = 0; i < limit_curr; i++) {
                con2[l][4 + i] = t_i[l][i];
                con2[l][4+limit_curr + i] = t_p_i[l][i];
                con2[l][4+2*limit_curr + i] = s_i[l][i];
            } 

        }

    }


    // verify NIZKP for the second conjunction
    public boolean verifyCon2() {

        boolean hold = true;

        BigInteger[] b = ballot.getB();
        BigInteger[] y = ballot.getY();

        BigInteger[] prev_b = prev_ballot.getB();
        BigInteger[] prev_y = prev_ballot.getY();

        BigInteger[] t = new BigInteger[limit_prev];
        BigInteger[] t_p = new BigInteger[limit_prev];
        BigInteger[][] t_i = new BigInteger[limit_prev][limit_curr];
        BigInteger[][] t_p_i = new BigInteger[limit_prev][limit_curr];
        BigInteger[] c = new BigInteger[limit_prev];
        BigInteger[] s = new BigInteger[limit_prev];
        BigInteger[][] s_i = new BigInteger[limit_prev][limit_curr];

        for (int l = 0; l < limit_prev; l++) {

            t[l] = con2[l][0];
            t_p[l] = con2[l][1];
            c[l] = con2[l][2];
            s[l] = con2[l][3];

            BigInteger left0 = g0.modPow(s[l], p);
            BigInteger right0 = prev_b[l].multiply(g1.modPow(BigInteger.valueOf(alpha), p).modInverse(p)).mod(p).modPow(c[l], p).multiply(t[l]).mod(p);

            BigInteger left1 = g1.modPow(s[l], p);
            BigInteger right1 = prev_y[l].modPow(c[l], p).multiply(t_p[l]).mod(p);

            if (left0.compareTo(right0) != 0 || left1.compareTo(right1) != 0) {
                hold = false;
            }

            for (int i = 0; i < limit_curr; i++) {

                t_i[l][i] = con2[l][4 + i];
                t_p_i[l][i] = con2[l][4+limit_curr + i];
                s_i[l][i] = con2[l][4+2*limit_curr + i];

            }

            for (int i = 0; i < l; i++) {

                BigInteger left2 = g0.modPow(s_i[l][i], p);
                BigInteger right2 = b[i].multiply(prev_b[i].modInverse(p)).mod(p).modPow(c[l], p).multiply(t_i[l][i]).mod(p);

                BigInteger left3 = g1.modPow(s_i[l][i], p);
                BigInteger right3 = y[i].multiply(prev_y[i].modInverse(p)).mod(p).modPow(c[l], p).multiply(t_p_i[l][i]).mod(p);

                if (left2.compareTo(right2) != 0 || left3.compareTo(right3) != 0) {
                    hold = false;
                }

            }

            for (int i = l; i < limit_curr; i++) {

                BigInteger left4 = g0.modPow(s_i[l][i], p);
                BigInteger right4 = b[i].multiply(prev_b[i+1].modInverse(p)).mod(p).modPow(c[l], p).multiply(t_i[l][i]).mod(p);

                BigInteger left5 = g1.modPow(s_i[l][i], p);
                BigInteger right5 = y[i].multiply(prev_y[i+1].modInverse(p)).mod(p).modPow(c[l], p).multiply(t_p_i[l][i]).mod(p);

                if (left4.compareTo(right4) != 0 || left5.compareTo(right5) != 0) {
                    hold = false;
                }

            }
            

        }

        return hold;

    }

}