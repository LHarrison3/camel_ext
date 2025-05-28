package camel;

import java.util.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class EncodingNIZKP extends NIZKP {

    // this NIZKP has two conjunctions
    // we store all the published values per conjunction
    private ECPoint[][] con1_t;
    private BigInteger[][] con1_c;
    private BigInteger[][] con1_s;
    private ECPoint[] con2_zeroes_t;
    private BigInteger[] con2_zeroes_c;
    private BigInteger[] con2_zeroes_s;
    private ECPoint[][] con2_rest_t;
    private BigInteger[][] con2_rest_c;
    private BigInteger[][] con2_rest_s;

    private ArrayList<Integer> elims;

    public EncodingNIZKP(ECCurve.Fp curve, ECPoint g0, ECPoint g1, int num_candidates, Ballot ballot, int[] vote, int[] encoding, BigInteger[] x_bal, BigInteger[] x_enc, ArrayList<Integer> elims) {

        super(curve, g0, g1, num_candidates, ballot);

        // we want a deep copy here
        this.elims = new ArrayList<Integer>();
        for (Integer c : elims) {
            this.elims.add(c);
        }

        
        genCon1(encoding, x_enc);
        genCon2(vote, x_bal, encoding, x_enc);
        

    } 

    public boolean verify() {
        return verifyCon1() && verifyCon2();
    }

    
    private void genCon1(int[] encoding, BigInteger[] x_enc) {
        

        // initialise storage for published values
        this.con1_t = new ECPoint[num_candidates][4];
        this.con1_c = new BigInteger[num_candidates][2];
        this.con1_s = new BigInteger[num_candidates][2];

        ECPoint[] e = ballot.getE();
        ECPoint[] z = ballot.getZ();

        BigInteger id = BigInteger.valueOf(ballot.getIndex());

        BigInteger[] r = new BigInteger[num_candidates];
        ECPoint[] t0 = new ECPoint[num_candidates];
        ECPoint[] t0_p = new ECPoint[num_candidates];
        ECPoint[] t1 = new ECPoint[num_candidates];
        ECPoint[] t1_p = new ECPoint[num_candidates]; 
        BigInteger[] c0 = new BigInteger[num_candidates];
        BigInteger[] c1 = new BigInteger[num_candidates];
        BigInteger[] s0 = new BigInteger[num_candidates];
        BigInteger[] s1 = new BigInteger[num_candidates];

        BigInteger ch;
        ArrayList<ECPoint> all = new ArrayList<ECPoint>();
        all.add(g0.multiply(id));
        all.add(g0);
        all.add(g1);

        // generate proof for each entry in the vector
        for (int i = 0; i < num_candidates; i++) {

            if (encoding[i] == 0) {

                r[i] = Election.genRandom(q);
                t0[i] = g0.multiply(r[i]);  
                t0_p[i] = g1.multiply(r[i]);

                c1[i] = Election.genRandom(q);
                s1[i] = Election.genRandom(q);

                t1[i] = (e[i].subtract(g1)).multiply(c1[i].negate()).add(g0.multiply(s1[i]));
                t1_p[i] = z[i].multiply(c1[i].negate()).add(g1.multiply(s1[i]));

            } else {

                r[i] = Election.genRandom(q);
                t1[i] = g0.multiply(r[i]);
                t1_p[i] = g1.multiply(r[i]);

                c0[i] = Election.genRandom(q);
                s0[i] = Election.genRandom(q);

                t0[i] =  e[i].multiply(c0[i].negate()).add(g0.multiply(s0[i]));
                t0_p[i] = z[i].multiply(c0[i].negate()).add(g1.multiply(s0[i]));

            }

            all.add(e[i]);
            all.add(z[i]);
            all.add(t0[i]);
            all.add(t0_p[i]);
            all.add(t1[i]);
            all.add(t1_p[i]);

        }

        ECPoint[] arr = all.toArray(new ECPoint[all.size()]);
        ch = Election.hash(arr);

        for (int i = 0; i < num_candidates; i++) {

            if (encoding[i] == 0) {
                c0[i] = ch.subtract(c1[i]);
                s0[i] = r[i].add(x_enc[i].multiply(c0[i]));
            } else {
                c1[i] = ch.subtract(c0[i]);
                s1[i] = r[i].add(x_enc[i].multiply(c1[i]));
            }

            con1_t[i][0] = t0[i];
            con1_t[i][1] = t0_p[i];
            con1_t[i][2] = t1[i];
            con1_t[i][3] = t1_p[i];
            con1_c[i][0] = c0[i];
            con1_c[i][1] = c1[i];
            con1_s[i][0] = s0[i];
            con1_s[i][1] = s1[i];

        }

        

    }

    
    private boolean verifyCon1() {

        boolean hold = true;

        ECPoint t0;
        ECPoint t0_p;
        ECPoint t1;
        ECPoint t1_p;
        BigInteger c0;
        BigInteger c1;
        BigInteger s0;
        BigInteger s1;

        ECPoint[] e = super.ballot.getE();
        ECPoint[] z = super.ballot.getZ();

        for (int i = 0; i < num_candidates; i++) {
            
            t0 = con1_t[i][0];
            t0_p = con1_t[i][1];
            t1 = con1_t[i][2];
            t1_p = con1_t[i][3];
            c0 = con1_c[i][0];
            c1 = con1_c[i][1];
            s0 = con1_s[i][0];
            s1 = con1_s[i][1];

            ECPoint left0 = g0.multiply(s0); 
            ECPoint right0 = e[i].multiply(c0).add(t0);

            ECPoint left1 = g1.multiply(s0); 
            ECPoint right1 = z[i].multiply(c0).add(t0_p);

            ECPoint left2 = g0.multiply(s1); 
            ECPoint right2 = e[i].subtract(g1).multiply(c1).add(t1); 

            ECPoint left3 = g1.multiply(s1); 
            ECPoint right3 = z[i].multiply(c1).add(t1_p);

            if (!left0.equals(right0) || !left1.equals(right1) || !left2.equals(right2) || !left3.equals(right3)) {
                hold = false;
            }

        }

        return hold;

    }
    


    private void genCon2(int[] vote, BigInteger[] x_bal, int[] encoding, BigInteger[] x_enc) {
        
        // we only need to enumerate over the remaining non-eliminated choices
        ArrayList<Integer> remaining = new ArrayList<Integer>();
        for (int i = 1; i <= num_candidates; i++) {
            if (!elims.contains(i)) {
                remaining.add(i);
            }
        }

        int length = remaining.size();

        // initialise storage for published values
        // it is easier to split this one up into the zero case and non-zero cases
        this.con2_zeroes_t = new ECPoint[4];
        this.con2_zeroes_c = new BigInteger[1];
        this.con2_zeroes_s = new BigInteger[2];
        this.con2_rest_t = new ECPoint[length][6];
        this.con2_rest_c = new BigInteger[length][1];
        this.con2_rest_s = new BigInteger[length][3];

        ECPoint[] b = super.ballot.getB();
        ECPoint[] y = super.ballot.getY();
        ECPoint[] e = super.ballot.getE();
        ECPoint[] z = super.ballot.getZ();

        BigInteger id = BigInteger.valueOf(ballot.getIndex());

        // i : [1,n]
        BigInteger r0;
        BigInteger r1;
        ECPoint t0;
        ECPoint t0_p;
        ECPoint t1;
        ECPoint t1_p;
        BigInteger r_i0;
        BigInteger r_i1;
        BigInteger r_i2;
        ECPoint[] t_i0 = new ECPoint[length];
        ECPoint[] t_i0_p = new ECPoint[length];
        ECPoint[] t_i1 = new ECPoint[length];
        ECPoint[] t_i1_p = new ECPoint[length];
        ECPoint[] t_i2 = new ECPoint[length];
        ECPoint[] t_i2_p = new ECPoint[length];
        BigInteger c0;
        BigInteger[] ci = new BigInteger[length];
        BigInteger s0;
        BigInteger s1;
        BigInteger[] si0 = new BigInteger[length];
        BigInteger[] si1 = new BigInteger[length];
        BigInteger[] si2 = new BigInteger[length];

        ECPoint e_sum;
        ECPoint z_sum;

        ArrayList<ECPoint> all = new ArrayList<ECPoint>();
        all.add(g0);
        all.add(g1);
        all.add(g0.multiply(id));

        // case 1 : encoding is all zeroes
        boolean isZeroes = true;
        for (int i = 0; i < num_candidates; i++) {
            if (encoding[i] != 0) {
                isZeroes = false;
            }
        }
        if (isZeroes) {

            r0 = Election.genRandom(q);
            r1 = Election.genRandom(q);

            t0 = g0.multiply(r0);
            t0_p = g1.multiply(r0); 
            t1 = g0.multiply(r1); 
            t1_p = g1.multiply(r1);

            all.add(b[0]);
            all.add(y[0]);

            all.add(t0);
            all.add(t0_p);
            all.add(t1);
            all.add(t1_p);

            int idx = 0;
            for (Integer i : remaining) {

                ci[idx] = Election.genRandom(q);
                si0[idx] = Election.genRandom(q);
                si1[idx] = Election.genRandom(q);
                si2[idx] = Election.genRandom(q);

                t_i0[idx] = (b[0].subtract(g1.multiply(BigInteger.valueOf(i)))).multiply(ci[idx].negate()).add(g0.multiply(si0[idx]));
                t_i0_p[idx] = y[0].multiply(ci[idx].negate()).add(g1.multiply(si0[idx]));

                t_i1[idx] = (e[remaining.get(idx)-1].subtract(g1)).multiply(ci[idx].negate()).add(g0.multiply(si1[idx]));
                t_i1_p[idx] = (z[remaining.get(idx)-1]).multiply(ci[idx].negate()).add(g1.multiply(si1[idx]));

                e_sum = curve.getInfinity();
                z_sum = curve.getInfinity();

                for (int l = 1; l <= num_candidates; l++) {

                    if (l == i) {
                        continue;
                    }

                    e_sum = e_sum.add(e[l-1]); 
                    z_sum = z_sum.add(z[l-1]); 

                }

                t_i2[idx] = e_sum.multiply(ci[idx].negate()).add(g0.multiply(si2[idx]));
                t_i2_p[idx] = z_sum.multiply(ci[idx].negate()).add(g1.multiply(si2[idx]));

                all.add(e[idx]);
                all.add(z[idx]);
                all.add(t_i0[idx]);
                all.add(t_i0_p[idx]);
                all.add(t_i1[idx]);
                all.add(t_i1_p[idx]);
                all.add(t_i2[idx]);
                all.add(t_i2_p[idx]);

                con2_rest_t[idx][0] = t_i0[idx];
                con2_rest_t[idx][1] = t_i0_p[idx];
                con2_rest_t[idx][2] = t_i1[idx];
                con2_rest_t[idx][3] = t_i1_p[idx];
                con2_rest_t[idx][4] = t_i2[idx];
                con2_rest_t[idx][5] = t_i2_p[idx];
                con2_rest_c[idx][0] = ci[idx];
                con2_rest_s[idx][0] = si0[idx];
                con2_rest_s[idx][1] = si1[idx];
                con2_rest_s[idx][2] = si2[idx];

                idx++;

            }

            ECPoint[] arr = all.toArray(new ECPoint[all.size()]);
            BigInteger ch = Election.hash(arr);

            idx = 0;
            c0 = ch;
            for (Integer i : remaining) {
                c0 = c0.subtract(ci[idx]);
                idx++;
            }

            BigInteger x_sum = BigInteger.ZERO;
            for (int l = 1; l <= num_candidates; l++) {
                x_sum = x_sum.add(x_enc[l-1]);
            }

            s0 = r0.add(x_bal[0].multiply(c0));
            s1 = r1.add(x_sum.multiply(c0));

            con2_zeroes_t[0] = t0;
            con2_zeroes_t[1] = t0_p;
            con2_zeroes_t[2] = t1;
            con2_zeroes_t[3] = t1_p;
            con2_zeroes_c[0] = c0;
            con2_zeroes_s[0] = s0;
            con2_zeroes_s[1] = s1;

        } else {
            
            // other cases: there is an i : remaining that is encoded
            
            // first fake the case for an encoding of all zeroes
            c0 = Election.genRandom(q);
            s0 = Election.genRandom(q);
            s1 = Election.genRandom(q);

            t0 = b[0].multiply(c0.negate()).add(g0.multiply(s0));
            t0_p = y[0].multiply(c0.negate()).add(g1.multiply(s0));

            e_sum = curve.getInfinity();
            z_sum = curve.getInfinity();

            for (int l = 1; l <= num_candidates; l++) {

                e_sum = e_sum.add(e[l-1]);
                z_sum = z_sum.add(z[l-1]);

            }

            t1 = e_sum.multiply(c0.negate()).add(g0.multiply(s1));
            t1_p = z_sum.multiply(c0.negate()).add(g1.multiply(s1));

            all.add(b[0]);
            all.add(y[0]);

            all.add(t0);
            all.add(t0_p);
            all.add(t1);
            all.add(t1_p);

            con2_zeroes_t[0] = t0;
            con2_zeroes_t[1] = t0_p;
            con2_zeroes_t[2] = t1;
            con2_zeroes_t[3] = t1_p;
            con2_zeroes_c[0] = c0;
            con2_zeroes_s[0] = s0;
            con2_zeroes_s[1] = s1;
            


            r_i0 = Election.genRandom(q);
            r_i1 = Election.genRandom(q);
            r_i2 = Election.genRandom(q);

            int idx = 0;
            int marked_idx = (-1);
            for (Integer i : remaining) {
                
                if (encoding[i-1] == 1) {

                    marked_idx = idx;
                    t_i0[marked_idx] = g0.multiply(r_i0); 
                    t_i0_p[marked_idx] = g1.multiply(r_i0);
                    t_i1[marked_idx] = g0.multiply(r_i1);
                    t_i1_p[marked_idx] = g1.multiply(r_i1);
                    t_i2[marked_idx] = g0.multiply(r_i2);
                    t_i2_p[marked_idx] = g1.multiply(r_i2);

                } else {

                    ci[idx] = Election.genRandom(q);
                    si0[idx] = Election.genRandom(q);
                    si1[idx] = Election.genRandom(q);
                    si2[idx] = Election.genRandom(q);

                    t_i0[idx] = (b[0].subtract(g1.multiply(BigInteger.valueOf(i)))).multiply(ci[idx].negate()).add(g0.multiply(si0[idx]));
                    t_i0_p[idx] = y[0].multiply(ci[idx].negate()).add(g1.multiply(si0[idx]));

                    t_i1[idx] = (e[remaining.get(idx)-1].subtract(g1)).multiply(ci[idx].negate()).add(g0.multiply(si1[idx]));
                    t_i1_p[idx] = z[remaining.get(idx)-1].multiply(ci[idx].negate()).add(g1.multiply(si1[idx]));

                    e_sum = curve.getInfinity();
                    z_sum = curve.getInfinity();

                    for (int l = 1; l <= num_candidates; l++) {

                        if (l == i) {
                            continue;
                        }

                        e_sum = e_sum.add(e[l-1]);
                        z_sum = z_sum.add(z[l-1]);

                    }

                    t_i2[idx] = e_sum.multiply(ci[idx].negate()).add(g0.multiply(si2[idx]));
                    t_i2_p[idx] = z_sum.multiply(ci[idx].negate()).add(g1.multiply(si2[idx]));

                }

                all.add(e[idx]);
                all.add(z[idx]);
                all.add(t_i0[idx]);
                all.add(t_i0_p[idx]);
                all.add(t_i1[idx]);
                all.add(t_i1_p[idx]);
                all.add(t_i2[idx]);
                all.add(t_i2_p[idx]);

                idx++;

            }

            ECPoint[] arr = all.toArray(new ECPoint[all.size()]);
            BigInteger ch = Election.hash(arr);

            idx = 0;
            ci[marked_idx] = ch.subtract(c0);
            for (Integer i : remaining) {
                if (idx != marked_idx) {
                    ci[marked_idx] = ch.subtract(ci[idx]);
                }
                idx++;
            }

            BigInteger x_sum = BigInteger.ZERO;
            for (int l = 1; l <= num_candidates; l++) {
                if (l != remaining.get(marked_idx)) {
                    x_sum = x_sum.add(x_enc[l-1]);
                }
            }

            si0[marked_idx] = r_i0.add(x_bal[0].multiply(ci[marked_idx]));
            si1[marked_idx] = r_i1.add(x_enc[remaining.get(marked_idx)-1].multiply(ci[marked_idx]));
            si2[marked_idx] = r_i2.add(x_sum.multiply(ci[marked_idx]));

            idx = 0;
            for (Integer i : remaining) {
                con2_rest_t[idx][0] = t_i0[idx];
                con2_rest_t[idx][1] = t_i0_p[idx];
                con2_rest_t[idx][2] = t_i1[idx];
                con2_rest_t[idx][3] = t_i1_p[idx];
                con2_rest_t[idx][4] = t_i2[idx];
                con2_rest_t[idx][5] = t_i2_p[idx];
                con2_rest_c[idx][0] = ci[idx];
                con2_rest_s[idx][0] = si0[idx];
                con2_rest_s[idx][1] = si1[idx];
                con2_rest_s[idx][2] = si2[idx];
                idx++;
            }
            
        }
        

    }

    
    private boolean verifyCon2() {

        ArrayList<Integer> remaining = new ArrayList<Integer>();
        for (int i = 1; i <= num_candidates; i++) {
            if (!elims.contains(i)) {
                remaining.add(i);
            }
        }

        int length = remaining.size();

        ECPoint[] b = super.ballot.getB();
        ECPoint[] y = super.ballot.getY();
        ECPoint[] e = super.ballot.getE();
        ECPoint[] z = super.ballot.getZ();

        boolean hold = true;

        ECPoint t0;
        ECPoint t0_p;
        ECPoint t1;
        ECPoint t1_p;
        ECPoint[] t_i0 = new ECPoint[length];
        ECPoint[] t_i0_p = new ECPoint[length];
        ECPoint[] t_i1 = new ECPoint[length];
        ECPoint[] t_i1_p = new ECPoint[length];
        ECPoint[] t_i2 = new ECPoint[length];
        ECPoint[] t_i2_p = new ECPoint[length];
        BigInteger c0;
        BigInteger[] ci = new BigInteger[length];
        BigInteger s0;
        BigInteger s1;
        BigInteger[] si0 = new BigInteger[length];
        BigInteger[] si1 = new BigInteger[length];
        BigInteger[] si2 = new BigInteger[length];

        t0 = con2_zeroes_t[0];
        t0_p = con2_zeroes_t[1];
        t1 = con2_zeroes_t[2];
        t1_p = con2_zeroes_t[3];
        c0 = con2_zeroes_c[0];
        s0 = con2_zeroes_s[0];
        s1 = con2_zeroes_s[1];

        ECPoint left0 = g0.multiply(s0);
        ECPoint right0 = b[0].multiply(c0).add(t0); 
        
        ECPoint left1 = g1.multiply(s0);
        ECPoint right1 = y[0].multiply(c0).add(t0_p); 

        ECPoint e_sum = curve.getInfinity();
        ECPoint z_sum = curve.getInfinity();
        for (int i = 0; i < num_candidates; i++) {
            e_sum = e_sum.add(e[i]);
            z_sum = z_sum.add(z[i]);
        }

        ECPoint left2 = g0.multiply(s1);
        ECPoint right2 = e_sum.multiply(c0).add(t1); 

        ECPoint left3 = g1.multiply(s1);
        ECPoint right3 = z_sum.multiply(c0).add(t1_p); 

        if (!left0.equals(right0) || !left1.equals(right1) || !left2.equals(right2) || !left3.equals(right3)) {
            hold = false;
        }        

        
        int idx = 0;
        for (Integer i : remaining) {

            t_i0[idx] = con2_rest_t[idx][0];
            t_i0_p[idx] = con2_rest_t[idx][1];
            t_i1[idx] = con2_rest_t[idx][2];
            t_i1_p[idx] = con2_rest_t[idx][3];
            t_i2[idx] = con2_rest_t[idx][4];
            t_i2_p[idx] = con2_rest_t[idx][5];
            ci[idx] = con2_rest_c[idx][0];
            si0[idx] = con2_rest_s[idx][0];
            si1[idx] = con2_rest_s[idx][1];
            si2[idx] = con2_rest_s[idx][2];

            e_sum = curve.getInfinity();
            z_sum = curve.getInfinity();

            for (int l = 1; l <= num_candidates; l++) {

                if (l == i) {
                    continue;
                }

                e_sum = e_sum.add(e[l-1]);
                z_sum = z_sum.add(z[l-1]);

            }

            ECPoint left4 = g0.multiply(si0[idx]);
            ECPoint right4 = (b[0].subtract(g1.multiply(BigInteger.valueOf(i)))).multiply(ci[idx]).add(t_i0[idx]); 

            ECPoint left5 = g0.multiply(si1[idx]);
            ECPoint right5 = (e[remaining.get(idx)-1].subtract(g1)).multiply(ci[idx]).add(t_i1[idx]); 

            ECPoint left6 = g0.multiply(si2[idx]);
            ECPoint right6 = e_sum.multiply(ci[idx]).add(t_i2[idx]);  

            ECPoint left7 = g1.multiply(si0[idx]);
            ECPoint right7 = y[0].multiply(ci[idx]).add(t_i0_p[idx]); 

            ECPoint left8 = g1.multiply(si1[idx]);
            ECPoint right8 = z[remaining.get(idx)-1].multiply(ci[idx]).add(t_i1_p[idx]); 

            ECPoint left9 = g1.multiply(si2[idx]);
            ECPoint right9 = z_sum.multiply(ci[idx]).add(t_i2_p[idx]); 

            if (!left4.equals(right4) || !left5.equals(right5) || !left6.equals(right6) || !left7.equals(right7) || !left8.equals(right8) || !left9.equals(right9)) {
                hold = false;
            }

            idx++;

        }
        
        return hold;

    }
    

}