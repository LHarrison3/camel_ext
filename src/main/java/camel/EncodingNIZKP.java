package camel;

import java.util.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class EncodingNIZKP extends NIZKP {

    // this NIZKP has two conjunctions
    // we store all the published values per conjunction
    private BigInteger[][] con1;
    private BigInteger[] con2_zeroes;
    private BigInteger[][] con2_rest;

    private ArrayList<Integer> elims;

    public EncodingNIZKP(BigInteger p, BigInteger q, BigInteger g0, BigInteger g1, int num_candidates, Ballot ballot, int[] vote, int[] encoding, BigInteger[] x_bal, BigInteger[] x_enc, ArrayList<Integer> elims) {

        super(p, q, g0, g1, num_candidates, ballot);

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
        this.con1 = new BigInteger[num_candidates][8];

        BigInteger[] e = ballot.getE();
        BigInteger[] z = ballot.getZ();

        BigInteger id = BigInteger.valueOf(ballot.getIndex());

        BigInteger[] r = new BigInteger[num_candidates];
        BigInteger[] t0 = new BigInteger[num_candidates];
        BigInteger[] t0_p = new BigInteger[num_candidates];
        BigInteger[] t1 = new BigInteger[num_candidates];
        BigInteger[] t1_p = new BigInteger[num_candidates]; 
        BigInteger[] c0 = new BigInteger[num_candidates];
        BigInteger[] c1 = new BigInteger[num_candidates];
        BigInteger[] s0 = new BigInteger[num_candidates];
        BigInteger[] s1 = new BigInteger[num_candidates];

        BigInteger ch;
        ArrayList<BigInteger> all = new ArrayList<BigInteger>();
        all.add(id);
        all.add(g0);
        all.add(g1);

        // generate proof for each entry in the vector
        for (int i = 0; i < num_candidates; i++) {

            if (encoding[i] == 0) {

                r[i] = super.genRandomQ();
                t0[i] = g0.modPow(r[i], p);
                t0_p[i] = g1.modPow(r[i], p);

                c1[i] = super.genRandomQ();
                s1[i] = super.genRandomQ();

                t1[i] = e[i].multiply(g1.modInverse(p)).mod(p).modPow(c1[i], p).modInverse(p).multiply(g0.modPow(s1[i], p)).mod(p);
                t1_p[i] = z[i].modPow(c1[i], p).modInverse(p).multiply(g1.modPow(s1[i], p)).mod(p);


            } else {

                r[i] = super.genRandomQ();
                t1[i] = g0.modPow(r[i], p);
                t1_p[i] = g1.modPow(r[i], p);

                c0[i] = super.genRandomQ();
                s0[i] = super.genRandomQ();

                t0[i] = e[i].modPow(c0[i], p).modInverse(p).multiply(g0.modPow(s0[i], p)).mod(p);
                t0_p[i] = z[i].modPow(c0[i], p).modInverse(p).multiply(g1.modPow(s0[i], p)).mod(p);

            }

            all.add(e[i]);
            all.add(z[i]);
            all.add(t0[i]);
            all.add(t0_p[i]);
            all.add(t1[i]);
            all.add(t1_p[i]);

        }

        BigInteger[] arr = all.toArray(new BigInteger[all.size()]);
        ch = Election.hash(arr);

        for (int i = 0; i < num_candidates; i++) {

            if (encoding[i] == 0) {
                c0[i] = ch.subtract(c1[i]).mod(q);
                s0[i] = r[i].add(x_enc[i].multiply(c0[i]).mod(q)).mod(q);
            } else {
                c1[i] = ch.subtract(c0[i]).mod(q);
                s1[i] = r[i].add(x_enc[i].multiply(c1[i]).mod(q)).mod(q);
            }

            con1[i][0] = t0[i];
            con1[i][1] = t0_p[i];
            con1[i][2] = t1[i];
            con1[i][3] = t1_p[i];
            con1[i][4] = c0[i];
            con1[i][5] = c1[i];
            con1[i][6] = s0[i];
            con1[i][7] = s1[i];

        }

    }

    private boolean verifyCon1() {

        boolean hold = true;

        BigInteger t0;
        BigInteger t0_p;
        BigInteger t1;
        BigInteger t1_p;
        BigInteger c0;
        BigInteger c1;
        BigInteger s0;
        BigInteger s1;

        BigInteger[] e = super.ballot.getE();
        BigInteger[] z = super.ballot.getZ();

        for (int i = 0; i < num_candidates; i++) {
            
            t0 = con1[i][0];
            t0_p = con1[i][1];
            t1 = con1[i][2];
            t1_p = con1[i][3];
            c0 = con1[i][4];
            c1 = con1[i][5];
            s0 = con1[i][6];
            s1 = con1[i][7];

            BigInteger left0 = g0.modPow(s0, p);
            BigInteger right0 = e[i].modPow(c0, p).multiply(t0).mod(p);

            BigInteger left1 = g1.modPow(s0, p);
            BigInteger right1 = z[i].modPow(c0, p).multiply(t0_p).mod(p);

            BigInteger left2 = g0.modPow(s1, p);
            BigInteger right2 = e[i].multiply(g1.modInverse(p)).mod(p).modPow(c1, p).multiply(t1).mod(p);

            BigInteger left3 = g1.modPow(s1, p);
            BigInteger right3 = z[i].modPow(c1, p).multiply(t1_p).mod(p);

            if (left0.compareTo(right0) != 0 || left1.compareTo(right1) != 0 || left2.compareTo(right2) != 0 || left3.compareTo(right3) != 0) {
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
        this.con2_zeroes = new BigInteger[7];
        this.con2_rest = new BigInteger[length][10];

        BigInteger[] b = super.ballot.getB();
        BigInteger[] y = super.ballot.getY();
        BigInteger[] e = super.ballot.getE();
        BigInteger[] z = super.ballot.getZ();

        BigInteger id = BigInteger.valueOf(ballot.getIndex());

        // i : [1,n]
        BigInteger r0;
        BigInteger r1;
        BigInteger t0;
        BigInteger t0_p;
        BigInteger t1;
        BigInteger t1_p;
        BigInteger r_i0;
        BigInteger r_i1;
        BigInteger r_i2;
        BigInteger[] t_i0 = new BigInteger[length];
        BigInteger[] t_i0_p = new BigInteger[length];
        BigInteger[] t_i1 = new BigInteger[length];
        BigInteger[] t_i1_p = new BigInteger[length];
        BigInteger[] t_i2 = new BigInteger[length];
        BigInteger[] t_i2_p = new BigInteger[length];
        BigInteger c0;
        BigInteger[] ci = new BigInteger[length];
        BigInteger s0;
        BigInteger s1;
        BigInteger[] si0 = new BigInteger[length];
        BigInteger[] si1 = new BigInteger[length];
        BigInteger[] si2 = new BigInteger[length];

        BigInteger e_prod;
        BigInteger z_prod;

        ArrayList<BigInteger> all = new ArrayList<BigInteger>();
        all.add(g0);
        all.add(g1);
        all.add(id);

        // case 1 : encoding is all zeroes
        boolean isZeroes = true;
        for (int i = 0; i < num_candidates; i++) {
            if (encoding[i] != 0) {
                isZeroes = false;
            }
        }
        if (isZeroes) {

            r0 = super.genRandomQ();
            r1 = super.genRandomQ();

            t0 = g0.modPow(r0, p);
            t0_p = g1.modPow(r0, p);
            t1 = g0.modPow(r1, p);
            t1_p = g1.modPow(r1, p);

            all.add(b[0]);
            all.add(y[0]);

            all.add(t0);
            all.add(t0_p);
            all.add(t1);
            all.add(t1_p);

            int idx = 0;
            for (Integer i : remaining) {

                ci[idx] = super.genRandomQ();
                si0[idx] = super.genRandomQ();
                si1[idx] = super.genRandomQ();
                si2[idx] = super.genRandomQ();

                t_i0[idx] = b[0].multiply(g1.modPow(BigInteger.valueOf(i), p).modInverse(p)).mod(p).modPow(ci[idx], p).modInverse(p).multiply(g0.modPow(si0[idx], p)).mod(p);
                t_i0_p[idx] = y[0].modPow(ci[idx], p).modInverse(p). multiply(g1.modPow(si0[idx], p)).mod(p);

                t_i1[idx] = e[remaining.get(idx)-1].multiply(g1.modInverse(p)).mod(p).modPow(ci[idx], p).modInverse(p).multiply(g0.modPow(si1[idx], p)).mod(p);
                t_i1_p[idx] = z[remaining.get(idx)-1].modPow(ci[idx], p).modInverse(p).multiply(g1.modPow(si1[idx], p)).mod(p);

                e_prod = BigInteger.ONE;
                z_prod = BigInteger.ONE;

                for (int l = 1; l <= num_candidates; l++) {

                    if (l == i) {
                        continue;
                    }

                    e_prod = e_prod.multiply(e[l-1]).mod(p);
                    z_prod = z_prod.multiply(z[l-1]).mod(p);

                }

                t_i2[idx] = e_prod.modPow(ci[idx], p).modInverse(p).multiply(g0.modPow(si2[idx], p)).mod(p);
                t_i2_p[idx] = z_prod.modPow(ci[idx], p).modInverse(p).multiply(g1.modPow(si2[idx], p)).mod(p);

                all.add(e[idx]);
                all.add(z[idx]);
                all.add(t_i0[idx]);
                all.add(t_i0_p[idx]);
                all.add(t_i1[idx]);
                all.add(t_i1_p[idx]);
                all.add(t_i2[idx]);
                all.add(t_i2_p[idx]);

                con2_rest[idx][0] = t_i0[idx];
                con2_rest[idx][1] = t_i0_p[idx];
                con2_rest[idx][2] = t_i1[idx];
                con2_rest[idx][3] = t_i1_p[idx];
                con2_rest[idx][4] = t_i2[idx];
                con2_rest[idx][5] = t_i2_p[idx];
                con2_rest[idx][6] = ci[idx];
                con2_rest[idx][7] = si0[idx];
                con2_rest[idx][8] = si1[idx];
                con2_rest[idx][9] = si2[idx];

                idx++;

            }

            BigInteger[] arr = all.toArray(new BigInteger[all.size()]);
            BigInteger ch = Election.hash(arr);

            idx = 0;
            c0 = ch;
            for (Integer i : remaining) {
                c0 = c0.subtract(ci[idx]).mod(q);
                idx++;
            }

            BigInteger x_sum = BigInteger.ZERO;
            for (int l = 1; l <= num_candidates; l++) {
                x_sum = x_sum.add(x_enc[l-1]).mod(q);
            }

            s0 = r0.add(x_bal[0].multiply(c0).mod(q)).mod(q);
            s1 = r1.add(x_sum.multiply(c0).mod(q)).mod(q);

            con2_zeroes[0] = t0;
            con2_zeroes[1] = t0_p;
            con2_zeroes[2] = t1;
            con2_zeroes[3] = t1_p;
            con2_zeroes[4] = c0;
            con2_zeroes[5] = s0;
            con2_zeroes[6] = s1;

        } else {

            
            // other cases: there is an i : remaining that is encoded
            
            // first fake the case for an encoding of all zeroes
            c0 = super.genRandomQ();
            s0 = super.genRandomQ();
            s1 = super.genRandomQ();

            t0 = b[0].modPow(c0, p).modInverse(p).multiply(g0.modPow(s0, p)).mod(p);
            t0_p = y[0].modPow(c0, p).modInverse(p).multiply(g1.modPow(s0, p)).mod(p);

            e_prod = BigInteger.ONE;
            z_prod = BigInteger.ONE;

            for (int l = 1; l <= num_candidates; l++) {

                e_prod = e_prod.multiply(e[l-1]).mod(p);
                z_prod = z_prod.multiply(z[l-1]).mod(p);

            }

            t1 = e_prod.modPow(c0, p).modInverse(p).multiply(g0.modPow(s1, p)).mod(p);
            t1_p = z_prod.modPow(c0, p).modInverse(p).multiply(g1.modPow(s1, p)).mod(p);

            all.add(b[0]);
            all.add(y[0]);

            all.add(t0);
            all.add(t0_p);
            all.add(t1);
            all.add(t1_p);

            con2_zeroes[0] = t0;
            con2_zeroes[1] = t0_p;
            con2_zeroes[2] = t1;
            con2_zeroes[3] = t1_p;
            con2_zeroes[4] = c0;
            con2_zeroes[5] = s0;
            con2_zeroes[6] = s1;
            


            r_i0 = super.genRandomQ();
            r_i1 = super.genRandomQ();
            r_i2 = super.genRandomQ();

            int idx = 0;
            int marked_idx = (-1);
            for (Integer i : remaining) {
                
                if (encoding[i-1] == 1) {

                    marked_idx = idx;
                    t_i0[marked_idx] = g0.modPow(r_i0, p);
                    t_i0_p[marked_idx] = g1.modPow(r_i0, p);
                    t_i1[marked_idx] = g0.modPow(r_i1, p);
                    t_i1_p[marked_idx] = g1.modPow(r_i1, p);
                    t_i2[marked_idx] = g0.modPow(r_i2, p);
                    t_i2_p[marked_idx] = g1.modPow(r_i2, p);

                } else {

                    ci[idx] = super.genRandomQ();
                    si0[idx] = super.genRandomQ();
                    si1[idx] = super.genRandomQ();
                    si2[idx] = super.genRandomQ();

                    t_i0[idx] = b[0].multiply(g1.modPow(BigInteger.valueOf(i), p).modInverse(p)).mod(p).modPow(ci[idx], p).modInverse(p).multiply(g0.modPow(si0[idx], p)).mod(p);
                    t_i0_p[idx] = y[0].modPow(ci[idx], p).modInverse(p). multiply(g1.modPow(si0[idx], p)).mod(p);

                    t_i1[idx] = e[remaining.get(idx)-1].multiply(g1.modInverse(p)).mod(p).modPow(ci[idx], p).modInverse(p).multiply(g0.modPow(si1[idx], p)).mod(p);
                    t_i1_p[idx] = z[remaining.get(idx)-1].modPow(ci[idx], p).modInverse(p).multiply(g1.modPow(si1[idx], p)).mod(p);

                    e_prod = BigInteger.ONE;
                    z_prod = BigInteger.ONE;

                    for (int l = 1; l <= num_candidates; l++) {

                        if (l == i) {
                            continue;
                        }

                        e_prod = e_prod.multiply(e[l-1]).mod(p);
                        z_prod = z_prod.multiply(z[l-1]).mod(p);

                    }

                    t_i2[idx] = e_prod.modPow(ci[idx], p).modInverse(p).multiply(g0.modPow(si2[idx], p)).mod(p);
                    t_i2_p[idx] = z_prod.modPow(ci[idx], p).modInverse(p).multiply(g1.modPow(si2[idx], p)).mod(p);

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

            BigInteger[] arr = all.toArray(new BigInteger[all.size()]);
            BigInteger ch = Election.hash(arr);

            idx = 0;
            ci[marked_idx] = ch.subtract(c0).mod(q);
            for (Integer i : remaining) {
                if (idx != marked_idx) {
                    ci[marked_idx] = ch.subtract(ci[idx]).mod(q);
                }
                idx++;
            }

            BigInteger x_sum = BigInteger.ZERO;
            for (int l = 1; l <= num_candidates; l++) {
                if (l != remaining.get(marked_idx)) {
                    x_sum = x_sum.add(x_enc[l-1]).mod(q);
                }
            }

            si0[marked_idx] = r_i0.add(x_bal[0].multiply(ci[marked_idx]).mod(q)).mod(q);
            si1[marked_idx] = r_i1.add(x_enc[remaining.get(marked_idx)-1].multiply(ci[marked_idx])).mod(q);
            si2[marked_idx] = r_i2.add(x_sum.multiply(ci[marked_idx]).mod(q)).mod(q);

            idx = 0;
            for (Integer i : remaining) {
                con2_rest[idx][0] = t_i0[idx];
                con2_rest[idx][1] = t_i0_p[idx];
                con2_rest[idx][2] = t_i1[idx];
                con2_rest[idx][3] = t_i1_p[idx];
                con2_rest[idx][4] = t_i2[idx];
                con2_rest[idx][5] = t_i2_p[idx];
                con2_rest[idx][6] = ci[idx];
                con2_rest[idx][7] = si0[idx];
                con2_rest[idx][8] = si1[idx];
                con2_rest[idx][9] = si2[idx];
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

        BigInteger[] b = super.ballot.getB();
        BigInteger[] y = super.ballot.getY();
        BigInteger[] e = super.ballot.getE();
        BigInteger[] z = super.ballot.getZ();

        boolean hold = true;

        BigInteger t0;
        BigInteger t0_p;
        BigInteger t1;
        BigInteger t1_p;
        BigInteger[] t_i0 = new BigInteger[length];
        BigInteger[] t_i0_p = new BigInteger[length];
        BigInteger[] t_i1 = new BigInteger[length];
        BigInteger[] t_i1_p = new BigInteger[length];
        BigInteger[] t_i2 = new BigInteger[length];
        BigInteger[] t_i2_p = new BigInteger[length];
        BigInteger c0;
        BigInteger[] ci = new BigInteger[length];
        BigInteger s0;
        BigInteger s1;
        BigInteger[] si0 = new BigInteger[length];
        BigInteger[] si1 = new BigInteger[length];
        BigInteger[] si2 = new BigInteger[length];

        t0 = con2_zeroes[0];
        t0_p = con2_zeroes[1];
        t1 = con2_zeroes[2];
        t1_p = con2_zeroes[3];
        c0 = con2_zeroes[4];
        s0 = con2_zeroes[5];
        s1 = con2_zeroes[6];

        BigInteger left0 = g0.modPow(s0, p);
        BigInteger right0 = b[0].modPow(c0, p).multiply(t0).mod(p);
        
        BigInteger left1 = g1.modPow(s0, p);
        BigInteger right1 = y[0].modPow(c0, p).multiply(t0_p).mod(p);

        BigInteger e_prod = BigInteger.ONE;
        BigInteger z_prod = BigInteger.ONE;
        for (int i = 0; i < num_candidates; i++) {
            e_prod = e_prod.multiply(e[i]).mod(p);
            z_prod = z_prod.multiply(z[i]).mod(p);
        }

        BigInteger left2 = g0.modPow(s1, p);
        BigInteger right2 = e_prod.modPow(c0, p).multiply(t1).mod(p);

        BigInteger left3 = g1.modPow(s1, p);
        BigInteger right3 = z_prod.modPow(c0, p).multiply(t1_p).mod(p);

        if (left0.compareTo(right0) != 0 || left1.compareTo(right1) != 0 || left2.compareTo(right2) != 0 || left3.compareTo(right3) != 0) {
            hold = false;
        }        

        
        int idx = 0;
        for (Integer i : remaining) {

            t_i0[idx] = con2_rest[idx][0];
            t_i0_p[idx] = con2_rest[idx][1];
            t_i1[idx] = con2_rest[idx][2];
            t_i1_p[idx] = con2_rest[idx][3];
            t_i2[idx] = con2_rest[idx][4];
            t_i2_p[idx] = con2_rest[idx][5];
            ci[idx] = con2_rest[idx][6];
            si0[idx] = con2_rest[idx][7];
            si1[idx] = con2_rest[idx][8];
            si2[idx] = con2_rest[idx][9];

            e_prod = BigInteger.ONE;
            z_prod = BigInteger.ONE;

            for (int l = 1; l <= num_candidates; l++) {

                if (l == i) {
                    continue;
                }

                e_prod = e_prod.multiply(e[l-1]).mod(p);
                z_prod = z_prod.multiply(z[l-1]).mod(p);

            }

            BigInteger left4 = g0.modPow(si0[idx], p);
            BigInteger right4 = b[0].multiply(g1.modPow(BigInteger.valueOf(i), p).modInverse(p)).mod(p).modPow(ci[idx], p).multiply(t_i0[idx]).mod(p);

            BigInteger left5 = g0.modPow(si1[idx], p);
            BigInteger right5 = e[remaining.get(idx)-1].multiply(g1.modInverse(p)).mod(p).modPow(ci[idx], p).multiply(t_i1[idx]).mod(p);

            BigInteger left6 = g0.modPow(si2[idx], p);
            BigInteger right6 = e_prod.modPow(ci[idx], p).multiply(t_i2[idx]).mod(p);

            BigInteger left7 = g1.modPow(si0[idx], p);
            BigInteger right7 = y[0].modPow(ci[idx], p).multiply(t_i0_p[idx]).mod(p);

            BigInteger left8 = g1.modPow(si1[idx], p);
            BigInteger right8 = z[remaining.get(idx)-1].modPow(ci[idx], p).multiply(t_i1_p[idx]).mod(p);

            BigInteger left9 = g1.modPow(si2[idx], p);
            BigInteger right9 = z_prod.modPow(ci[idx], p).multiply(t_i2_p[idx]).mod(p);

            if (left4.compareTo(right4) != 0  || left5.compareTo(right5) != 0 || left6.compareTo(right6) != 0 || left7.compareTo(right7) != 0 || left8.compareTo(right8) != 0 || left9.compareTo(right9) != 0) {
                hold = false;
            }

            idx++;

        }
        
        return hold;

    }

}