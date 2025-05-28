package camel;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * This class represents the bulletin board.
 */
public class BulletinBoard {

    // parameters for the election
    private final int num_candidates;
    private final ECPoint g0;
    private final ECPoint g1;
    ECCurve.Fp curve;

    // tally of votes and randomness for each round
    private ArrayList<int[]> t;
    private ArrayList<BigInteger[]> s;

    // storage of all indexed data per round of the tallying phase
    public ArrayList<HashMap<Integer,BulletinBoardData>> datas;

    public BulletinBoard(int num_candidates, ECPoint g0, ECPoint g1, ECCurve.Fp curve) {

        this.num_candidates = num_candidates;

        this.g0 = g0;
        this.g1 = g1;
        this.curve = curve;

        this.t = new ArrayList<int[]>();
        this.s = new ArrayList<BigInteger[]>();

        this.datas = new ArrayList<HashMap<Integer,BulletinBoardData>>();

        // initialise t and s for each round
        // and initialise the storage for the tallying ballots as well
        for (int i = 0; i < num_candidates - 1; i++) {
            this.t.add(i, new int[num_candidates]);
            BigInteger[] zeroes = new BigInteger[num_candidates];
            for (int j = 0; j < num_candidates; j++) {
                zeroes[j] = BigInteger.ZERO;
            }
            this.s.add(i, zeroes);
            datas.add(new HashMap<Integer,BulletinBoardData>());
        }

    }

    // get the tally for a round
    public int[] getTallyAtRound(int round) {
        return this.t.get(round);
    }

    // get the sum of randomness for a round
    public BigInteger[] getRandomnessAtRound(int round) {
        return this.s.get(round);
    }

    // add to the tally for a round
    public void addToTallyAtRound(int round, int[] encoding) {
        for (int i = 0; i < num_candidates; i++) {
            this.t.get(round)[i] += encoding[i];
        }
    }

    // add to the randomness for a round
    public void addToEncodingRandomnessAtRound(int round, BigInteger[] randomness) {
        for (int i = 0; i < num_candidates; i++) {
            this.s.get(round)[i] = s.get(round)[i].add(randomness[i]);
        }
    }

    public void addToBulletinDataAtRound(int round, BulletinBoardData data) { 
        this.datas.get(round).put(data.getBallot().getIndex(), data);
    }

    public HashMap<Integer, BulletinBoardData> getBulletinDataAtRound(int round) {
        return this.datas.get(round);
    }

    public void removeFromBulletinDataAtRound(int round, int index) {
        this.datas.get(round).remove(index);
    }

    // display the tally list in a neat format for a round
    public void printTallyAtRound(int round) {

        int[] tally = t.get(round);

        System.out.print("(");
        for (int i = 0; i < num_candidates; i++) {

            if (i == num_candidates - 1) {
                System.out.print(tally[i]);
            } else {
                System.out.print(tally[i] + ", ");
            }

        }
        System.out.println(")");

    }

    // display the tally list in a neat format for all rounds
    public void printTallies() {
        
        for (int i = 0; i < num_candidates - 1; i++) {
            printTallyAtRound(i);
        }

    }

    // verify the tallies at a round
    public boolean verifyTalliesAtRound(int round) {

        boolean hold = true;

        HashMap<Integer, BulletinBoardData> data = this.getBulletinDataAtRound(round);

        int[] tally_round = this.getTallyAtRound(round);
        BigInteger[] randomness_round = this.getRandomnessAtRound(round);

        ECPoint[] e_sum = new ECPoint[num_candidates];
        ECPoint[] z_sum = new ECPoint[num_candidates];

        for (int i = 0; i < num_candidates; i++) {

            e_sum[i] = curve.getInfinity();
            z_sum[i] = curve.getInfinity();

            for (int k : data.keySet()) {

                Ballot ballot = data.get(k).getBallot();
                ECPoint[] e = ballot.getE();
                ECPoint[] z = ballot.getZ();

                e_sum[i] = e_sum[i].add(e[i]);
                z_sum[i] = z_sum[i].add(z[i]);


            }

            ECPoint left0 = e_sum[i];
            ECPoint right0 = g0.multiply(randomness_round[i]).add(g1.multiply(BigInteger.valueOf(t.get(round)[i])));

            ECPoint left1 = z_sum[i];
            ECPoint right1 = g1.multiply(s.get(round)[i]);

            if (!left0.equals(right0) || !left1.equals(right1)) {
                hold = false;
            }

        }

        return hold;

    }

}
