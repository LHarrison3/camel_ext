package camel;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.math.BigInteger;

/**
 * This class represents the bulletin board.
 */
public class BulletinBoard {

    // parameters for the election
    private final int num_candidates;
    private final BigInteger g0;
    private final BigInteger g1;
    private final BigInteger p;
    private final BigInteger q;

    // tally of votes and randomness for each round
    private ArrayList<int[]> t;
    private ArrayList<BigInteger[]> s;

    // storage of all ballots over all rounds of the tallying phase 
    private ArrayList<ArrayList<Ballot>> ballots;

    // storage of all NIZKPs
    private ArrayList<ArrayList<NIZKP>> bal_nizkps;
    private ArrayList<ArrayList<NIZKP>> enc_nizkps;


    public BulletinBoard(int num_candidates, BigInteger g0, BigInteger g1, BigInteger p, BigInteger q) {

        this.num_candidates = num_candidates;

        this.g0 = g0;
        this.g1 = g1;
        this.p = p;
        this.q = q;

        this.t = new ArrayList<int[]>();
        this.s = new ArrayList<BigInteger[]>();

        this.ballots = new ArrayList<ArrayList<Ballot>>();
        this.bal_nizkps = new ArrayList<ArrayList<NIZKP>>();
        this.enc_nizkps = new ArrayList<ArrayList<NIZKP>>();

        // initialise t and s for each round
        // and initialise the storage for the tallying ballots as well
        for (int i = 0; i < num_candidates - 1; i++) {
            this.t.add(i, new int[num_candidates]);
            BigInteger[] zeroes = new BigInteger[num_candidates];
            for (int j = 0; j < num_candidates; j++) {
                zeroes[j] = BigInteger.ZERO;
            }
            this.s.add(i, zeroes);
            ballots.add(new ArrayList<Ballot>());
            bal_nizkps.add(new ArrayList<NIZKP>());
            this.enc_nizkps.add(new ArrayList<NIZKP>());
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
            this.s.get(round)[i] = s.get(round)[i].add(randomness[i]).mod(p);
        }
    }

    // add a ballot to the list of all ballots over all rounds
    public void addBallot(int round, Ballot ballot) {
        this.ballots.get(round).add(ballot);
    }

    public ArrayList<Ballot> getBallotsAtRound(int round) {
        return this.ballots.get(round);
    }

    // add a nizkp to the list of all nizkps over all rounds
    public void addBallotNIZKP(int round, NIZKP bal_nizkp) {
        this.bal_nizkps.get(round).add(bal_nizkp);
    }

    public void addEncodingNIZKP(int round, NIZKP enc_nizkp) {
        this.enc_nizkps.get(round).add(enc_nizkp);
    }

    public ArrayList<NIZKP> getBallotNIZKPsAtRound(int round) {
        return this.bal_nizkps.get(round);
    }

    public ArrayList<NIZKP> getEncodingNIZKPsAtRound(int round) {
        return this.enc_nizkps.get(round);
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

        ArrayList<Ballot> ballots_round = this.getBallotsAtRound(round);
        int[] tally_round = this.getTallyAtRound(round);
        BigInteger[] randomness_round = this.getRandomnessAtRound(round);

        BigInteger[] e_prod = new BigInteger[num_candidates];
        BigInteger[] z_prod = new BigInteger[num_candidates];

        for (int i = 0; i < num_candidates; i++) {

            e_prod[i] = BigInteger.ONE;
            z_prod[i] = BigInteger.ONE;

            for (int k = 0; k < ballots_round.size(); k++) {

                Ballot ballot = ballots_round.get(k);
                BigInteger[] e = ballot.getE();
                BigInteger[] z = ballot.getZ();

                e_prod[i] = e_prod[i].multiply(e[i]).mod(p);
                z_prod[i] = z_prod[i].multiply(z[i]).mod(p);

            }

            BigInteger left0 = e_prod[i];
            BigInteger right0 = g0.modPow(randomness_round[i].mod(q),p).multiply(g1.modPow(BigInteger.valueOf(tally_round[i]).mod(q),p)).mod(p);

            BigInteger left1 = z_prod[i];
            BigInteger right1 = g1.modPow(randomness_round[i].mod(q),p);

            if (left0.compareTo(right0) != 0 || left1.compareTo(right1) != 0) {
                hold = false;
            }

        }

        return hold;

    }

}
