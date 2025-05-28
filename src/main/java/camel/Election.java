package camel;

import java.util.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECFieldElement;

/**
 * This class runs an entire election in Camel (including the tallying rounds).
 */
public class Election {

    // parameters concerning candidates
    public final int num_candidates;
    protected final int[] candidates;

    // other information about the election
    String election_name;
    String election_date;

    // cryptographic parameters
    public final ECCurve.Fp curve;
    public final ECPoint g0;
    public final ECPoint g1;
    public final BigInteger q;
    private static final String hash_alg = "SHA-256";

    // ID for ballots
    private int ballot_index = 0;

    // storage on the voting server for plaintext votes and randomnesses during rounds of the tallying phase
    private ArrayList<HashMap<Integer,ElectionData>> election_datas;
    
    // the degree by which ZKPs should be computed
    // by default all ZKPs are computed
    private ZKPLevel level = ZKPLevel.COMPUTE_ALL_ZKPS;

    // for convenience we store the eliminated choices at each round as well
    private ArrayList<Integer> elims;

    // the bulletin board
    public BulletinBoard bulletin_board;

    // create an election
    public Election(String election_name, String election_date, int num_candidates) {

        this.election_name = election_name;
        this.election_date = election_date;

        this.num_candidates = num_candidates;
        this.candidates = new int[num_candidates];

        // assign identifiers to the candidates
        for (int i = 0; i < this.candidates.length; i++) {
            this.candidates[i] = i + 1;
        }

        // storage of plaintext votes and randomnesses for the tallying phase
        // we initialise each round here
        this.election_datas = new ArrayList<HashMap<Integer,ElectionData>>();
        this.elims = new ArrayList<Integer>();

        for (int i = 0; i < num_candidates - 1; i++) {
            election_datas.add(new HashMap<Integer,ElectionData>());
        }

        // set up NIST P-256 curve

        X9ECParameters nist = NISTNamedCurves.getByName("P-256");
        this.curve = (ECCurve.Fp) nist.getCurve();
        this.g0 = (ECPoint) nist.getG();

        this.q = curve.getQ();

        // find a second generator

        ECPoint g1temp = curve.getInfinity();
        String election_string = election_name + election_date;
        for (int i = 0; i < candidates.length; i++) {
            election_string += i;
        }

        BigInteger counter = BigInteger.ZERO;
        while (true) {

            try {

                MessageDigest md = MessageDigest.getInstance(hash_alg);
                md.update(g0.getEncoded(false));
                md.update(election_string.getBytes());
                md.update(counter.toByteArray());

                byte[] result = md.digest();

                BigInteger h = new BigInteger(1, result);
                g1temp = this.hashToCurve(h.mod(q));

                // check if the result is non-identity (for NIST P-256)
                if (!g1temp.equals(curve.getInfinity()) && !g1temp.equals(g0)) {
                    break;
                }
                
                counter = counter.add(BigInteger.ONE);

            } catch (NoSuchAlgorithmException e) {
                System.out.println("Hashing algorithm not recognised");
            }

        }

        // set the g1 that we found
        this.g1 = g1temp;

        // set up the bulletin board
        bulletin_board = new BulletinBoard(num_candidates, g0, g1, curve);

    }

    // create an election with a specific ZKP level
    public Election(String election_name, String election_date, int num_candidates, ZKPLevel level) {

        this(election_name, election_date, num_candidates);
        this.level = level;

    }

    // given a ranking compute its associated encoding
    public int[] encode(int[] ranking) {

        int[] encoding = new int[num_candidates];
        int top = ranking[0];


        for (int i = 0; i < num_candidates; i++) {

            if (i == top - 1) {
                encoding[i] = 1;
            } else {
                encoding[i] = 0; 
            }

        }

        return encoding;

    }
    
    // create a new ID for a ballot
    public int genBallotIndex() {
        ballot_index++;
        return ballot_index;
    }

    // cast a vote in an election
    // whenever a vote is cast, we also encrypt it and generate an associated proof
    // that the underlying plaintext matrix is a permutation matrix
    public int castVote(int[] ranking) {

        // get the encoding for the ranking
        int[] encoding = encode(ranking);

        // create a ballot from the vote
        int index = genBallotIndex();

        ECPoint[] b = new ECPoint[num_candidates + 1];
        ECPoint[] y = new ECPoint[num_candidates + 1];
        ECPoint[] e = new ECPoint[num_candidates];
        ECPoint[] z = new ECPoint[num_candidates];

        BigInteger[] x_bal = genRandomVec(q, num_candidates + 1);
        BigInteger[] x_enc = genRandomVec(q, num_candidates);

        for (int i = 0; i <= num_candidates; i++) {
            b[i] = g0.multiply(x_bal[i]).add(g1.multiply(BigInteger.valueOf(ranking[i])));
            y[i] = g1.multiply(x_bal[i]);
        }

        for (int i = 0; i < num_candidates; i++) {
            e[i] = g0.multiply(x_enc[i]).add(g1.multiply(BigInteger.valueOf(encoding[i])));
            z[i] = g1.multiply(x_enc[i]);
        }

        Ballot ballot = new Ballot(index, b, y, e, z);

        // add the randomness to the storage on the server (for the first round)
        ElectionData election_data = new ElectionData(ranking, encoding, x_bal, x_enc);
        election_datas.get(0).put(index, election_data);

        CastNIZKP nizkp_cast;
        EncodingNIZKP nizkp_enc;

        // only create the NIZKPs if the level permits it
        if (this.level == ZKPLevel.COMPUTE_CAST_ZKPS || this.level == ZKPLevel.COMPUTE_ALL_ZKPS) {

            // create a NIZKP for well-formedness of ranking
            nizkp_cast = new CastNIZKP(curve, g0, g1, num_candidates, ballot, ranking, x_bal);

            // create a NIZKP for well-formedness of encoding
            nizkp_enc = new EncodingNIZKP(curve, g0, g1, num_candidates, ballot, ranking, encoding, x_bal, x_enc, new ArrayList<Integer>());

        } else {

            nizkp_cast = null;
            nizkp_enc = null;

        }

        // publish the ballot to the bulletin board for the first round alongside its nizkp
        BulletinBoardData data = new BulletinBoardData(ballot, nizkp_cast, nizkp_enc);

        this.bulletin_board.addToBulletinDataAtRound(0, data);

        // update the tallies on the bulletin board
        this.bulletin_board.addToTallyAtRound(0, encoding);
        this.bulletin_board.addToEncodingRandomnessAtRound(0, x_enc);

        // return the index of the cast ballot
        return index;

    }
    

    // compute the tally of most-preferred placements across all votes at a round m
    public int[] computeTally(int round) {

        int[] tally = new int[num_candidates];

        HashMap<Integer,ElectionData> round_data = election_datas.get(round);

        for (int index : round_data.keySet()) {

            int[] enc = round_data.get(index).getEncoding();

            for (int j = 0; j < num_candidates; j++) {
                tally[j] += enc[j];
            }

        }

        return tally;

    }

    // find the choice to eliminate (the one that minimises the tally and that is not already eliminated)
    // for simplicity we take one of the choices if they are tied
    public int findWeakestChoice(int[] tally) {

        // initialise a list of all non-eliminated choices
        ArrayList<Integer> remaining = new ArrayList<Integer>();
        // we skip over 0 as it encodes the STOP choice
        for (int i = 1; i <= num_candidates; i++) {
            if (!elims.contains(i)) {
                remaining.add(i);
            }
        }

        // find the non-eliminated choice that creates the smallest value of the tally
        int weakest = remaining.get(0);
        for (int k = 0; k < remaining.size(); k++) {
            int contender = remaining.get(k);
            if (tally[contender - 1] < tally[weakest - 1]) {
                weakest = contender;
            }
        }

        return weakest;

    }

    // delete the entry of an eliminated choice from a ranking
    public int[] shift(int alpha, int[] ranking) {

        int n = ranking.length;
        int[] copy = new int[n - 1];

        int i = 0;
        int j = 0;

        while (j < n - 1) {

            if (ranking[i] == alpha) {
                i++;
            }

            copy[j] = ranking[i];
            i++;
            j++;

        }

        return copy;

    }

    // run a round
    public void runRound(int round) {

        // find a choice to eliminate from the vectors of the previous round and store it
        int[] prev_tally = computeTally(round - 1);
        int alpha = findWeakestChoice(prev_tally);
        elims.add(alpha);

        // compute the shifted vectors from the previous round and store them for the current round
        // also generate a new ballot for the shifted vote 
        HashMap<Integer, ElectionData> prev_election_data = election_datas.get(round - 1);

        // variables for logging
        int counter = 0;
        long start = System.currentTimeMillis();

        Iterator<Integer> prev_it = prev_election_data.keySet().iterator();

        //for (int prev_index : prev_election_data.keySet()) {
        while (prev_it.hasNext()) {

            int prev_index = prev_it.next();

            int[] prev_vote = prev_election_data.get(prev_index).getVote();

            int[] shifted = this.shift(alpha, prev_vote);

            // recompute the encoding for the shifted vote
            int[] encoding = this.encode(shifted);

            int n = shifted.length;

            int index = genBallotIndex();

            ECPoint[] b = new ECPoint[n];
            ECPoint[] y = new ECPoint[n];
            ECPoint[] e = new ECPoint[num_candidates];
            ECPoint[] z = new ECPoint[num_candidates];

            BigInteger[] x_bal = genRandomVec(q, n);
            BigInteger[] x_enc = genRandomVec(q, num_candidates);

            for (int i = 0; i < n; i++) {

                b[i] = g0.multiply(x_bal[i]).add(g1.multiply(BigInteger.valueOf(shifted[i])));
                y[i] = g1.multiply(x_bal[i]);

            }

            for (int i = 0; i < num_candidates; i++) {

                e[i] = g0.multiply(x_enc[i]).add(g1.multiply(BigInteger.valueOf(encoding[i])));
                z[i] = g1.multiply(x_enc[i]);

            }

            // generate the ballot 
            Ballot ballot = new Ballot(index, b, y, e, z);

            ElectionData election_data = new ElectionData(shifted, encoding, x_bal, x_enc);
            election_datas.get(round).put(index, election_data);

            // generate the associated NIZKP for the Tallying phase for this ballot
            HashMap<Integer, BulletinBoardData> prev_data = this.bulletin_board.getBulletinDataAtRound(round - 1);

            Ballot prev_ballot = prev_data.get(prev_index).getBallot();
            BigInteger[] prev_x = prev_election_data.get(prev_index).getRandomnessesBal();


            // only compute the NIZKPs if the level permits it
            TallyNIZKP nizkp_bal;
            EncodingNIZKP nizkp_enc;

            if (this.level == ZKPLevel.COMPUTE_TALLY_ZKPS || this.level == ZKPLevel.COMPUTE_ALL_ZKPS) {

                //nizkp_bal = new TallyNIZKP(curve, g0, g1, num_candidates, ballot, shifted, x_bal, prev_ballot, prev_vote, prev_x, round, alpha, elims);
                //nizkp_enc = new EncodingNIZKP(curve, g0, g1, num_candidates, ballot, shifted, encoding, x_bal, x_enc, elims);

                // we still run the proofs as above to get estimates for their running time
                // but we're going to null them here to save on memory for the benchmarks
                // (and pray that the garbage collector is smart at cleaning these up for us)
                // the proofs don't need to all be in memory at once in an idealised system
                // as these could be stored on disk for the bulletin board to read from

                nizkp_bal = new TallyNIZKP(curve, g0, g1, num_candidates, ballot, shifted, x_bal, prev_ballot, prev_vote, prev_x, round, alpha, elims);
                nizkp_enc = new EncodingNIZKP(curve, g0, g1, num_candidates, ballot, shifted, encoding, x_bal, x_enc, elims);

                //nizkp_bal = null;
                //nizkp_enc = null;

            } else {

                nizkp_bal = null;
                nizkp_enc = null;

            }

            // add to data on the bulletin board
            BulletinBoardData data = new BulletinBoardData(ballot, nizkp_bal, nizkp_enc);
            this.bulletin_board.addToBulletinDataAtRound(round, data);
            
            // update the tallies on the bulletin board
            this.bulletin_board.addToTallyAtRound(round, encoding);
            this.bulletin_board.addToEncodingRandomnessAtRound(round, x_enc);

            // we can remove the previous ballot and associated values now we are done with it
            prev_it.remove();
            this.bulletin_board.removeFromBulletinDataAtRound(round - 1, prev_index);

            // a bit of logging 
            counter++;
            if (counter % 1000 == 0) {
                long partial_elapsed = System.currentTimeMillis() - start;
                System.out.println("Tallied " + counter + " votes in " + partial_elapsed + "ms");
            } 

        }

        // make the previous data store available for garbage collection
        election_datas.set(round - 1, null);

    }
    
    // run all the rounds
    public void runRounds() {

        for (int i = 1; i < num_candidates - 1; i++) {
            runRound(i);
        }

    }

    // helper function to hash into an elliptic curve
    private ECPoint hashToCurve(BigInteger x) {

        int counter = 0;
        BigInteger a = curve.getA().toBigInteger();
        BigInteger b = curve.getB().toBigInteger();

        // use the ``try and increment'' method to hash a value to the curve 
        // election parameters are public so this is fine in our case
        while (true) {

            //BigInteger y2 = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(q); 
            BigInteger y2 = x.modPow(BigInteger.valueOf(3),q).add(a.multiply(x).mod(q)).mod(q).add(b).mod(q);
            BigInteger exponent = q.subtract(BigInteger.ONE).divide(BigInteger.TWO);

            // check using Euler's criterion whether y2 is a quadratic residue mod q
            if (y2.modPow(exponent, q).equals(BigInteger.ONE)) {

                ECPoint point = curve.createPoint(x, curve.fromBigInteger(y2).sqrt().toBigInteger());

                return point;

            }

            x = x.add(BigInteger.ONE);

        }

    }

    // helper function to generate a random big integer from 1 to a limit
    public static BigInteger genRandom(BigInteger limit) {
        
        Random gen = new Random();
        BigInteger random;
        int i = 0;
        do {
            random = new BigInteger(limit.bitLength(), gen);
        } while (random.compareTo(limit) >= 0 || random.compareTo(BigInteger.ZERO) == 0);
        return random;
        
    }
    
    // helper function to generate an vector of random numbers
    public static BigInteger[] genRandomVec(BigInteger limit, int n) {
        BigInteger[] x = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            x[i] = genRandom(limit);
        }
        return x;
    }

    // helper function for hashing commitments
    public static BigInteger hash(ECPoint[] points) {

        try {

            MessageDigest md = MessageDigest.getInstance(hash_alg);
            for (int i = 0; i < points.length; i++) {
                md.update(points[i].getEncoded(false));
            }
            byte[] result = md.digest();

            return new BigInteger(1, result);

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Hashing algorithm not recognised");
            return new BigInteger("-1");
        }

    }

}
