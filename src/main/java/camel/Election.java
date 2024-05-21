package camel;

import java.util.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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
    public final BigInteger g0;
    public final BigInteger g1;
    public final BigInteger p;
    public final BigInteger q;

    // ID for ballots
    private int ballot_index = 0;

    // storage on the voting server for plaintext votes and randomnesses during rounds of the tallying phase
    public ArrayList<ArrayList<int[]>> votes;
    public ArrayList<ArrayList<int[]>> encodings;
    private ArrayList<ArrayList<BigInteger[]>> randomnesses_bals;
    private ArrayList<ArrayList<BigInteger[]>> randomnesses_encs;

    // for convenience we store the eliminated choices at each round as well
    private ArrayList<Integer> elims;

    // the bulletin board
    public BulletinBoard bulletin_board;

    // create an election
    public Election(String election_name, String election_date, int num_candidates, int security_bits) {

        this.election_name = election_name;
        this.election_date = election_date;

        // storage of plaintext votes and randomnesses for the tallying phase
        // we initialise each round here
        this.votes = new ArrayList<ArrayList<int[]>>();
        this.encodings = new ArrayList<ArrayList<int[]>>();
        this.randomnesses_bals = new ArrayList<ArrayList<BigInteger[]>>();
        this.randomnesses_encs = new ArrayList<ArrayList<BigInteger[]>>();
        this.elims = new ArrayList<Integer>();

        for (int i = 0; i < num_candidates - 1; i++) {
            votes.add(new ArrayList<int[]>());
            encodings.add(new ArrayList<int[]>());
            randomnesses_bals.add(new ArrayList<BigInteger[]>());
            randomnesses_encs.add(new ArrayList<BigInteger[]>());
        }

        // values for p, q and g0 are taken from NIST
        // default to 128-bit security
        String p_str = "90066455B5CFC38F9CAA4A48B4281F292C260FEEF01FD61037E56258A7795A1C7AD46076982CE6BB956936C6AB4DCFE05E6784586940CA544B9B2140E1EB523F009D20A7E7880E4E5BFA690F1B9004A27811CD9904AF70420EEFD6EA11EF7DA129F58835FF56B89FAA637BC9AC2EFAAB903402229F491D8D3485261CD068699B6BA58A1DDBBEF6DB51E8FE34E8A78E542D7BA351C21EA8D8F1D29F5D5D15939487E27F4416B0CA632C59EFD1B1EB66511A5A0FBF615B766C5862D0BD8A3FE7A0E0DA0FB2FE1FCB19E8F9996A8EA0FCCDE538175238FC8B0EE6F29AF7F642773EBE8CD5402415A01451A840476B2FCEB0E388D30D4B376C37FE401C2A2C2F941DAD179C540C1C8CE030D460C4D983BE9AB0B20F69144C1AE13F9383EA1C08504FB0BF321503EFE43488310DD8DC77EC5B8349B8BFE97C2C560EA878DE87C11E3D597F1FEA742D73EEC7F37BE43949EF1A0D15C3F3E3FC0A8335617055AC91328EC22B50FC15B941D3D1624CD88BC25F3E941FDDC6200689581BFEC416B4B2CB73";

        String q_str = "CFA0478A54717B08CE64805B76E5B14249A77A4838469DF7F7DC987EFCCFB11D";

        String g0_str = "5E5CBA992E0A680D885EB903AEA78E4A45A469103D448EDE3B7ACCC54D521E37F84A4BDD5B06B0970CC2D2BBB715F7B82846F9A0C393914C792E6A923E2117AB805276A975AADB5261D91673EA9AAFFEECBFA6183DFCB5D3B7332AA19275AFA1F8EC0B60FB6F66CC23AE4870791D5982AAD1AA9485FD8F4A60126FEB2CF05DB8A7F0F09B3397F3937F2E90B9E5B9C9B6EFEF642BC48351C46FB171B9BFA9EF17A961CE96C7E7A7CC3D3D03DFAD1078BA21DA425198F07D2481622BCE45969D9C4D6063D72AB7A0F08B2F49A7CC6AF335E08C4720E31476B67299E231F8BD90B39AC3AE3BE0C6B6CACEF8289A2E2873D58E51E029CAFBD55E6841489AB66B5B4B9BA6E2F784660896AFF387D92844CCB8B69475496DE19DA2E58259B090489AC8E62363CDF82CFD8EF2A427ABCD65750B506F56DDE3B988567A88126B914D7828E2B63A6D7ED0747EC59E0E0A23CE7D8A74C1D2C2A7AFB6A29799620F00E11C33787F7DED3B30E1A22D09F1FBDA1ABBBFBF25CAE05A13F812E34563F99410E73B";

        // 112-bit security
        if (security_bits == 112) {
            p_str = "C196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE428782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BFFAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83";

            q_str = "90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D";

            g0_str = "A59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E5048B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDFD049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085";
        }

        this.p = new BigInteger(p_str, 16);
        this.q = new BigInteger(q_str, 16);
        this.g0 = new BigInteger(g0_str, 16);

        BigInteger counter = BigInteger.ZERO;

        // next we must find a suitable g1
        // we do this by computing g1 = H(g0, election_string, counter)
        // and check if the result has the prime order q

        BigInteger g1_temp = BigInteger.ONE;

        // compute a string specific to this election
        String election_string = election_name + election_date;
        for (int i = 0; i < num_candidates; i++) {
            election_string += i;
        }
        BigInteger election_data = new BigInteger(election_string.getBytes());

        String hash_alg = "SHA-256";
        while (true) {

            try {

                MessageDigest md = MessageDigest.getInstance(hash_alg);
                md.update(g0.toByteArray());
                md.update(election_data.toByteArray());
                md.update(counter.toByteArray());

                byte[] result = md.digest();
                g1_temp = new BigInteger(1, result);

                g1_temp = g1_temp.modPow(p.subtract(BigInteger.ONE).divide(q), p);

                // check if result gives the prime order q
                if (g1_temp.compareTo(BigInteger.ONE) != 0) {
                    break;
                }

                counter = counter.add(BigInteger.ONE);

            } catch (NoSuchAlgorithmException e) {
                System.out.println("Hashing algorithm not recognised");
            }

        }

        // set the g1 that we found
        this.g1 = g1_temp;

        //System.out.println("g0 is: " + g0.toString());
        //System.out.println("g1 is: " + g1.toString());

        this.num_candidates = num_candidates;
        this.candidates = new int[num_candidates];

        // assign identifiers to the candidates
        for (int i = 0; i < this.candidates.length; i++) {
            this.candidates[i] = i + 1;
        }

        // set up the bulletin board
        bulletin_board = new BulletinBoard(num_candidates, g0, g1, p, q);

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

        // add the matrix to the storage on the server (for the first round)
        votes.get(0).add(ranking);
        encodings.get(0).add(encoding);

        // create a ballot from the vote
        int index = genBallotIndex();

        BigInteger[] b = new BigInteger[num_candidates + 1];
        BigInteger[] y = new BigInteger[num_candidates + 1];
        BigInteger[] e = new BigInteger[num_candidates];
        BigInteger[] z = new BigInteger[num_candidates];

        BigInteger[] x_bal = genRandomVec(num_candidates + 1);
        BigInteger[] x_enc = genRandomVec(num_candidates);

        for (int i = 0; i <= num_candidates; i++) {
            b[i] = g0.modPow(x_bal[i], p).multiply(g1.modPow(BigInteger.valueOf(ranking[i]), p)).mod(p);
            y[i] = g1.modPow(x_bal[i], p);
        }

        for (int i = 0; i < num_candidates; i++) {
            e[i] = g0.modPow(x_enc[i], p).multiply(g1.modPow(BigInteger.valueOf(encoding[i]), p)).mod(p);
            z[i] = g1.modPow(x_enc[i], p);
        }

        Ballot ballot = new Ballot(ballot_index, b, y, e, z);

        // add the randomness to the storage on the server (for the first round)
        randomnesses_bals.get(0).add(x_bal);
        randomnesses_encs.get(0).add(x_enc);

        // create a NIZKP for well-formedness of ranking
        CastNIZKP nizkp_cast = new CastNIZKP(p, q, g0, g1, num_candidates, ballot, ranking, x_bal);

        // create a NIZKP for well-formedness of encoding
        EncodingNIZKP nizkp_enc = new EncodingNIZKP(p, q, g0, g1, num_candidates, ballot, ranking, encoding, x_bal, x_enc, new ArrayList<Integer>());

        // publish the ballot to the bulletin board for the first round alongside its nizkp
        this.bulletin_board.addBallot(0, ballot);
        this.bulletin_board.addBallotNIZKP(0, nizkp_cast);
        this.bulletin_board.addEncodingNIZKP(0, nizkp_enc);

        // update the tallies on the bulletin board
        this.bulletin_board.addToTallyAtRound(0, encoding);
        this.bulletin_board.addToEncodingRandomnessAtRound(0, x_enc);

        // return the index of the cast ballot
        return index;

    }
    

    // compute the tally of most-preffered placements across all votes at a round m
    public int[] computeTally(int round) {

        int[] tally = new int[num_candidates];

        for (int i = 0; i < encodings.get(round).size(); i++) {

            int[] encoding = encodings.get(round).get(i);

            for (int j = 0; j < num_candidates; j++) {
                tally[j] += encoding[j];
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
        ArrayList<int[]> prev_votes = votes.get(round - 1);

        for (int v = 0; v < prev_votes.size(); v++) {

            int[] shifted = shift(alpha, prev_votes.get(v));

            // recompute the encoding for the shifted vote
            int[] encoding = encode(shifted);

            int n = shifted.length;

            votes.get(round).add(shifted);
            encodings.get(round).add(encoding);

            int index = genBallotIndex();
            BigInteger[] b = new BigInteger[n];
            BigInteger[] y = new BigInteger[n];
            BigInteger[] e = new BigInteger[num_candidates];
            BigInteger[] z = new BigInteger[num_candidates];

            BigInteger[] x_bal = genRandomVec(n);
            BigInteger[] x_enc = genRandomVec(num_candidates);

            for (int i = 0; i < n; i++) {

                b[i] = g0.modPow(x_bal[i], p).multiply(g1.modPow(BigInteger.valueOf(shifted[i]), p)).mod(p);
                y[i] = g1.modPow(x_bal[i], p);

            }

            for (int i = 0; i < num_candidates; i++) {

                e[i] = g0.modPow(x_enc[i], p).multiply(g1.modPow(BigInteger.valueOf(encoding[i]), p)).mod(p);
                z[i] = g1.modPow(x_enc[i], p);

            }

            // generate the ballot 
            Ballot ballot = new Ballot(ballot_index, b, y, e, z);

            // add the randomness to the storage on the server for the current round
            randomnesses_bals.get(round).add(x_bal);
            randomnesses_encs.get(round).add(x_enc);

            // publish the ballot to the bulletin board for the current round
            this.bulletin_board.addBallot(round, ballot);

            // generate the associated NIZKP for the Tallying phase for this ballot
            Ballot prev_ballot = this.bulletin_board.getBallotsAtRound(round - 1).get(this.bulletin_board.getBallotsAtRound(round).size() - 1);
            int[] prev_vote = votes.get(round - 1).get(votes.get(round).size() - 1);
            BigInteger[] prev_x = randomnesses_bals.get(round - 1).get(randomnesses_bals.get(round).size() - 1);

            TallyNIZKP nizkp_bal = new TallyNIZKP(p, q, g0, g1, num_candidates, ballot, shifted, x_bal, prev_ballot, prev_vote, prev_x, round, alpha, elims);
            this.bulletin_board.addBallotNIZKP(round, nizkp_bal);

            // generate the encoding NIZKP for this ballot
            EncodingNIZKP nizkp_enc = new EncodingNIZKP(p, q, g0, g1, num_candidates, ballot, shifted, encoding, x_bal, x_enc, elims);
            this.bulletin_board.addEncodingNIZKP(round, nizkp_enc);


            // update the tallies on the bulletin board
            this.bulletin_board.addToTallyAtRound(round, encoding);
            this.bulletin_board.addToEncodingRandomnessAtRound(round, x_enc);
        }

    }
    
    // run all the rounds
    public void runRounds() {

        for (int i = 1; i < num_candidates - 1; i++) {
            runRound(i);
        }

    }

    // helper function to generate a random big integer from 1 to a limit
    public BigInteger genRandom(BigInteger limit) {
        Random gen = new Random();
        BigInteger random;
        do {
            random = new BigInteger(limit.bitLength(), gen);
        } while (random.compareTo(limit) >= 0 || random.compareTo(BigInteger.ZERO) == 0);
        return random;
    }
    
    // helper function for hashing commitments
    public static BigInteger hash(BigInteger[] t) {

        String hash_alg = "SHA-256";

        try {

            MessageDigest md = MessageDigest.getInstance(hash_alg);
            for (int i = 0; i < t.length; i++) {
                md.update(t[i].toByteArray());
            }
            byte[] result = md.digest();

            return new BigInteger(1, result);

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Hashing algorithm not recognised");
            return new BigInteger("-1");
        }
    }

    // helper function to generate an vector of random numbers
    public BigInteger[] genRandomVec(int n) {
        BigInteger limit = q.subtract(BigInteger.ONE);
        BigInteger[] x = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            x[i] = genRandom(limit);
        }
        return x;
    }

}
