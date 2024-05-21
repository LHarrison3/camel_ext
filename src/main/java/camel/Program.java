package camel;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.math.BigInteger;

public class Program {

    public static void main(String[] args) {

        // try out the class

        int num_candidates = 4;

        Election e = new Election("Sample Election", "05/05/22", num_candidates, 112);

        int[] rank0 = {0,2,1,3,4};
        int[] rank1 = {0,3,1,2,4};
        int[] rank2 = {3,0,2,4,1}; // 
        int[] rank3 = {1,2,4,0,3}; //
        int[] rank4 = {4,1,3,0,2};
        int[] rank5 = {3,2,1,4,0}; //
        int[] rank6 = {2,0,4,3,1}; //
        int[] rank7 = {3,2,0,4,1}; //
        int[] rank8 = {2,3,1,0,4}; //

        int[] encoding0 = e.encode(rank0);
        int[] encoding1 = e.encode(rank1);
        int[] encoding2 = e.encode(rank2);
        int[] encoding3 = e.encode(rank3);
        int[] encoding4 = e.encode(rank4);
        int[] encoding5 = e.encode(rank5);
        int[] encoding6 = e.encode(rank6);
        int[] encoding7 = e.encode(rank7);
        int[] encoding8 = e.encode(rank8);


        /*
        System.out.println(Arrays.toString(rank0));
        System.out.println(Arrays.toString(encoding0));

        System.out.println("");
        System.out.println(Arrays.toString(rank1));
        System.out.println(Arrays.toString(encoding1));

        System.out.println("");
        System.out.println(Arrays.toString(rank2));
        System.out.println(Arrays.toString(encoding2));

        System.out.println("");
        System.out.println(Arrays.toString(rank3));
        System.out.println(Arrays.toString(encoding3));

        System.out.println("");
        System.out.println(Arrays.toString(rank4));
        System.out.println(Arrays.toString(encoding4));

        System.out.println("");
        System.out.println(Arrays.toString(rank5));
        System.out.println(Arrays.toString(encoding5));

        System.out.println("");
        System.out.println(Arrays.toString(rank6));
        System.out.println(Arrays.toString(encoding6));

        System.out.println("");
        System.out.println(Arrays.toString(rank7));
        System.out.println(Arrays.toString(encoding7));

        System.out.println("");
        System.out.println(Arrays.toString(rank8));
        System.out.println(Arrays.toString(encoding8));
        System.out.println("");
        */

        e.castVote(rank0);
        e.castVote(rank1);
        e.castVote(rank2);
        e.castVote(rank3);
        e.castVote(rank4);
        e.castVote(rank5);
        e.castVote(rank6);
        e.castVote(rank7);
        e.castVote(rank8);

        //e.runRound(1);

        e.runRounds();

        e.bulletin_board.printTallies();

        /*
        System.out.println(Arrays.toString(e.votes.get(2).get(4)));
        System.out.println(Arrays.toString(e.encodings.get(2).get(4)));
        */

        int rnd = 2;

        ArrayList<NIZKP> nizkps_bal = e.bulletin_board.getBallotNIZKPsAtRound(rnd);
        ArrayList<NIZKP> nizkps_enc = e.bulletin_board.getEncodingNIZKPsAtRound(rnd);

        for (int i = 0; i < nizkps_bal.size(); i++) {
            //System.out.println("Vote: " + Arrays.toString(e.votes.get(rnd).get(i)));
            //System.out.println("Encoding: " + Arrays.toString(e.encodings.get(rnd).get(i)));
            System.out.println("NIZKP verification: " + nizkps_bal.get(i).verify());
            //System.out.println("");
        }

        
        for (int i = 0; i < num_candidates - 1; i++) {
            System.out.println("Tally verification: " + e.bulletin_board.verifyTalliesAtRound(i));
        }        

    }

}
