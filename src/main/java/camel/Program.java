package camel;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.math.BigInteger;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class Program {

    public static void main(String[] args) {
        
        //String[] choices = {"WADE Kym", "MARRA John", "APLIN Greg", "KING Niloufer", "JACKSON Ross"};
        //IRVReader ir = new IRVReader("./albury.txt", choices);
        String[] choices = {"AHMED Kays", "OUEIK Ronney", "WALKER Raema", "MICHELS Malikeh", "FOLEY Luke", "GARRARD Paul"};
        IRVReader ir = new IRVReader("./auburn.txt", choices);

        System.out.println("Number of votes: " + ir.getVoteList().size());
        
        Election e = new Election("NSW", "05/12/24", choices.length, ZKPLevel.COMPUTE_TALLY_ZKPS);

        long start = System.currentTimeMillis();

        for (int i = 0; i < ir.getVoteList().size(); i++) {
            
            e.castVote(ir.getVoteList().get(i));

            if (i % 1000 == 0) {
                long partial_elapsed = System.currentTimeMillis() - start;
                System.out.println("Cast " + i + " votes in " + partial_elapsed + "ms");
            }

        }

        long elapsed = System.currentTimeMillis() - start;

        System.out.println("Total cast time: " + elapsed + "ms");

        // see the tallies after casting
        e.bulletin_board.printTallyAtRound(0);

        // time the tallying phase

        for (int i = 1; i <= 4; i++) {

             start = System.currentTimeMillis();

            e.runRound(i);

            elapsed = System.currentTimeMillis() - start;

            System.out.println("Total tally time: " + elapsed + "ms");

            // see the tallies

            System.out.println("Tallies");
            e.bulletin_board.printTallyAtRound(i);

            // time the tally verification

            start = System.currentTimeMillis();

            e.bulletin_board.verifyTalliesAtRound(i);

            elapsed = System.currentTimeMillis() - start;

            System.out.println("Total tally verification time: " + elapsed + "ms");

        }

       
        /*
        // time verification of the nizkps for the tallying phase

        start = System.currentTimeMillis();

        HashMap<Integer,BulletinBoardData> data = e.bulletin_board.getBulletinDataAtRound(1);

        int counter = 0;
        boolean res = true;
        for (int index : data.keySet()) {

            NIZKP balNizkp = data.get(index).getBalNizkp();
            NIZKP encNizkp = data.get(index).getEncNizkp();

            res = res && balNizkp.verify() && encNizkp.verify();

            counter++;

            long partial_elapsed = System.currentTimeMillis() - start;
            if (counter % 1000 == 0) {
                System.out.println("Verified " + counter + " NIZKPs in " + partial_elapsed + "ms");
            }

        }

        elapsed = System.currentTimeMillis() - start;

        System.out.println("Total NIZKP verification time: " + elapsed + "ms");

        if (res) {
            System.out.println("NIZKP verification was successful");
        } else {
            System.out.println("NIZKP verification failed");
        }
        */

    }

}
