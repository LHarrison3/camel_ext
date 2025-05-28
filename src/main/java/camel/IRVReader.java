package camel;

import java.util.*;
import java.io.*;

public class IRVReader {

    private ArrayList<int[]> votes; 
    private String[] choices;

    private HashMap<String, Integer> map; // mapping of choices to integers

    private BufferedReader br;

    public IRVReader(String path, String[] choices) {

        votes = new ArrayList<int[]>();
        this.choices = choices;
        map = new HashMap<String, Integer>();

        for (int i = 0; i < choices.length; i++) {
            map.put(choices[i], i+1);
        }

        try {

            br = new BufferedReader(new FileReader(path));

        } catch (FileNotFoundException e) {

            e.printStackTrace();

        }

        // parse the votes
        int prev_id = 1;
        try {

            br.readLine(); // skip the header

            int[] vote = new int[choices.length + 1];
            int count = 0;

            String line;
            while ((line = br.readLine()) != null) {
                
                String[] vals = line.split("\t");

                int id = Integer.parseInt(vals[2]);
                
                // just reached a new ballot
                if (id != prev_id) {

                    // skip any informal ones
                    if (vals[3].equals("Informal")) {
                        continue;
                    }

                    // fill in the previous ballot if it is a partial one
                    if (count < choices.length) {

                        vote[count] = 0; // end the ballot with the STOP choice
                        count++;

                        for (int i = 1; i <= choices.length; i++) {

                            // fill in the missing choices (order is arbitrary)
                            boolean in = false;
                            for (int j = 0; j < vote.length; j++) {
                                if (vote[j] == i) {
                                    in = true;
                                }
                            }

                            if (!in) {
                                vote[count] = i;
                                count++;
                            }

                        }

                    }
                    
                    // add the previous ballot to the list
                    votes.add(vote);

                    // start making the new ballot from current line
                    count = 0;
                    vote = new int[choices.length + 1];
                    prev_id = id;

                } 
                
                // keep adding to current ballot

                String choice = vals[4];

                if (vals.length >= 7) { // only add valid preferences (ones which exist)
                    int placement = Integer.parseInt(vals[6]);
                    vote[placement-1] = map.get(choice);
                    count++;
                } 

            }

            // clean up for the last ballot
            if (count < choices.length) {
                vote[count] = 0; // end the ballot with the STOP choice
                count++;
                for (int i = 1; i <= choices.length; i++) {
                    boolean in = false;
                    for (int j = 0; j < vote.length; j++) {
                        if (vote[j] == i) {
                            in = true;
                        }
                    }
                    if (!in) {
                        vote[count] = i;
                        count++;
                    }
                }
            }
            votes.add(vote);

        } catch (IOException e) {

            e.printStackTrace();

        } finally {
            
            try {

                br.close();

            } catch (IOException e) {

                e.printStackTrace();

            }

        }

    }

    public ArrayList<int[]> getVoteList() {
        return votes;
    }

}