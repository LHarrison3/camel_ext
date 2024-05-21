package camel;

import java.util.*;
import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.annotations.Setup;

public class VerificationBenchmark {

    @State(Scope.Benchmark)
    public static class ElectionState {

        // specified number of candidates for which to run the benchmarks on
        @Param({"3","4","5","6","7","8","9","10"})
        public String candidates_val;

        // n-bit security levels
        @Param({"112","128"})
        public String security_bits;

        // number of candidates as an integer
        public int num_candidates;

        // each benchmark gets multiple random votes
        public int[][] votes;

        // an election so we can use methods from it for easier setup
        public Election election;

        @Setup(Level.Invocation)
        public void setUp() {

            num_candidates = Integer.parseInt(candidates_val);

            int bits = Integer.parseInt(security_bits);
            int num_votes = 50;

            votes = new int[num_votes][num_candidates];

            // set election object
            election = new Election("Benchmarking Election", "11/05/21", num_candidates, bits);

            // generate some random votes
            for (int i = 0; i < num_votes; i++) {

                ArrayList<Integer> vote_list = new ArrayList<Integer>();

                for (int j = 0; j < num_candidates; j++) {
                    vote_list.add(j);
                }

                Collections.shuffle(vote_list);
                
                for (int j = 0; j < num_candidates; j++) {
                    votes[i][j] = vote_list.get(j).intValue();
                }

                // add the ballot
                election.castVote(votes[i]);

            }

            // run the tallying rounds
            election.runRounds();

        }

    }
    
    
    // benchmark verification of a NIZKP during the Vote Casting phase
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(value = 1, warmups = 3)
    @Measurement(iterations = 5, timeUnit = TimeUnit.MILLISECONDS)
    @Warmup(iterations = 3, timeUnit = TimeUnit.MILLISECONDS)
    public void benchmarkCastingVerification(Blackhole blackhole, ElectionState state) {

       Election e = state.election;
       boolean hold = e.bulletin_board.getBallotNIZKPsAtRound(0).get(0).verify();
       blackhole.consume(hold);

    }
    
    
    
    // benchmark verification of a NIZKP during the second round of the Tallying phase
    // we choose the second round here as this gives the proof of well-formedness P_wf^T
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(value = 1, warmups = 3)
    @Measurement(iterations = 5, timeUnit = TimeUnit.MILLISECONDS)
    @Warmup(iterations = 3, timeUnit = TimeUnit.MILLISECONDS)
    public void benchmarkRoundVerification(Blackhole blackhole, ElectionState state) {

       Election e = state.election;
       boolean hold = e.bulletin_board.getBallotNIZKPsAtRound(1).get(0).verify();
       blackhole.consume(hold);

    }
    
    
    
    // benchmark verification of the tallies during the first round of the Tallying phase
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(value = 1, warmups = 3)
    @Measurement(iterations = 5, timeUnit = TimeUnit.MILLISECONDS)
    @Warmup(iterations = 3, timeUnit = TimeUnit.MILLISECONDS)
    public void benchmarkTallyVerification(Blackhole blackhole, ElectionState state) {

       Election e = state.election;
       boolean hold = e.bulletin_board.verifyTalliesAtRound(0);
       blackhole.consume(hold);

    }
    

}
