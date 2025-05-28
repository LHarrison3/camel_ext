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

public class TallyRoundVerificationBenchmark {

    @State(Scope.Benchmark)
    public static class ElectionState {

        // fixed maximum number of choices
        public int num_candidates = 10;

        // determine rounds to run per benchmark
        @Param({"1","2","3","4","5","6","7","8"})
        public String rnds;

        // round to verify in the benchmark
        public int rnd;

        // an election so we can use methods from it for easier setup
        public Election election;

        @Setup(Level.Invocation)
        public void setUp() {

            // set election object
            election = new Election("Benchmarking Election", "11/05/21", num_candidates, ZKPLevel.COMPUTE_ALL_ZKPS);

            // generate a random vote
            int[] vote = new int[num_candidates+1];
            ArrayList<Integer> vote_list = new ArrayList<Integer>();

            for (int i = 0; i <= num_candidates; i++) {
                vote_list.add(i);
            }

            Collections.shuffle(vote_list);

            for (int i = 0; i <= num_candidates; i++) {
                vote[i] = vote_list.get(i).intValue();
            }

            // add the ballot
            election.castVote(vote);

            rnd = Integer.parseInt(rnds);

            // run the rounds specified by the benchmark parameters
            for (int i = 1; i <= rnd; i++) {
                election.runRound(i);
            }

        }

    }

    // benchmark verification of the nizkps for the tallying rounds over all ballots
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(value = 1, warmups = 3)
    @Measurement(iterations = 5, timeUnit = TimeUnit.MILLISECONDS)
    @Warmup(iterations = 3, timeUnit = TimeUnit.MILLISECONDS)
    public void benchmarkTallyRoundNizkpVerify(Blackhole blackhole, ElectionState state) {

        Election e = state.election;

        HashMap<Integer,BulletinBoardData> data = e.bulletin_board.getBulletinDataAtRound(state.rnd);

        Iterator it = data.keySet().iterator();
        int index = (int) it.next();

        NIZKP balNizkp = data.get(index).getBalNizkp();
        NIZKP encNizkp = data.get(index).getEncNizkp();

        blackhole.consume(balNizkp.verify() && encNizkp.verify());

    }

}
