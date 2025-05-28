package camel;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;


/**
 * This class represents storage of data on the bulletin board
 */
public class BulletinBoardData {

    // a ballot 
    private Ballot ballot;

    // its ballot nizkp
    private NIZKP bal_nizkp;

    // its encoding nizkp
    private NIZKP enc_nizkp;

    public BulletinBoardData(Ballot ballot, NIZKP bal_nizkp, NIZKP enc_nizkp) {
        
        this.ballot = ballot;
        this.bal_nizkp = bal_nizkp;
        this.enc_nizkp = enc_nizkp;

    }

    public Ballot getBallot() {
        return this.ballot;
    }

    public NIZKP getBalNizkp() {
        return this.bal_nizkp;
    }

    public NIZKP getEncNizkp() {
        return this.enc_nizkp;
    }


}