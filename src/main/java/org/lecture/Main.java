package org.lecture;

import java.math.BigInteger;
import java.util.Arrays;

public class Main {

    void main() {
        BigInteger g = BigInteger.valueOf(1228L); //g primitive Wurzel
        BigInteger r = BigInteger.valueOf(77L); //r random secure Number
        BigInteger p = BigInteger.valueOf(3623L); // p private key
        BigInteger k = BigInteger.valueOf(3L); // k random secure Number to decrypt m with publicKey
        BigInteger m = BigInteger.valueOf(2412L); // m message

        ElGamalEncryption elGamalEncryption = new ElGamalEncryption(p, g, r, k);

        // y = g^r mod p
        System.out.println(elGamalEncryption.getY());

        // get public key
        BigInteger[] publicKey = elGamalEncryption.getPublicKey();
        System.out.println("public Key  -> " + Arrays.toString(publicKey));

        // encrypt message
        BigInteger[] encryptedMessage = elGamalEncryption.encrypt(m, k);
        System.out.println("encryptedMessage = " + Arrays.toString(encryptedMessage));

        // encrypt message
        BigInteger decryptedMessage = elGamalEncryption.decrypt();
        System.out.println("decryptedMessage = " + decryptedMessage);

    }
}
