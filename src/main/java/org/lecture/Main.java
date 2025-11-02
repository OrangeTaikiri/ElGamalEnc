package org.lecture;

import java.math.BigInteger;

public class Main {

    void main() {
        BigInteger g = BigInteger.valueOf(1228L); //g primitive Wurzel
        BigInteger r = BigInteger.valueOf(1628L); //r random secure Number
        BigInteger p = BigInteger.valueOf(3623L); // p private key
        BigInteger k = BigInteger.valueOf(876L); // k random secure Number to decrypt m with publicKey
        BigInteger m = BigInteger.valueOf(2412L); // m message

        ElGamalEncryption elGamalEncryption = new ElGamalEncryption(p, g, r, k);

        // y = g^r mod p
        System.out.println("");
        System.out.println("Alice computes a part the public key ----> y");
        System.out.println("y = g^r mod p");
        System.out.println("y = "+g+"^"+r+" mod "+ p + " = " + elGamalEncryption.getY());
        System.out.println("--------------------------------");

        // get public key
        BigInteger[] publicKey = elGamalEncryption.getPublicKey();
        System.out.println("Public Key  -> (p ,g ,y ) ");
        System.out.println("public Key  -> (p = " + publicKey[0] + " , g = " + publicKey[1] + " , y = " + publicKey[2] + ")");
        System.out.println("--------------------------------");

        // encrypt message
        System.out.println("Alice encrypts the message ----> (c1 , c2)");
        BigInteger[] encryptedMessage = elGamalEncryption.encrypt(m, k);
        BigInteger c1 = encryptedMessage[0];
        BigInteger c2 = encryptedMessage[1];
        System.out.println("c1 = g^k mod p");
        System.out.println("c1 = " + g + "^" + k + " mod " + p + " = " + c1);
        System.out.println("c2 = m * y^k mod p");
        System.out.println("c2 = " + m + " * " + publicKey[2] + "^" + k + " mod " + p + " = " + c2);
        System.out.println("encryptedMessage -> (c1 = " + c1 + " , c2 = " + c2 + ")");
        System.out.println("--------------------------------");

        // decrypt message
        System.out.println("Bob decrypts the message ----> m");
        System.out.println("s = c1^r mod p");
        BigInteger s = c1.modPow(r, p);
        System.out.println("s = " + c1 + "^" + r + " mod " + p + " = " + s);
        BigInteger sInv = s.modInverse(p);
        System.out.println("s^-1 mod p = " + sInv);
        System.out.println("m = c2 * s^-1 mod p");
        BigInteger decryptedMessage = elGamalEncryption.decrypt();
        System.out.println("m = " + c2 + " * " + sInv + " mod " + p + " = " + decryptedMessage);

    }
}
