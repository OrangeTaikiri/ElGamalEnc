package org.lecture;

import java.math.BigInteger;

public class ElGamalEncryption {
    private BigInteger p; // Prime number
    private BigInteger g; // Generator
    private BigInteger r; // Private key
    private BigInteger y; // Public key
    private BigInteger c1;
    private BigInteger c2;


    /**
     * Constructor for the ElGamalEncryption class.
     * This initializes the ElGamal encryption scheme with the given parameters and computes the public key.
     *
     * @param p the prime number used in the encryption process
     * @param g the generator of the cyclic group
     * @param r the private key
     * @param k a random value used internally (not utilized directly in this constructor)
     */
    public ElGamalEncryption(BigInteger p, BigInteger g, BigInteger r, BigInteger k) {
        this.p = p;
        this.g = g;
        this.r = r;
        y = g.modPow(r, p); // Public key
    }

    /**
     * Encrypts a given message using the ElGamal encryption algorithm.
     *
     * @param message the plaintext message to be encrypted
     * @param k a random number used to generate the ciphertext
     * @return an array of BigInteger containing two parts of the ciphertext:
     *         the first part (c1) represents g^k mod p, and the second part (c2) represents the encrypted message
     */
    public BigInteger[] encrypt(BigInteger message, BigInteger k) {
        this.c1 = g.modPow(k, p);
        this.c2 = message.multiply(y.modPow(k, p)).mod(p);
        return new BigInteger[]{c1, c2};
    }

    /**
     * Decrypts the ciphertext previously encrypted using the ElGamal encryption algorithm.
     * The method computes the shared secret from the ciphertext and the private key,
     * calculates its modular inverse, and then uses it to recover the original message.
     *
     * @return the decrypted message as a BigInteger
     */
    public BigInteger decrypt() {
        BigInteger s = this.c1.modPow(r, p);

        // Berechne das Inverse von s mod p
        BigInteger sInv = s.modInverse(p);

        // Entschlüsselte Nachricht: m = c2 * sInv mod p
        BigInteger message = this.c2.multiply(sInv).mod(p);

        return message;
    }

    /**
     * Retrieves the computed public key component y.
     *
     * @return the public key component y as a BigInteger
     */
    public BigInteger getY() {
        return y;
    }

    /**
     * Retrieves the public key components used in the ElGamal encryption scheme.
     * The public key consists of three components:
     * the prime number p, the generator g, and the computed public key y.
     *
     * @return an array of BigInteger containing the public key components [p, g, y]
     */
    public BigInteger[] getPublicKey(){
        return new BigInteger[]{p, g, y};
    }

}