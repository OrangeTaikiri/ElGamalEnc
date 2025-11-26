package org.lecture;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class ElGamalEncryptionTest {

    @Test
    void encryptAndDecryptRoundTrip() {
        BigInteger p = BigInteger.valueOf(3623L);
        BigInteger g = BigInteger.valueOf(1228L);
        BigInteger r = BigInteger.valueOf(1628L);
        BigInteger k = BigInteger.valueOf(211L);
        BigInteger m = BigInteger.valueOf(1011L);

        ElGamalEncryption elGamalEncryption = new ElGamalEncryption(p, g, r, k);

        BigInteger[] ciphertext = elGamalEncryption.encrypt(m, k);
        BigInteger c1 = ciphertext[0];
        BigInteger c2 = ciphertext[1];

        BigInteger expectedC1 = g.modPow(k, p);
        BigInteger expectedC2 = m.multiply(elGamalEncryption.getY().modPow(k, p)).mod(p);

        assertEquals(expectedC1, c1, "c1 should equal g^k mod p");
        assertEquals(expectedC2, c2, "c2 should equal m * y^k mod p");

        BigInteger decrypted = elGamalEncryption.decrypt();
        assertEquals(m, decrypted, "decrypt should recover the original message");
    }

    @ParameterizedTest
    @MethodSource("messageAndNonceSamples")
    void roundTripForVariousMessagesAndNonces(BigInteger message, BigInteger k) {
        BigInteger p = BigInteger.valueOf(3623L);
        BigInteger g = BigInteger.valueOf(1228L);
        BigInteger r = BigInteger.valueOf(1628L);

        ElGamalEncryption elGamalEncryption = new ElGamalEncryption(p, g, r, k);

        BigInteger[] ciphertext = elGamalEncryption.encrypt(message, k);
        BigInteger c1 = ciphertext[0];
        BigInteger c2 = ciphertext[1];

        assertEquals(g.modPow(k, p), c1, "c1 should equal g^k mod p");
        assertEquals(message.multiply(elGamalEncryption.getY().modPow(k, p)).mod(p), c2, "c2 formula should hold");
        assertEquals(message, elGamalEncryption.decrypt(), "decrypt should recover the original message");
    }

    @Test
    void differentNoncesYieldDifferentCiphertexts() {
        BigInteger p = BigInteger.valueOf(3623L);
        BigInteger g = BigInteger.valueOf(1228L);
        BigInteger r = BigInteger.valueOf(1628L);
        BigInteger message = BigInteger.valueOf(1777L);

        ElGamalEncryption first = new ElGamalEncryption(p, g, r, BigInteger.valueOf(15));
        BigInteger[] ct1 = first.encrypt(message, BigInteger.valueOf(15));

        ElGamalEncryption second = new ElGamalEncryption(p, g, r, BigInteger.valueOf(245));
        BigInteger[] ct2 = second.encrypt(message, BigInteger.valueOf(245));

        assertNotEquals(ct1[0], ct2[0], "c1 should differ with different k");
        assertNotEquals(ct1[1], ct2[1], "c2 should differ with different k for the same message");
    }

    private static Stream<org.junit.jupiter.params.provider.Arguments> messageAndNonceSamples() {
        return Stream.of(
                org.junit.jupiter.params.provider.Arguments.of(BigInteger.valueOf(5L), BigInteger.valueOf(3L)),
                org.junit.jupiter.params.provider.Arguments.of(BigInteger.valueOf(777L), BigInteger.valueOf(55L)),
                org.junit.jupiter.params.provider.Arguments.of(BigInteger.valueOf(1500L), BigInteger.valueOf(333L)),
                org.junit.jupiter.params.provider.Arguments.of(BigInteger.valueOf(3100L), BigInteger.valueOf(1111L)),
                org.junit.jupiter.params.provider.Arguments.of(BigInteger.valueOf(3621L), BigInteger.valueOf(41L)) // p - 2
        );
    }
}
