package com.proj2.cryptoUtility;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class PaillierCrypto {

    private PaillierCrypto() {
    }

    public static class PublicKey {
        public final BigInteger n;
        public final BigInteger g;
        public final BigInteger nSquared;

        public PublicKey(BigInteger n, BigInteger g) {
            this.n = n;
            this.g = g;
            this.nSquared = n.multiply(n);
        }
    }

    public static class PrivateKey {
        public final BigInteger lambda;
        public final BigInteger mu;
        public final PublicKey publicKey;

        public PrivateKey(BigInteger lambda, BigInteger mu, PublicKey publicKey) {
            this.lambda = lambda;
            this.mu = mu;
            this.publicKey = publicKey;
        }
    }

    public static class KeyPair {
        public final PublicKey publicKey;
        public final PrivateKey privateKey;

        public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }
    }

    public static KeyPair generateKeyPair(int bitLength) {
        SecureRandom rng = new SecureRandom();

        BigInteger p;
        BigInteger q;
        BigInteger n;

        do {
            p = BigInteger.probablePrime(bitLength / 2, rng);
            q = BigInteger.probablePrime(bitLength / 2, rng);
            n = p.multiply(q);
        } while (
                p.equals(q)
                        || !n.gcd(
                                p.subtract(BigInteger.ONE)
                                        .multiply(q.subtract(BigInteger.ONE))
                        ).equals(BigInteger.ONE)
        );

        BigInteger g = n.add(BigInteger.ONE);

        BigInteger lambda = lcm(
                p.subtract(BigInteger.ONE),
                q.subtract(BigInteger.ONE)
        );

        BigInteger mu = lambda.modInverse(n);

        PublicKey pub = new PublicKey(n, g);
        PrivateKey priv  = new PrivateKey(lambda, mu, pub);

        return new KeyPair(pub, priv);
    }

    public static BigInteger encrypt(long plaintext, PublicKey publicKey) {
        return encrypt(BigInteger.valueOf(plaintext), publicKey);
    }

    public static BigInteger encrypt(BigInteger plaintext, PublicKey publicKey) {
        if (plaintext.signum() < 0 || plaintext.compareTo(publicKey.n) >= 0) {
            throw new IllegalArgumentException("Plaintext must be in range [0, n).");
        }

        SecureRandom random = new SecureRandom();
        BigInteger r;

        do {
            r = new BigInteger(publicKey.n.bitLength(), random);
        } while (
                r.compareTo(BigInteger.ONE) < 0
                        || r.compareTo(publicKey.n) >= 0
                        || !r.gcd(publicKey.n).equals(BigInteger.ONE)
        );

        BigInteger gm = publicKey.g.modPow(plaintext, publicKey.nSquared);
        BigInteger rn = r.modPow(publicKey.n, publicKey.nSquared);

        return gm.multiply(rn).mod(publicKey.nSquared);
    }

    public static BigInteger decrypt(BigInteger ciphertext, PrivateKey privateKey) {
        PublicKey publicKey = privateKey.publicKey;

        BigInteger x = ciphertext.modPow(privateKey.lambda, publicKey.nSquared);
        BigInteger l = lFunction(x, publicKey.n);

        return l.multiply(privateKey.mu).mod(publicKey.n);
    }

    public static BigInteger addCiphertexts(
            BigInteger c1,
            BigInteger c2,
            PublicKey publicKey
    ) {
        return c1.multiply(c2).mod(publicKey.nSquared);
    }

    public static BigInteger multiplyByScalar(
            BigInteger ciphertext,
            long scalar,
            PublicKey publicKey
    ) {
        return ciphertext.modPow(BigInteger.valueOf(scalar), publicKey.nSquared);
    }

    public static BigInteger multiplyByScalar(
            BigInteger ciphertext,
            BigInteger scalar,
            PublicKey publicKey
    ) {
        return ciphertext.modPow(scalar, publicKey.nSquared);
    }

    private static BigInteger lFunction(BigInteger x, BigInteger n) {
        return x.subtract(BigInteger.ONE).divide(n);
    }

    private static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.multiply(b).abs().divide(a.gcd(b));
    }
}
