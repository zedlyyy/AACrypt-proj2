package com.proj2.cryptoUtility;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

public final class RsaMultiplicativeCrypto {

    private RsaMultiplicativeCrypto() {}

    public static class PublicKey {
        public final BigInteger n;
        public final BigInteger e;

        public PublicKey(BigInteger n, BigInteger e) {
            this.n = n;
            this.e = e;
        }
    }

    public static class PrivateKey {
        public final BigInteger n;
        public final BigInteger d;

        public PrivateKey(BigInteger n, BigInteger d) {
            this.n = n;
            this.d = d;
        }
    }

    public static class RsaKeyPair {
        public final PublicKey publicKey;
        public final PrivateKey privateKey;

        public RsaKeyPair(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }
    }

    public static RsaKeyPair generateKeyPair(int bitLength) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bitLength);

            KeyPair keyPair = generator.generateKeyPair();

            RSAPublicKey javaPublicKey = (RSAPublicKey) keyPair.getPublic();

            RSAPrivateCrtKey javaPrivateKey = (RSAPrivateCrtKey) keyPair.getPrivate();

            PublicKey publicKey = new PublicKey(javaPublicKey.getModulus(), javaPublicKey.getPublicExponent());

            PrivateKey privateKey = new PrivateKey(javaPrivateKey.getModulus(), javaPrivateKey.getPrivateExponent());

            return new RsaKeyPair(publicKey, privateKey);

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }

    public static BigInteger encrypt(BigInteger plaintext, PublicKey publicKey) {
        validatePlaintext(plaintext, publicKey.n);
        return plaintext.modPow(publicKey.e, publicKey.n);
    }

    public static BigInteger encrypt(long plaintext, PublicKey publicKey) {
        return encrypt(BigInteger.valueOf(plaintext), publicKey);
    }

    public static BigInteger decrypt(BigInteger ciphertext, PrivateKey privateKey) {
        validateCiphertext(ciphertext, privateKey.n);
        return ciphertext.modPow(privateKey.d, privateKey.n);
    }

    public static BigInteger multiplyCiphertexts(
            BigInteger c1,
            BigInteger c2,
            PublicKey publicKey
    ) {
        validateCiphertext(c1, publicKey.n);
        validateCiphertext(c2, publicKey.n);

        return c1.multiply(c2).mod(publicKey.n);
    }

    private static void validatePlaintext(BigInteger plaintext, BigInteger n) {
        if (plaintext == null) {
            throw new IllegalArgumentException("Plaintext cannot be null.");
        }

        if (plaintext.signum() < 0 || plaintext.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Plaintext must be in range [0, n).");
        }
    }

    private static void validateCiphertext(BigInteger ciphertext, BigInteger n) {
        if (ciphertext == null) {
            throw new IllegalArgumentException("Ciphertext cannot be null.");
        }

        if (ciphertext.signum() < 0 || ciphertext.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Ciphertext must be in range [0, n).");
        }
    }
}
