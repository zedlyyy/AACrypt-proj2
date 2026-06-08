package com.proj2.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public final class AesCtrCrypto {

    private static final String KEY_ALGORITHM = "AES";
    private static final String CIPHER_SUITE = "AES/CTR/NoPadding";

    private static final int AES_KEY_SIZE_BITS = 256;
    private static final int IV_SIZE_BYTES = 16;

    private static final SecureRandom secureRandom = new SecureRandom();

    private AesCtrCrypto() {}

    public static SecretKey generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
            keyGenerator.init(AES_KEY_SIZE_BITS);
            return keyGenerator.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate AES-256 key", e);
        }
    }

    public static String encrypt(String plaintext, SecretKey key) {
        byte[] iv = new byte[IV_SIZE_BYTES];
        secureRandom.nextBytes(iv);

        byte[] ciphertext = doCipher(Cipher.ENCRYPT_MODE, plaintext.getBytes(StandardCharsets.UTF_8), key, iv);

        byte[] combined = concatenate(iv, ciphertext);
        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decrypt(String encoded, SecretKey key) {
        byte[] combined = Base64.getDecoder().decode(encoded);

        if (combined.length < IV_SIZE_BYTES) {
            throw new IllegalArgumentException("Invalid AES/CTR ciphertext.");
        }

        byte[] iv = Arrays.copyOfRange(combined, 0, IV_SIZE_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(combined, IV_SIZE_BYTES, combined.length);

        byte[] plaintext = doCipher(Cipher.DECRYPT_MODE, ciphertext, key, iv);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    
    public static String encryptDeterministic(String plaintext, SecretKey key) {
        byte[] fixedIV = new byte[IV_SIZE_BYTES];
        
        byte[] ciphertext = doCipher(Cipher.ENCRYPT_MODE, plaintext.getBytes(StandardCharsets.UTF_8), key, fixedIV);

        return Base64.getEncoder().encodeToString(ciphertext);
    }
    
    public static String decryptDeterministic(String encoded, SecretKey key) {
        byte[] ciphertext = Base64.getDecoder().decode(encoded);
        byte[] fixedIV = new byte[IV_SIZE_BYTES];
        byte[] plaintext = doCipher(Cipher.DECRYPT_MODE, ciphertext, key, fixedIV);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private static byte[] doCipher(int mode, byte[] input, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_SUITE);
            cipher.init(mode, key, new IvParameterSpec(iv));
            return cipher.doFinal(input);
        } catch (Exception e) {
            throw new RuntimeException("AES/CTR operation failed", e);
        }
    }

    private static byte[] concatenate(byte[] left, byte[] right) {
        byte[] result = new byte[left.length + right.length];
        System.arraycopy(left, 0, result, 0, left.length);
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }

}
