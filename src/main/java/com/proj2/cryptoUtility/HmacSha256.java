package com.proj2.cryptoUtility;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public final class HmacSha256 {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int KEY_SIZE_BITS = 256;

    private HmacSha256() {}

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(HMAC_ALGORITHM);
            keyGenerator.init(KEY_SIZE_BITS);
            return keyGenerator.generateKey();
    }

    public static String compute(String message, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(key);

            byte[] result = mac.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(result);
    }

    public static boolean verify(String message, String expectedMac, SecretKey key) throws InvalidKeyException, NoSuchAlgorithmException {
        String actualMac = compute(message, key);

        return actualMac.equals(expectedMac);
    }

}