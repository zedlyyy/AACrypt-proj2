package com.proj2.cryptoUtility;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class Sha256Index {

    private Sha256Index() {}

    public static String token(String value) throws NoSuchAlgorithmException {
        String normalized = value.trim().toLowerCase();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(normalized.getBytes(StandardCharsets.UTF_8));
        return toHex(hash);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();

        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }

        return builder.toString();
    }
}
