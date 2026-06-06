package com.proj2.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class Sha256Index {

    private Sha256Index() {}

    public static String token(String value) {
        String normalized = value.trim().toLowerCase();

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(normalized.getBytes(StandardCharsets.UTF_8));
            return toHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute SHA-256 index token", e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();

        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }

        return builder.toString();
    }
}
