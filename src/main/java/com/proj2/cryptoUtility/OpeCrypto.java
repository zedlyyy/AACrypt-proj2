package com.proj2.cryptoUtility;

import java.util.TreeMap;

public class OpeCrypto {

    private final TreeMap<Integer, Long> plaintextToCiphertext = new TreeMap<>();
    private final TreeMap<Long, Integer> ciphertextToPlaintext = new TreeMap<>();

    private static final long GAP = 1_000_000L;

    public synchronized long encrypt(int value) {
        if (plaintextToCiphertext.containsKey(value)) {
            return plaintextToCiphertext.get(value);
        }

        long ciphertext;

        if (plaintextToCiphertext.isEmpty()) {
            ciphertext = GAP;
        } else {
            Integer lower = plaintextToCiphertext.lowerKey(value);
            Integer higher = plaintextToCiphertext.higherKey(value);

            if (lower == null) {
                ciphertext = plaintextToCiphertext.get(higher) / 2;
            } else if (higher == null) {
                ciphertext = plaintextToCiphertext.get(lower) + GAP;
            } else {
                long lowCipher = plaintextToCiphertext.get(lower);
                long highCipher = plaintextToCiphertext.get(higher);

                ciphertext = (lowCipher + highCipher) / 2;

                if (ciphertext == lowCipher || ciphertext == highCipher) {
                    throw new IllegalStateException("OPE ciphertext space exhausted.");
                }
            }
        }

        plaintextToCiphertext.put(value, ciphertext);
        ciphertextToPlaintext.put(ciphertext, value);

        return ciphertext;
    }

    public synchronized int decrypt(long ciphertext) {
        Integer value = ciphertextToPlaintext.get(ciphertext);

        if (value == null) {
            throw new IllegalArgumentException("Unknown OPE ciphertext.");
        }

        return value;
    }
}
