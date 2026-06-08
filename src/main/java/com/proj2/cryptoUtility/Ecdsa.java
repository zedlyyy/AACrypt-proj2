package com.proj2.cryptoUtility;

import java.security.*;
import java.util.Base64;

public final class Ecdsa {

    private static final String KEY_ALGORITHM = "EC";
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final int KEY_SIZE_BITS = 256;

    private Ecdsa() {}

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            generator.initialize(KEY_SIZE_BITS);
            return generator.generateKeyPair();
    }

    public static String sign(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(message.getBytes());

            byte[] signatureBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);

    }

    public static boolean verify( String message, String signatureBase64, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(message.getBytes());

            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
            return signature.verify(signatureBytes);
    }
}
