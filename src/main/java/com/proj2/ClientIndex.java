package com.proj2;

import com.proj2.cryptoUtility.OpeCrypto;
import com.proj2.cryptoUtility.PaillierCrypto;
import com.proj2.cryptoUtility.RsaMultiplicativeCrypto;

public class ClientIndex {

    public String deterministicKeyBase64;
    public String randomKeyBase64;

    public PaillierCrypto.KeyPair paillierKeyPair;
    public RsaMultiplicativeCrypto.RsaKeyPair rsaKeyPair;

    public OpeCrypto ope;
}
