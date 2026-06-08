package com.proj2;

import com.proj2.crypto.OpeCrypto;
import com.proj2.crypto.PaillierCrypto;
import com.proj2.crypto.RsaMultiplicativeCrypto;

public class ClientIndex {

    public String deterministicKeyBase64;
    public String randomKeyBase64;

    public PaillierCrypto.KeyPair paillierKeyPair;
    public RsaMultiplicativeCrypto.RsaKeyPair rsaKeyPair;

    public OpeCrypto ope;
}
