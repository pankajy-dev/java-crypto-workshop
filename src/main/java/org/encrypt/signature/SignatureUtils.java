package org.encrypt.signature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SignatureUtils {
    private static final String SIGNING_ALGO = "SHA256withRSA";

    public static byte[] createDigitalSignature(byte[] input, PrivateKey privateKey) throws Exception{
        Signature signature = Signature.getInstance(SIGNING_ALGO);
        signature.initSign(privateKey);
        signature.update(input);
        return signature.sign();
    }

    public static boolean verifySignature(byte[] input, byte[] signatureToVerify, PublicKey publicKey) throws Exception{
        Signature signature = Signature.getInstance(SIGNING_ALGO);
        signature.initVerify(publicKey);
        signature.update(input);
        return signature.verify(signatureToVerify);
    }
}
