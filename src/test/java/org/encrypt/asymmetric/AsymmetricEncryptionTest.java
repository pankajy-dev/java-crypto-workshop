package org.encrypt.asymmetric;

import java.security.KeyPair;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AsymmetricEncryptionTest {

    @Test
    void performEncryptionRoutineTest() throws Exception {
        String plainText = "doming suscipit ea nonumy dolore";
        System.out.println("Original text : " + plainText);
        KeyPair keyPair = AsymmetricEncryption.generateKeyPair();
        byte[] cipherText = AsymmetricEncryption.performRsaEncryption(plainText, keyPair.getPublic());
        System.out.println(Base64.getEncoder().encodeToString(cipherText));

        String decryptedText = AsymmetricEncryption.performDecryption(cipherText, keyPair.getPrivate());
        System.out.println("Decrypted text :" + decryptedText);
        assertEquals(plainText, decryptedText);
    }
}