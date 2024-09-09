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

        // 3.b. private/public key pair used for encryption and decryption.
        KeyPair keyPair = AsymmetricEncryption.generateKeyPair();

        // 3.c. Perform encryption on plain text using the public key.
        byte[] cipherText = AsymmetricEncryption.performRsaEncryption(plainText, keyPair.getPublic());
        System.out.println(Base64.getEncoder().encodeToString(cipherText));

        // 3.d. Perform decryption on plain text using the private key.
        String decryptedText = AsymmetricEncryption.performDecryption(cipherText, keyPair.getPrivate());
        System.out.println("Decrypted text :" + decryptedText);

        // Plain text and decrypted text are same.
        assertEquals(plainText, decryptedText);
    }
}