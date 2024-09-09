package org.encrypt.signature;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Signature;
import java.util.Base64;

import org.encrypt.asymmetric.AsymmetricEncryption;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SignatureUtilsTest {

    @Test
    public void testSignatureUtils() throws Exception{
        // Load the text file from the resource file.
        URL url = this.getClass().getClassLoader().getResource("big-file.txt");
        assert url != null;
        Path path = Paths.get(url.toURI());
        byte[] input = Files.readAllBytes(path);

        // 5.b. Generate private/public keypair for signing and verification of signature.
        KeyPair keyPair = AsymmetricEncryption.generateKeyPair();

        // 5.c. Create a digital signature using the private key
        byte[] signature = SignatureUtils.createDigitalSignature(input, keyPair.getPrivate());
        System.out.println(Base64.getEncoder().encodeToString(signature));

        // 5.d. Verify the signature using the public key
        boolean isVerified = SignatureUtils.verifySignature(input, signature, keyPair.getPublic());
        assertTrue(isVerified);

        // Read the file with just once character difference then the previous file.
        url = this.getClass().getClassLoader().getResource("big-file-new.txt");
        assert url != null;
        path = Paths.get(url.toURI());
        byte[] inputNew = Files.readAllBytes(path);

        // Using new file as input and previous calculated signature.
        isVerified = SignatureUtils.verifySignature(inputNew, signature, keyPair.getPublic());

        assertFalse(isVerified);
    }

}