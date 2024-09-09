package org.encrypt.hash;

import java.security.MessageDigest;

public class HashUtils {
    private static final String SHA2_ALGO = "SHA-256";

    public static byte[] createSha2Hash(String input) throws Exception{
        MessageDigest messageDigest = MessageDigest.getInstance(SHA2_ALGO);
        return messageDigest.digest(input.getBytes());
    }
}
