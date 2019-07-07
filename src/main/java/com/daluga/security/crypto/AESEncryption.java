package com.daluga.security.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AESEncryption {

    // AESEncryption is a symmetrical block cipher with a 128-bit size, which equates to 16 bytes.
    private static final int INITIALIZATION_VECTOR_LENGTH_BYTES = 16;
    private static final String AES_TRANSFORMATION_MODE = "AES/CBC/PKCS5Padding";
    private static final String ALGORITHM = "AES";

    private static final Logger LOGGER = LoggerFactory.getLogger(AESEncryption.class);

    public static String encrypt(String strToEncrypt, String secret) {
        return encrypt(strToEncrypt, secret, null);
    }

    public static String encrypt(String strToEncrypt, String secret, String salt) {
        try {

            SecretKeySpec secretKeySpec = getSecretKeySpec(secret, salt);

            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION_MODE);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new SecureRandom());

            // Encrypt the string
            byte[] encryptedBytes = cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8));

            // Get the initialization vector from the cipher
            byte[] initializationVector = cipher.getIV();

            // Append the initialization vector as a prefix to use it during decryption
            byte[] combinedPayload = new byte[initializationVector.length + encryptedBytes.length];

            // Populate the payload with prefix initialization vector and encrypted data
            System.arraycopy(initializationVector, 0, combinedPayload, 0, initializationVector.length);
            System.arraycopy(encryptedBytes, 0, combinedPayload, initializationVector.length, encryptedBytes.length);

            return Base64.getEncoder().encodeToString(combinedPayload);
         } catch (Exception e) {
            LOGGER.error("Error while encrypting: " + e.toString(), e);
        }

        return null;
    }

    public static String decrypt(String strToDecrypt, String secret) {
        return decrypt(strToDecrypt, secret, null);
    }

    public static String decrypt(String strToDecrypt, String secret, String salt) {
        try {
            byte[] encryptedPayload = Base64.getDecoder().decode(strToDecrypt);
            byte[] initializationVector = new byte[INITIALIZATION_VECTOR_LENGTH_BYTES];
            byte[] encryptedBytes = new byte[encryptedPayload.length - initializationVector.length];

            // Populate the initialization vector
            System.arraycopy(encryptedPayload, 0, initializationVector, 0, 16);

            // Populate the encrypted bytes
            System.arraycopy(encryptedPayload, initializationVector.length, encryptedBytes, 0, encryptedBytes.length);

            SecretKeySpec secretKeySpec = getSecretKeySpec(secret, salt);

            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION_MODE);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(initializationVector));
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            LOGGER.error("Error while decrypting: " + e.toString(), e);
        }

        return null;
    }

    private static SecretKeySpec getSecretKeySpec(String secret, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeySpec secretKeySpec = null;

        if (salt == null) {
            secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        } else {
            secretKeySpec = getSecretKeySpecWithSalt(secret, salt);
        }

        return secretKeySpec;
    }

    private static SecretKeySpec getSecretKeySpecWithSalt(String secret, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
    }

    public static String getGeneratedSalt() throws NoSuchAlgorithmException {
        // See this for more details: https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecureRandom
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

//    private static SecureRandom getSecureRandom() throws NoSuchAlgorithmException {
//        return SecureRandom.getInstance("SHA1PRNG");
//    }
}