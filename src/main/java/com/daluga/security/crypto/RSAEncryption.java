package com.daluga.security.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class RSAEncryption {

    private static final String DEFAULT_KEY_FACTORY = "RSA";
    private static final int KEY_SIZE = 2048;

    private static final String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlWCG+cxXJS2w7jotN3R2u4S1mYdyst7oGoHOH22N3vbRkdCaJQsF/07uAbEOnXKZrf/0QoDl8uvIm8x1S+mw6S/QDYgaJZdgI22XU5UZp/V2cSaBG+5OX3PvEgzzlhbKqmCuKl0FEi0SGrDjr6UFUzCWs7ZjEpUGvBctrQwzeC/XAHvLIrt1/VK90LJiAv4rgOvezVBiNccZ9VpLaMDBfqxj0PaymXX2dADpY3dB6AS2lOo0qQyzpksW4jfoU1QmZY3DH/plx+3oHjblZ6Z+HrLgv8Y8r193uBKvBQw3QqlJ702Zf0RcnskrRpsVVqAV+ygrYHRzTnj/+dU4prKpoQIDAQAB";
    private static final String PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCVYIb5zFclLbDuOi03dHa7hLWZh3Ky3ugagc4fbY3e9tGR0JolCwX/Tu4BsQ6dcpmt//RCgOXy68ibzHVL6bDpL9ANiBoll2AjbZdTlRmn9XZxJoEb7k5fc+8SDPOWFsqqYK4qXQUSLRIasOOvpQVTMJaztmMSlQa8Fy2tDDN4L9cAe8siu3X9Ur3QsmIC/iuA697NUGI1xxn1WktowMF+rGPQ9rKZdfZ0AOljd0HoBLaU6jSpDLOmSxbiN+hTVCZljcMf+mXH7egeNuVnpn4esuC/xjyvX3e4Eq8FDDdCqUnvTZl/RFyeyStGmxVWoBX7KCtgdHNOeP/51TimsqmhAgMBAAECggEAdbMcR4G5/MJ20g8nB7YNxA16ZeGy/7vh2NkEyACzs8Z5NNLQUnXQIO5ZXR3c7TSaYN734Nrd1T3x0MkWd11Il0SkQ7VFHO+cwe2dOi+WiqA/1kJHovFv8YhRDMEFwfJteDg7o4et8jdvN3a/wOtfOcBkTnBcugyQxO3igKLHf1/E2+i/+QdMZsQdanbsmQNxvw0fBfX3bI0C6ywRtKM1ZVBf4X6MSohil5/V9YDxuvD8Q7sdtNTWhOUul8ILyEoSqtQG7cS43upu5yIvEDPW67mtA2eKwVZ+D4epEKXBzFrQl6HyqDEBShln5WMEHQWZlAtZhxTpFLArfmlT0H0fAQKBgQDYjo47WLWp7fkP9zGY9fJ3PXIMCwegHW8BJ7nKPrT86jZax+W0UC1bzbeZDKut4I29xbeW/sN7eaKUJsYJZid+5DxTwn/R9T3Bie/OR5H3pKYryAHld/JvfSViZXDsZt1Ar7UToMseVDTCp1lxscwqJtXL3djlx/1ljzdwTAKJ0QKBgQCwlZB6+UawRdw/qBM+iLC6+oCR7zBx2b0eTNiiRtv+C2rSCudKvEEjMt5taHlge1Fbv1oH3qySISX/Tez3t5wDw7wzZ8CiMQ1uihRnaPX079Opjieb1rbCDUKJFqbbJVflrl+OECY81VOb+5XPXmcww9z93sZxuwu/Eb1BsyFG0QKBgHCcsRnrZ4yWU44Z3ZDNVOjs6wGYOr7oj3DqV5L0SOm8YceTa7/4cZ3rvC26iQxCWXL1/iJnGQB8oC6qexEoLiGuTjDAU/e6sAKU2D9MuHsvA7qAp3vMhCW1zlr8pVxJoYSh2mf6laWP5F/U5o5ZBvJkf4kkNEZJWVwWvZ2H6UoBAoGBAI42JcGj+BYGbTam+binBQ3QqLLe2zkVjoVUhjNKtemG8GRwe41ox1y9nvyl4vqc1gz5slwcLQcSwzM1Yt6tdGxjurH7oNv+fT7E3WHa2hqE+wXWgnezGER3wVn+cCqVjJBhOnuC7giYFVnN5/y1no1bcCLUwyTc6rzaYH0E8ovBAoGARnVclIJgd3watQZpCpNwvukIw96pmahN1Aq2bW5+hFpS2q+ImIMEC74XvVHmO2T/guvMQqXJhuYQTw2G78NLLRZgLHIB958zBEuDR/c5iUK1x2D78ok4sd33JZhXhps83eYX+Dys7QOGw34E388882xOg8b5qLhwbFwmXRsARds=";

    private static final Logger LOGGER = LoggerFactory.getLogger(RSAEncryption.class);

    public KeyPair generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(DEFAULT_KEY_FACTORY);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(KEY_SIZE, random);
        KeyPair pair = keyGen.generateKeyPair();
//        Files.write(Paths.get("publicKey"), pair.getPublic().getEncoded());
//        Files.write(Paths.get("privateKey"), pair.getPrivate().getEncoded());

        String publicKeyB64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        String privKeyB64 = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());

        LOGGER.debug("Public Key: " + publicKeyB64);
        LOGGER.debug("Private Key: " + privKeyB64);

        return pair;
    }

    public byte[] encrypt(String data) throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        byte[] decPublicKeyB64 = Base64.getDecoder().decode(PUBLIC_KEY);
        KeyFactory keyFactory = KeyFactory.getInstance(DEFAULT_KEY_FACTORY);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(decPublicKeyB64);
        PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    public String decrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        byte[] decPrivateKeyB64 = Base64.getDecoder().decode(PRIVATE_KEY);
        KeyFactory keyFactory = KeyFactory.getInstance(DEFAULT_KEY_FACTORY);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decPrivateKeyB64);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }
}
