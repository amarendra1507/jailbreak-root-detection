package com.smartwinnr.plugins.jailbreakrootdetection;

import java.security.SecureRandom;
import android.util.Base64;

public class NonceUtil {

    public static String generateNonce(int length) {
        // Step 1: Generate a random byte array (nonce)
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[length];
        secureRandom.nextBytes(nonce);

        // Step 2: Base64 encode the byte array
        String base64Nonce = Base64.encodeToString(nonce, Base64.NO_WRAP);

        // Step 3: Make the base64 string URL-safe
        String urlSafeNonce = base64Nonce.replace('+', '-').replace('/', '_');

        // Step 4: Remove padding
        urlSafeNonce = urlSafeNonce.replaceAll("=+$", "");

        return urlSafeNonce;
    }
}

