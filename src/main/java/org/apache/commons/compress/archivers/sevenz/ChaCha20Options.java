/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.commons.compress.archivers.sevenz;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * Options for {@link SevenZMethod#CHACHA20POLY1305SHA256} encoder
 *
 * @since 1.23
 * @see ChaCha20Decoder
 */
public class ChaCha20Options implements CipherOptions {

    private static final byte[] EMPTY_BYTE_ARRAY = {};

    static final String ALGORITHM = "ChaCha20";

    static final String TRANSFORMATION = "ChaCha20-Poly1305";

    static final int NONE_SIZE = 16;
    static final int PBKDF2_ITERATIONS = 210_000;

    static SecretKeySpec newSecretKeySpec(final byte[] bytes) {
        return new SecretKeySpec(bytes, ALGORITHM);
    }

    private static byte[] randomBytes(final int size) {
        final byte[] bytes = new byte[size];
        try {
            SecureRandom.getInstanceStrong().nextBytes(bytes);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("No strong secure random available to generate strong AES key", e);
        }
        return bytes;
    }

    private final byte[] salt;
    private final byte[] iv;

    private final int numCyclesPower;

    private final Cipher cipher;

    /**
     * @param password password used for encryption
     */
    ChaCha20Options(final char[] password) {
        this(password, EMPTY_BYTE_ARRAY, randomBytes(NONE_SIZE), PBKDF2_ITERATIONS);
    }

    /**
     * @param password       password used for encryption
     * @param salt           for password hash salting (enforce password security)
     * @param iv             Initialization Vector (IV) used by cipher algorithm
     * @param numCyclesPower another password security enforcer parameter that controls the cycles of password hashing. More the this number is high, more
     *                       security you'll have but also high CPU usage
     */
    ChaCha20Options(final char[] password, final byte[] salt, final byte[] iv, final int numCyclesPower) {
        this.salt = salt;
        this.iv = iv;
        this.numCyclesPower = numCyclesPower;

        // NOTE: for security purposes, password is wrapped in a Cipher as soon as possible to not stay in memory
        final byte[] aesKeyBytes = kdf(password, numCyclesPower, salt);
        final SecretKey aesKey = newSecretKeySpec(aesKeyBytes);

        try {
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        } catch (final GeneralSecurityException generalSecurityException) {
            throw new IllegalStateException("Encryption error (do you have the JCE Unlimited Strength Jurisdiction Policy Files installed?)",
                    generalSecurityException);
        }
    }

    Cipher getCipher() {
        return cipher;
    }

    byte[] getIv() {
        return iv;
    }

    int getNumCyclesPower() {
        return numCyclesPower;
    }

    byte[] getSalt() {
        return salt;
    }

    public static byte[] kdf(char[] password, int numCyclesPower, byte[] salt) {
        try {
            KeySpec spec = new PBEKeySpec(password, salt, numCyclesPower, 256);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

            return factory.generateSecret(spec).getEncoded();
        }catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] kdf(byte[] password, int numCyclesPower, byte[] salt) {

        if(numCyclesPower < PBKDF2_ITERATIONS) {
            numCyclesPower = PBKDF2_ITERATIONS;
        }
        try {
            KeySpec spec = new PBEKeySpec(Base64.getEncoder().withoutPadding().encodeToString(password).toCharArray(), salt, numCyclesPower, 256);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

            return factory.generateSecret(spec).getEncoded();
        }catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
