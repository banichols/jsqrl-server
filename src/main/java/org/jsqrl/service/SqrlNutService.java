/*
 * Copyright 2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jsqrl.service;

import org.jsqrl.config.SqrlConfig;
import org.jsqrl.error.SqrlException;
import org.jsqrl.nut.SqrlNut;
import org.jsqrl.util.SqrlUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/**
 * The service for creating SQRL Nut Objects.
 * It requires you to provide a random number generator,
 * your SQRL configuration object, a hashing method, and
 * your server's private key.
 * <p>
 * Created by Brent Nichols
 */
public class SqrlNutService {

    private Random rng;
    private SqrlConfig config;
    private MessageDigest hasher;
    private Integer count;
    private Key serverEncryptionKey;

    public SqrlNutService(Random rng,
                          SqrlConfig config,
                          MessageDigest hasher,
                          Key serverEncryptionKey) {
        this.rng = rng;
        this.config = config;
        this.hasher = hasher;
        this.serverEncryptionKey = serverEncryptionKey;
        count = 0;
    }

    /**
     * Create a new nut for the provided associated IP Address. IP Address
     * can be IPv4 or IPv6, we will only be using its hash for verification.
     *
     * @param ipAddress The IP Address to be associated with the nut
     * @return The AES encrypted and Base64 encoded string representation of the nut
     */
    public SqrlNut createNut(String ipAddress, boolean qr) {
        int random = rng.nextInt();
        count++;
        if (ipAddress == null) {
            return new SqrlNut(count, random, qr);
        } else {
            return new SqrlNut(hasher.digest(ipAddress.getBytes()), count, random, qr);
        }
    }

    /**
     * This method will tell you if the provided nut string actually belongs to the
     * IP Address that is making the request. This can be used to check the validity
     * of a nut before even attempting to check the data store
     *
     * @param nutString The nut string the user is providing
     * @param ipAddress The IP Address they are authenticating from
     * @return
     */
    public Boolean nutBelongsToIp(String nutString, String ipAddress) {
        SqrlNut nut = createNutFromString(nutString);
        return nut.checkIpMatch(hasher.digest(ipAddress.getBytes()));
    }

    /**
     * Create the AES encrypted and Base64 URL encoded nut string
     *
     * @param sqrlNut The SQRL Nut to encrypt and encode
     * @return The AES encrypted and Base64 encoded string representation of the nut
     */
    public String getNutString(SqrlNut sqrlNut) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, serverEncryptionKey);
            byte[] encrypted = cipher.doFinal(sqrlNut.toByteArray());
            return SqrlUtil.unpaddedBase64UrlEncoded(encrypted);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SqrlException("Error creating encrypted and encoded nut string", e);
        }
    }

    public SqrlNut createNutFromString(String encryptedAndEncodedNut) {
        byte[] decodedEncryptedString = SqrlUtil.base64UrlDecode(encryptedAndEncodedNut);
        try {
            byte[] decrypted = getCipher(Cipher.DECRYPT_MODE).doFinal(decodedEncryptedString);

            if (decrypted.length >= 16) {
                return new SqrlNut(decrypted);

            } else {
                throw new SqrlException("Invalid nut receieved");
            }


        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SqrlException("Error decrypting nut string", e);
        }
    }

    private Cipher getCipher(int encryptMode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(encryptMode, serverEncryptionKey);
        return cipher;
    }

}
