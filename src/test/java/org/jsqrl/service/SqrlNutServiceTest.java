package org.jsqrl.service;


import lombok.extern.slf4j.Slf4j;
import org.jsqrl.config.SqrlConfig;
import org.jsqrl.nut.SqrlNut;
import org.jsqrl.util.SqrlUtil;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created by banic_000 on 7/9/2016.
 */
@Slf4j
public class SqrlNutServiceTest {


    private SqrlNutService service;
    private Key key;

    @Before
    public void setup() throws NoSuchAlgorithmException {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        key = keyGen.generateKey();

        MessageDigest hasher = MessageDigest.getInstance("SHA-256");

        Random rng = new SecureRandom();

        SqrlConfig config = new SqrlConfig();

        service = new SqrlNutService(rng, config, hasher, key);

    }

    @Test
    public void nutEncodeAndDecode() throws Exception {

        SqrlNut nut = service.createNut("1", true);

        log.debug("Created: {}", nut.getCreated());

        String nutString = service.getNutString(nut);

        SqrlNut recreatedNut = service.createNutFromString(nutString);

        assertThat(nut.getCount()).isEqualTo(recreatedNut.getCount());
        assertThat(nut.isQr()).isEqualTo(recreatedNut.isQr());
        assertThat(nut.getCreated()).isEqualTo(recreatedNut.getCreated());

    }

    @Test
    public void testIpMatch() throws Exception {

        String IP_ADDRESS = "0:0:0:0:0:0:0:1";

        SqrlNut nut1 = service.createNut(IP_ADDRESS, true);

        //Turn the nut into a string and recreate it
        String nut1String = service.getNutString(nut1);
        SqrlNut recreatedNut1 = service.createNutFromString(nut1String);

        SqrlNut nut2 = service.createNut(IP_ADDRESS, false);

        assertThat(recreatedNut1.checkIpMatch(nut2)).isTrue();

    }

    @Test
    public void testEncryptDecrypt() throws Exception {

        String toEncrypt = "asdfasdfasdfasdf";

        byte[] encrypted = getCipher(Cipher.ENCRYPT_MODE).doFinal(toEncrypt.getBytes());

        String encryptedStr = new String(encrypted);

        log.debug("Encrypted: {}", encryptedStr);

        byte[] decrypted = getCipher(Cipher.DECRYPT_MODE).doFinal(encrypted);

        String decryptedStr = new String(decrypted);
        System.out.println("Decrypted: " + decryptedStr);

    }

    @Test
    public void testEncryptDecryptEncode() throws Exception {

        String toEncrypt = "asdfasdfasdfasdf";

        byte[] encrypted = getCipher(Cipher.ENCRYPT_MODE).doFinal(toEncrypt.getBytes());

        String encryptedStr = new String(encrypted);

        log.debug("Encrypted string: {}", encryptedStr);

        String encoded = SqrlUtil.unpaddedBase64UrlEncoded(encrypted);

        log.debug("Encoded: {}", encoded);

        byte[] decoded = SqrlUtil.base64UrlDecode(encoded);

        log.debug("Decoded: {}", decoded);

        byte[] decrypted = getCipher(Cipher.DECRYPT_MODE).doFinal(decoded);

        log.debug("Decrypted: {}", new String(decrypted));

    }

    private Cipher getCipher(int encryptMode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(encryptMode, key);
        return cipher;
    }

}