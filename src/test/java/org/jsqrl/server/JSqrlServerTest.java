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

package org.jsqrl.server;

import lombok.extern.slf4j.Slf4j;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import org.jsqrl.config.SqrlConfig;
import org.jsqrl.error.SqrlException;
import org.jsqrl.model.SqrlAuthResponse;
import org.jsqrl.model.SqrlClientRequest;
import org.jsqrl.model.SqrlUser;
import org.jsqrl.model.TransactionInformationFlag;
import org.jsqrl.nut.SqrlNut;
import org.jsqrl.service.SqrlAuthenticationService;
import org.jsqrl.service.SqrlNutService;
import org.jsqrl.service.SqrlUserService;
import org.jsqrl.util.SqrlUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.security.*;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Created by Brent on 7/12/2016.
 */
@RunWith(MockitoJUnitRunner.class)
@Slf4j
public class JSqrlServerTest {

    private static final String LINE_SEPARATOR = "\r\n";
    private static final String IP_ADDRESS = "IP_ADDRESS";
    private static final Integer COUNT = 9;
    private static final Integer RANDOM = 4; //chosen by fair dice roll. guaranteed to be random.
    private static final String NUT_STRING = "NUT_STRING";
    private static final String NUT_STRING_2 = "NUT_STRING_2";
    private static final String SQRL_VERSION = "SQRL_VERSION";
    private static final Long NUT_EXPIRATION = 1000L;
    private static final String SFN = "SFN";
    private static final String SQRL_BASE = "/sqrlbase";
    private static final String PREVIOUS_ID_KEY = "PREVIOUS_ID_KEY";
    private static final String VERIFY_UNLOCK_KEY = "VERIFY_UNLOCK_KEY";
    private static final String SERVER_UNLOCK_KEY = "SERVER_UNLOCK_KEY";
    private static final String SERVER = "SERVER";

    private EdDSAParameterSpec edDsaSpec;
    private PrivateKey clientPrivateKey;
    private PublicKey clientPublicKey;
    private byte[] idk;
    private String idkEncoded;

    @Mock
    private SqrlUserService userService;
    @Mock
    private SqrlAuthenticationService sqrlAuthenticationService;
    private SqrlConfig config;
    @Mock
    private SqrlNutService nutService;
    @Mock
    private SqrlNut sqrlNut;
    @Mock
    private SqrlNut sqrlNut2;
    @Mock
    private SqrlUser sqrlUser;

    @InjectMocks
    private JSqrlServer jSqrlServer;

    @Before
    public void setup() throws InvalidAlgorithmParameterException {

        config = new SqrlConfig();
        config.setSqrlVersion(SQRL_VERSION);
        config.setNutExpirationSeconds(NUT_EXPIRATION);
        config.setSfn(SFN);
        config.setSqrlBaseUri(SQRL_BASE);

        jSqrlServer = new JSqrlServer(userService, sqrlAuthenticationService, config, nutService);

        when(nutService.createNutFromString(NUT_STRING)).thenReturn(sqrlNut);
        when(nutService.getNutString(sqrlNut)).thenReturn(NUT_STRING);
        when(sqrlNut.getCreated()).thenReturn(LocalDateTime.now().minus(10, ChronoUnit.SECONDS));
        when(sqrlNut.isQr()).thenReturn(true);

        when(nutService.createNut(IP_ADDRESS, true)).thenReturn(sqrlNut2);
        when(nutService.getNutString(sqrlNut2)).thenReturn(NUT_STRING_2);

        when(sqrlUser.sqrlEnabled()).thenReturn(true);

        edDsaSpec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512);
        KeyPairGenerator generator = new KeyPairGenerator();
        generator.initialize(edDsaSpec, new SecureRandom());

        KeyPair keyPair = generator.generateKeyPair();
        clientPrivateKey = keyPair.getPrivate();
        clientPublicKey = keyPair.getPublic();
        byte[] pke = clientPublicKey.getEncoded();
        idk = Arrays.copyOfRange(pke, pke.length - 32, pke.length);
        idkEncoded = SqrlUtil.unpaddedBase64UrlEncoded(idk);
    }

    @Test
    public void test_createAuthenticationRequest() {
        assertThat(jSqrlServer.createAuthenticationRequest(IP_ADDRESS, true)).isEqualTo(NUT_STRING_2);

        verify(nutService).createNut(IP_ADDRESS, true);
        verify(nutService).getNutString(sqrlNut2);
    }

    @Test
    public void testHandleClientRequest_query_user_unknown() {

        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(null);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "query",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                null,
                "suk",
                null,
                null);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertThat(response.getTif()).isZero();

        verify(sqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);

    }

    @Test
    public void testHandleClientRequest_query_user_known() {

        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(sqrlUser);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "query",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                null,
                "suk",
                null,
                null);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertThat(response.getTif()).isEqualTo(1);

        verify(sqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);

    }

    @Test
    public void testHandleClientRequest_ident_new_user() {
        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(null);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "ident",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                null,
                "suk",
                SERVER_UNLOCK_KEY,
                VERIFY_UNLOCK_KEY);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertThat(response.getTif()).isEqualTo(1);

        verify(sqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);
        verify(userService).registerSqrlUser(idkEncoded, SERVER_UNLOCK_KEY, VERIFY_UNLOCK_KEY);
    }

    @Test
    public void testHandleClientRequest_ident_by_pidk() throws Exception {

        //Generate a new key pair so we can sign the pidk
        KeyPairGenerator generator = new KeyPairGenerator();
        generator.initialize(edDsaSpec, new SecureRandom());

        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey pidkPrivate = keyPair.getPrivate();
        PublicKey pidkPublic = keyPair.getPublic();
        String pidkEncoded = getEncodedPublicKeyString(pidkPublic);

        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(null);
        when(userService.getUserBySqrlKey(pidkEncoded)).thenReturn(sqrlUser);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "ident",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                pidkEncoded,
                "suk",
                SERVER_UNLOCK_KEY,
                VERIFY_UNLOCK_KEY);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        byte[] pids = signRequest(request.getClient(), request.getServer(), pidkPrivate);
        request.setPids(SqrlUtil.unpaddedBase64UrlEncoded(pids));

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertResponseTifs(response, TransactionInformationFlag.PREVIOUS_ID_MATCH, TransactionInformationFlag.ID_MATCH);

        verify(sqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);
        verify(userService).getUserBySqrlKey(pidkEncoded);
        verify(userService).updateIdentityKey(pidkEncoded, idkEncoded);
    }

    @Test
    public void testHandleClientRequest_ident_by_pidk_invalid_pidk_sig() throws Exception {

        //Generate a new key pair so we can sign the pidk
        KeyPairGenerator generator = new KeyPairGenerator();
        generator.initialize(edDsaSpec, new SecureRandom());

        KeyPair keyPair = generator.generateKeyPair();
        PublicKey pidkPublic = keyPair.getPublic();
        String pidkEncoded = getEncodedPublicKeyString(pidkPublic);

        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(null);
        when(userService.getUserBySqrlKey(pidkEncoded)).thenReturn(sqrlUser);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "ident",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                pidkEncoded,
                "suk",
                SERVER_UNLOCK_KEY,
                VERIFY_UNLOCK_KEY);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        //Just use the original ids, it won't be valid
        request.setPids(request.getIds());

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertResponseTifs(response, TransactionInformationFlag.CLIENT_FAILURE);

        verify(sqrlAuthenticationService, never()).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService, never()).getUserBySqrlKey(anyString());
        verify(userService, never()).updateIdentityKey(anyString(), anyString());
    }

    @Test
    public void testHandleClientRequest_ident_disabled_user() {

        when(sqrlUser.sqrlEnabled()).thenReturn(false);

        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(sqrlUser);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "ident",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                null,
                "suk",
                SERVER_UNLOCK_KEY,
                VERIFY_UNLOCK_KEY);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertThat(response.getTif()).isEqualTo(TransactionInformationFlag.ID_MATCH.getHexValue() | TransactionInformationFlag.SQRL_DISABLED.getHexValue());

        verify(sqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);
        verify(sqrlAuthenticationService, never()).authenticateNut(anyString(), anyString());
    }

    @Test
    public void testHandleClientRequest_disable_existing_user() {
        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(sqrlUser);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "disable",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                null,
                "suk",
                null,
                null);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertThat(response.getTif()).isEqualTo(TransactionInformationFlag.ID_MATCH.getHexValue());

        verify(sqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);
        verify(userService).disableSqrlUser(idkEncoded);
    }

    @Test
    public void testHandleClientRequest_enable_existing_user() throws Exception {

        //Generate a new key pair so we can sign the unlock request
        KeyPairGenerator generator = new KeyPairGenerator();
        generator.initialize(edDsaSpec, new SecureRandom());

        KeyPair keyPair = generator.generateKeyPair();
        PublicKey vukPublic = keyPair.getPublic();
        PrivateKey vukPrivate = keyPair.getPrivate();

        String vuk = getEncodedPublicKeyString(vukPublic);

        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(sqrlUser);
        when(sqrlUser.getVerifyUnlockKey()).thenReturn(vuk);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "enable",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                null,
                "suk",
                null,
                null);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        byte[] urs = signRequest(request.getClient(), request.getServer(), vukPrivate);
        request.setUrs(SqrlUtil.unpaddedBase64UrlEncoded(urs));

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertThat(response.getTif()).isEqualTo(TransactionInformationFlag.ID_MATCH.getHexValue());

        verify(sqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);
        verify(userService).enableSqrlUser(idkEncoded);
    }

    @Test
    public void testHandleClientRequest_remove_existing_user() throws Exception {

        //Generate a new key pair so we can sign the unlock request
        KeyPairGenerator generator = new KeyPairGenerator();
        generator.initialize(edDsaSpec, new SecureRandom());

        KeyPair keyPair = generator.generateKeyPair();
        PublicKey vukPublic = keyPair.getPublic();
        PrivateKey vukPrivate = keyPair.getPrivate();

        String vuk = getEncodedPublicKeyString(vukPublic);

        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(sqrlUser);
        when(sqrlUser.getVerifyUnlockKey()).thenReturn(vuk);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "remove",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                null,
                "suk",
                null,
                null);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        byte[] urs = signRequest(request.getClient(), request.getServer(), vukPrivate);
        request.setUrs(SqrlUtil.unpaddedBase64UrlEncoded(urs));

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertThat(response.getTif()).isEqualTo(TransactionInformationFlag.ID_MATCH.getHexValue());

        verify(sqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);
        verify(userService).removeSqrlUser(idkEncoded);
    }

    @Test
    public void testUnverifiedSignature() throws Exception {

        //Generate a new key pair so we generate a valid signature, just one
        //that won't be verified against the original request
        KeyPairGenerator generator = new KeyPairGenerator();
        generator.initialize(edDsaSpec, new SecureRandom());

        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey invalidPrivateKey = keyPair.getPrivate();

        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(null);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "query",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                "suk",
                null,
                null,
                null);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, invalidPrivateKey);

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertResponseTifs(response, TransactionInformationFlag.CLIENT_FAILURE);

        /**TODO Is it valid to assume we shouldn't link a request with a bad signature to one that had a good signature?*/
        verify(sqrlAuthenticationService, never()).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService, never()).getUserBySqrlKey(idkEncoded);
    }

    @Test
    public void testHandleInvalidSignature() throws Exception {

        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(null);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "query",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                null,
                "suk",
                null,
                null);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);
        request.setIds("invalidsignature");

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertResponseTifs(response, TransactionInformationFlag.CLIENT_FAILURE);

        /**TODO Is it valid to assume we shouldn't link a request with a bad signature to one that had a good signature?*/
        verify(sqrlAuthenticationService, never()).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService, never()).getUserBySqrlKey(idkEncoded);
    }

    @Test
    public void test_checkAuthenticationStatus() {
        when(nutService.nutBelongsToIp(NUT_STRING, IP_ADDRESS)).thenReturn(true);
        when(sqrlAuthenticationService.getAuthenticatedSqrlIdentityKey(NUT_STRING, IP_ADDRESS)).thenReturn(idkEncoded);
        assertThat(jSqrlServer.checkAuthenticationStatus(NUT_STRING, IP_ADDRESS)).isTrue();
        verify(nutService).nutBelongsToIp(NUT_STRING, IP_ADDRESS);
        verify(sqrlAuthenticationService).getAuthenticatedSqrlIdentityKey(NUT_STRING, IP_ADDRESS);
    }

    @Test
    public void test_checkAuthenticationStatus_ip_mismatch() {
        when(nutService.nutBelongsToIp(NUT_STRING, IP_ADDRESS)).thenReturn(false);
        assertThat(jSqrlServer.checkAuthenticationStatus(NUT_STRING, IP_ADDRESS)).isFalse();
        verify(nutService).nutBelongsToIp(NUT_STRING, IP_ADDRESS);
        verify(sqrlAuthenticationService, never()).getAuthenticatedSqrlIdentityKey(anyString(), anyString());
    }

    @Test
    public void test_checkAuthenticationStatus_not_yet_authenticated() {
        when(nutService.nutBelongsToIp(NUT_STRING, IP_ADDRESS)).thenReturn(true);
        when(sqrlAuthenticationService.getAuthenticatedSqrlIdentityKey(NUT_STRING, IP_ADDRESS)).thenReturn(null);
        assertThat(jSqrlServer.checkAuthenticationStatus(NUT_STRING, IP_ADDRESS)).isFalse();
        verify(nutService).nutBelongsToIp(NUT_STRING, IP_ADDRESS);
        verify(sqrlAuthenticationService).getAuthenticatedSqrlIdentityKey(NUT_STRING, IP_ADDRESS);
    }
    
    private void assertResponseTifs(SqrlAuthResponse response, TransactionInformationFlag... expectedTifs) {

        int expectedTifValue = 0;
        if (expectedTifs != null) {
            expectedTifValue = Stream.of(expectedTifs)
                    .map(TransactionInformationFlag::getHexValue)
                    .reduce(0, (a, b) -> (a | b));
        }

        assertThat(response.getTif()).isEqualTo(expectedTifValue);
    }

    private SqrlClientRequest createClientRequest(String unencodedClientString, String unencodedServerString, PrivateKey privateKey) {
        String client = SqrlUtil.unpaddedBase64UrlEncoded(unencodedClientString);
        String server = SqrlUtil.unpaddedBase64UrlEncoded(unencodedServerString);
        byte[] ids = signRequest(client, server, privateKey);

        SqrlClientRequest request = new SqrlClientRequest();
        request.setClient(client);
        request.setServer(server);
        request.setIds(SqrlUtil.unpaddedBase64UrlEncoded(ids));

        return request;

    }

    private String createClientRequestMapString(String ver,
                                                String cmd,
                                                String idk,
                                                String pidk,
                                                String opt,
                                                String suk,
                                                String vuk) {
        StringBuilder stringBuilder = new StringBuilder();

        if (ver != null) {
            appendKeyValueLine(stringBuilder, "ver", ver);
        }

        if (ver != null) {
            appendKeyValueLine(stringBuilder, "cmd", cmd);
        }

        if (idk != null) {
            appendKeyValueLine(stringBuilder, "idk", idk);
        }

        if (pidk != null) {
            appendKeyValueLine(stringBuilder, "pidk", pidk);
        }

        if (opt != null) {
            appendKeyValueLine(stringBuilder, "opt", opt);
        }

        if (suk != null) {
            appendKeyValueLine(stringBuilder, "suk", suk);
        }

        if (vuk != null) {
            appendKeyValueLine(stringBuilder, "vuk", vuk);
        }

        String string = stringBuilder.toString();

        if (string != null && string.endsWith(LINE_SEPARATOR)) {
            string = string.substring(0, string.length() - 2);
        }

        return string;
    }

    private void appendKeyValueLine(StringBuilder sb, String key, String value) {
        sb.append(key).append("=").append(value).append(LINE_SEPARATOR);
    }

    private byte[] signRequest(String base64EncodedClient, String base64EncodedServer, PrivateKey privateKey) {

        byte[] requestMessage = (base64EncodedClient + base64EncodedServer).getBytes();
        try {

            Signature signature = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            signature.initSign(privateKey);
            signature.update(requestMessage);

            return signature.sign();

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new SqrlException("Unable to verify message signature", e);
        }
    }

    private String getEncodedPublicKeyString(PublicKey publicKey) {
        byte[] pkencoded = publicKey.getEncoded();
        byte[] key = Arrays.copyOfRange(pkencoded, pkencoded.length - 32, pkencoded.length);
        return SqrlUtil.unpaddedBase64UrlEncoded(key);
    }

}
