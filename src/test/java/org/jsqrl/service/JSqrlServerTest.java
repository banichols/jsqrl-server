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
import org.jsqrl.server.JSqrlServer;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Created by Brent on 7/12/2016.
 */
@RunWith(MockitoJUnitRunner.class)
@Slf4j
public class JSqrlServerTest {

    private static final String IP_ADDRESS = "IP_ADDRESS";
    private static final Integer COUNT = 9;
    private static final Integer RANDOM = 4; //chosen by fair dice roll. guaranteed to be random.
    private static final String NUT_STRING = "NUT_STRING";
    private static final String NUT_STRING_2 = "NUT_STRING_2";
    private static final String SQRL_VERSION = "SQRL_VERSION";
    private static final Long NUT_EXPIRATION = 1000L;
    private static final String SFN = "SFN";
    private static final String SQRL_BASE = "/sqrlbase";
    private static final String VERIFY_UNLOCK_KEY = "VERIFY_UNLOCK_KEY";
    private static final String SERVER_UNLOCK_KEY = "SERVER_UNLOCK_KEY";
    private static final String SERVER = "SERVER";

    private PrivateKey clientPrivateKey;
    private PublicKey clientPublicKey;
    private byte[] idk;
    private String idkEncoded;

    @Mock
    private SqrlUserService userService;
    @Mock
    private SqrlAuthenticationService sqrlSqrlAuthenticationService;
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

        jSqrlServer = new JSqrlServer(userService, sqrlSqrlAuthenticationService, config, nutService);

        when(nutService.createNutFromString(NUT_STRING)).thenReturn(sqrlNut);
        when(nutService.getNutString(sqrlNut)).thenReturn(NUT_STRING);
        when(sqrlNut.getCreated()).thenReturn(LocalDateTime.now().minus(10, ChronoUnit.SECONDS));
        when(sqrlNut.isQr()).thenReturn(true);

        when(nutService.createNut(IP_ADDRESS, true)).thenReturn(sqrlNut2);
        when(nutService.getNutString(sqrlNut2)).thenReturn(NUT_STRING_2);

        when(sqrlUser.sqrlEnabled()).thenReturn(true);

        EdDSAParameterSpec edDsaSpec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512);
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
                "suk",
                null,
                null);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertThat(response.getTif()).isZero();

        verify(sqrlSqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);

    }

    @Test
    public void testHandleClientRequest_ident_new_user() {
        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(null);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "ident",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                "suk",
                SERVER_UNLOCK_KEY,
                VERIFY_UNLOCK_KEY);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertThat(response.getTif()).isEqualTo(1);

        verify(sqrlSqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);
        verify(userService).registerSqrlUser(idkEncoded, SERVER_UNLOCK_KEY, VERIFY_UNLOCK_KEY);
    }

    @Test
    public void testHandleClientRequest_ident_disabled_user() {

        when(sqrlUser.sqrlEnabled()).thenReturn(false);

        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(sqrlUser);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "ident",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                "suk",
                SERVER_UNLOCK_KEY,
                VERIFY_UNLOCK_KEY);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertThat(response.getTif()).isEqualTo(TransactionInformationFlag.ID_MATCH.getHexValue() | TransactionInformationFlag.SQRL_DISABLED.getHexValue());

        verify(sqrlSqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);
        verify(sqrlSqrlAuthenticationService, never()).authenticateNut(anyString(), anyString());
    }

    @Test
    public void testHandleClientRequest_disable_existing_user() {
        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(sqrlUser);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "disable",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                "suk",
                null,
                null);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertThat(response.getTif()).isEqualTo(TransactionInformationFlag.ID_MATCH.getHexValue());

        verify(sqrlSqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);
        verify(userService).disableSqrlUser(idkEncoded);
    }

    @Test
    public void testHandleClientRequest_enable_existing_user() {
        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(sqrlUser);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "enable",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                "suk",
                null,
                null);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertThat(response.getTif()).isEqualTo(TransactionInformationFlag.ID_MATCH.getHexValue());

        verify(sqrlSqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);
        verify(userService).enableSqrlUser(idkEncoded);
    }

    @Test
    public void testHandleClientRequest_remove_existing_user() {
        when(userService.getUserBySqrlKey(idkEncoded)).thenReturn(sqrlUser);

        String clientRequestString = createClientRequestMapString(SQRL_VERSION,
                "remove",
                SqrlUtil.unpaddedBase64UrlEncoded(idk),
                "suk",
                null,
                null);

        SqrlClientRequest request = createClientRequest(clientRequestString, SERVER, clientPrivateKey);

        SqrlAuthResponse response = jSqrlServer.handleClientRequest(request, NUT_STRING, IP_ADDRESS);

        assertThat(response.getNut()).isEqualTo(NUT_STRING_2);
        assertThat(response.getVer()).isEqualTo(SQRL_VERSION);
        assertThat(response.getQry()).isEqualTo(SQRL_BASE + "?nut=" + NUT_STRING_2);
        assertThat(response.getTif()).isEqualTo(TransactionInformationFlag.ID_MATCH.getHexValue());

        verify(sqrlSqrlAuthenticationService).linkNut(NUT_STRING, NUT_STRING_2);
        verify(userService).getUserBySqrlKey(idkEncoded);
        verify(userService).removeSqrlUser(idkEncoded);
    }

    private SqrlClientRequest createClientRequest(String unencodedClientString, String unencodedServerString, PrivateKey privateKey) {
        String client = SqrlUtil.unpaddedBase64UrlEncoded(unencodedClientString);
        String server = SqrlUtil.unpaddedBase64UrlEncoded(unencodedServerString);
        byte[] ids = signRequest(client, server, clientPrivateKey);

        SqrlClientRequest request = new SqrlClientRequest();
        request.setClient(client);
        request.setServer(server);
        request.setIds(SqrlUtil.unpaddedBase64UrlEncoded(ids));

        return request;

    }

    private String createClientRequestMapString(String ver,
                                                String cmd,
                                                String idk,
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

        if (string != null && string.endsWith("\n")) {
            string = string.substring(0, string.length() - 1);
        }

        return string;
    }

    private void appendKeyValueLine(StringBuilder sb, String key, String value) {
        sb.append(key).append("=").append(value).append("\n");
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

}
