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
import org.jsqrl.config.SqrlConfig;
import org.jsqrl.nut.SqrlNut;
import org.jsqrl.server.JSqrlServer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
    private static final String SQRL_VERSION = "SQRL_VERSION";
    private static final Long NUT_EXPIRATION = 1000L;
    private static final String SFN = "SFN";
    private static final String CLIENT_REQUEST_STRING = "CLIENT_REQUEST_STRING";
    private static final String SERVER_REQUEST_STRING = "SERVER_REQUEST_STRING";
    private static final String IDENTITY_KEY = "IDENTITY_KEY";
    private static final String VERIFY_UNLOCK_KEY = "VERIFY_UNLOCK_KEY";
    private static final String SERVER_UNLOCK_KEY = "SERVER_UNLOCK_KEY";
    private static final String OPTION = "OPTION";

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

    @InjectMocks
    private JSqrlServer jSqrlServer;

    @Before
    public void setup() {

        config = new SqrlConfig();
        config.setSqrlVersion(SQRL_VERSION);
        config.setNutExpirationSeconds(NUT_EXPIRATION);
        config.setSfn(SFN);

        jSqrlServer = new JSqrlServer(userService, sqrlSqrlAuthenticationService, config, nutService);

        when(nutService.createNut(IP_ADDRESS, true)).thenReturn(sqrlNut);
        when(nutService.getNutString(sqrlNut)).thenReturn(NUT_STRING);

    }

    @Test
    public void test_createAuthenticationRequest() {

        assertThat(jSqrlServer.createAuthenticationRequest(IP_ADDRESS, true)).isEqualTo(NUT_STRING);

        verify(nutService).createNut(IP_ADDRESS, true);
        verify(nutService).getNutString(sqrlNut);

    }

/*    @Test
    public void testHandleClientRequest_query(){

        String clientRequestString = createClientRequestMapString(SQRL_VERSION, IDENTITY_KEY, "suk", null, null);

        SqrlClientRequest request = new SqrlClientRequest();
        request.setClient(SqrlUtil.unpaddedBase64UrlEncoded(clientRequestString));

        when(nutService.createNutFromString(NUT_STRING)).thenReturn(sqrlNut2);
    }*/


    private String createClientRequestMapString(String ver, String idk, String opt, String suk, String vuk) {
        StringBuilder stringBuilder = new StringBuilder();

        if (ver != null) {
            appendKeyValueLine(stringBuilder, "ver", ver);
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
        sb.append(key).append("=").append("\n");
    }

}
