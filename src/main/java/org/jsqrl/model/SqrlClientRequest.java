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

package org.jsqrl.model;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.jsqrl.util.SqrlUtil;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * An object representing a SQRL Client Request.
 * Helper methods are created to help get the various
 * parameters of a client request.
 * <p>
 * Created by Brent Nichols
 */
@Getter
@Setter
public class SqrlClientRequest {

    private static final String REQUEST_VERSION = "ver";
    private static final String COMMAND = "cmd";
    private static final String OPTIONS = "opt";
    private static final String IDENTITY_KEY = "idk";
    private static final String PREVIOUS_IDENTITY_KEY = "pidk";
    private static final String SERVER_UNLOCK_KEY = "suk";
    private static final String VERIFY_UNLOCK_KEY = "vuk";
    private static final String BUTTON = "btn";

    //Client request parameters
    private String client;

    //Server request
    private String server;

    //ID Signature
    private String ids;

    //Previous ID Signature
    private String pids;

    private Map<String, String> clientParameters;
    private Map<String, String> serverParameters;

    private Set<SqrlOptionFlag> optionFlags;

    public void setClient(String client) {
        this.client = client;
        clientParameters = parseParameterString(new String(SqrlUtil.base64UrlDecode(client)));
        optionFlags = parseOptionFlags(clientParameters);
    }

    public String getClientParameter(String parameter) {
        return MapUtils.getString(clientParameters, parameter);
    }

    public String getIdentityKey() {
        return getClientParameter(IDENTITY_KEY);
    }

    public String getPreviousIdentityKey() {
        return getClientParameter(PREVIOUS_IDENTITY_KEY);
    }

    public String getServerUnlockKey() {
        return getClientParameter(SERVER_UNLOCK_KEY);
    }

    public String getVerifyUnlockKey() {
        return getClientParameter(VERIFY_UNLOCK_KEY);
    }

    public String getRequestVersion() {
        return getClientParameter(REQUEST_VERSION);
    }

    public String getButton() {
        return getClientParameter(BUTTON);
    }

    public SqrlCommand getCommand() {
        return SqrlCommand.from(getClientParameter(COMMAND));
    }

    public String getDecodedClientData() {
        return new String(SqrlUtil.base64UrlDecode(client));
    }

    public String getDecodedServerData() {
        return new String(SqrlUtil.base64UrlDecode(server));
    }

    public byte[] getDecodedIdentitySignature() {
        return getDecodedSignature(ids);
    }

    public byte[] getDecodedPreviousIdSignature() {
        return getDecodedSignature(pids);
    }

    private byte[] getDecodedSignature(String signature) {
        if (signature != null) {
            return SqrlUtil.base64UrlDecode(signature);
        } else {
            return null;
        }
    }

    private Map<String, String> parseParameterString(String decodedString) {

        if (StringUtils.isBlank(decodedString)) {
            return new HashMap<>();
        }

        String[] keyValuePairs = StringUtils.split(decodedString, "\n");

        return Stream.of(keyValuePairs)
                .map(StringUtils::trimToEmpty)
                .map(v -> v.split("="))
                .filter(v -> v != null && v.length > 1)
                .collect(Collectors.toMap(k -> k[0], v -> v[1]));

    }

    private Set<SqrlOptionFlag> parseOptionFlags(Map<String, String> clientParameters) {
        String optionString = clientParameters.get(OPTIONS);
        return (optionString == null) ? null :
                Stream.of(optionString.split("~"))
                .map(SqrlOptionFlag::from)
                .filter(o -> o != null)
                .collect(Collectors.toSet());
    }

}
