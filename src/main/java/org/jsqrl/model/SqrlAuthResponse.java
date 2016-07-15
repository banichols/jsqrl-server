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

import lombok.Builder;
import lombok.Getter;

import java.util.Base64;
import java.util.Map;
import java.util.stream.Stream;

/**
 * The standard server response. The toString() method will create the proper
 * SQRL response body in readable format, toEncodedString() will create the
 * Base64 encoded server response to be read by the client.
 * <p>
 * Created by Brent Nichols
 */
@Getter
@Builder
public class SqrlAuthResponse {

    private static final String LINE_SEPERATOR = "\n";

    private String ver;

    private String nut;

    private int tif = 0;

    private String qry;

    private String url;

    private String suk;

    private String ask;

    //Any additional key/value pairs that should be added to the response
    private Map<String, String> additionalData;

    @Override
    public String toString() {

        StringBuilder sqrlResponseStringBuilder = new StringBuilder("");

        sqrlResponseStringBuilder
                .append("ver=").append(ver).append(LINE_SEPERATOR)
                .append("nut=").append(nut).append(LINE_SEPERATOR)
                .append("tif=").append(tif).append(LINE_SEPERATOR)
                .append("qry=").append(qry);

        appendKeyValuePairIfExists(sqrlResponseStringBuilder, "url", url);
        appendKeyValuePairIfExists(sqrlResponseStringBuilder, "suk", suk);
        appendKeyValuePairIfExists(sqrlResponseStringBuilder, "ask", ask);

        if (additionalData != null) {
            additionalData.keySet().stream()
                    .forEach(k -> appendKeyValuePairIfExists(sqrlResponseStringBuilder, k, additionalData.get(k)));
        }

        return sqrlResponseStringBuilder.toString();
    }

    public String toEncodedString() {
        String toString = toString();
        return new String(Base64.getUrlEncoder().encode(toString.getBytes()));
    }

    private StringBuilder appendKeyValuePairIfExists(StringBuilder builder,
                                                     String key,
                                                     String value) {
        if (value != null) {
            builder.append(LINE_SEPERATOR).append(key).append("=").append(value);
        }

        return builder;
    }

    public static class SqrlAuthResponseBuilder {

        public SqrlAuthResponseBuilder addTifs(TransactionInformationFlag... tifs) {
            Stream.of(tifs).forEach(t -> tif |= t.getHexValue());
            return this;
        }
    }

}
