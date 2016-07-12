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
