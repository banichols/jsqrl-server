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

package org.jsqrl.util;

import java.util.Base64;

/**
 * A utility class to handle various SQRL functionality.
 * <p>
 * Created by Brent Nichols
 */
public class SqrlUtil {

    private SqrlUtil() {
    }

    public static String unpaddedBase64UrlEncoded(String unencodedString) {
        return unpaddedBase64UrlEncoded(unencodedString.getBytes());
    }

    public static String unpaddedBase64UrlEncoded(byte[] unencodedBytes) {
        return stripEndEquals(new String(Base64.getUrlEncoder().encode(unencodedBytes)));
    }

    public static byte[] base64UrlDecode(String encodedString) {
        return base64UrlDecode(encodedString.getBytes());
    }

    public static byte[] base64UrlDecode(byte[] encodedBytes) {
        return Base64.getUrlDecoder().decode(encodedBytes);
    }

    /**
     * Strips the end equals characters from a base64 encoded string
     *
     * @param base64EncodedString The Base64 encoded string to strip the trailing "=" characters from
     * @return The provided encoded string, minus its trailing = characters
     */
    public static String stripEndEquals(String base64EncodedString) {

        int equalsSigns = 0;
        int strLength = base64EncodedString.length();

        for (int i = strLength - 1; i >= 0; i--) {
            if (base64EncodedString.charAt(i) == '=') {
                equalsSigns++;
            } else {
                break;
            }
        }

        return base64EncodedString.substring(0, strLength - equalsSigns);

    }

}
