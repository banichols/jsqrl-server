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
     * @param base64EncodedString
     * @return Returns the provided encoded string, minus its trailing = characters
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
