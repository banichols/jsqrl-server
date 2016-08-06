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

package org.jsqrl.nut;

import lombok.Getter;
import lombok.ToString;
import org.jsqrl.error.SqrlException;

import java.nio.ByteBuffer;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

/**
 * The object representation of a SQRL nut.
 * Methods are provided to return the 128-bit representation, and
 * to recreate a SqrlNut object from a 128-bit representation.
 * <p>
 * Created by Brent Nichols
 */
@Getter
@ToString
public class SqrlNut {

    private byte[] hashedIp;
    private int count;
    private int random;
    private boolean qr;
    private LocalDateTime created;

    public SqrlNut(byte[] hashedIp, int count, int random, boolean qr) {
        this.hashedIp = hashedIp;
        this.count = count;
        this.random = random;
        this.qr = qr;
        created = LocalDateTime.now().truncatedTo(ChronoUnit.SECONDS);
    }

    public SqrlNut(int count, int random, boolean qr) {
        this(null, count, random, qr);
    }

    /**
     * Recreate a SQRL Nut from a byte array
     *
     * @param bytes The 128-bit recreated representation of the nut
     */
    public SqrlNut(byte[] bytes) {

        if (bytes == null || bytes.length != 16) {
            throw new SqrlException("Invalid nut bytes provided");
        }

        //First 4 bytes are the least significant bits of the hashed IP
        hashedIp = Arrays.copyOfRange(bytes, 0, 4);

        //Next 4 bytes are the timestamp
        ByteBuffer tsBuffer = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 4, 8));
        Integer timestamp = tsBuffer.getInt();
        created = LocalDateTime.ofEpochSecond(timestamp.longValue(), 0, ZoneOffset.UTC);

        //Next 4 are the count
        ByteBuffer countBuffer = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 8, 12));
        count = countBuffer.getInt();

        //Next 4 are the random noise + qr flag. If the number coming back is odd, that means the qr bit was true
        ByteBuffer noiseBuffer = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 12, 16));
        random = noiseBuffer.getInt();

        qr = random % 2 != 0;

    }

    /**
     * @return Returns the 16 byte (128 bit) nut
     */
    public byte[] toByteArray() {
        ByteBuffer byteBuffer = ByteBuffer.allocate(16);

        //Obtain the least significant 4 bytes of the hashed IP if there is one, otherwise write a 0.
        if (hashedIp != null && hashedIp.length > 3) {
            byteBuffer.put(hashedIp[hashedIp.length - 4]);
            byteBuffer.put(hashedIp[hashedIp.length - 3]);
            byteBuffer.put(hashedIp[hashedIp.length - 2]);
            byteBuffer.put(hashedIp[hashedIp.length - 1]);
        } else {
            byteBuffer.putInt(0);
        }

        //Get the timestamp seconds and convert into 32 bit integer
        Long timestamp = created.toEpochSecond(ZoneOffset.UTC);
        byteBuffer.putInt(timestamp.intValue());

        byteBuffer.putInt(count);

        //Shift the random number left to allow the possibility
        //of the 1 bit QR flag
        int noise = random << 1;

        if (qr) {
            //Add 1 to set the right most bit to 1
            noise = noise + 1;
        }

        byteBuffer.putInt(noise);

        return byteBuffer.array();

    }

    /**
     * This method is used to check if the requesting IP address matches the provided nut.
     * Since it's the least significant part of the IP hash that's saved, we will compare
     * the hashed values byte for byte.
     *
     * @param otherNut The nut to compare IP addresses with
     * @return Returns true if the IP's match, false otherwise
     */
    public Boolean checkIpMatch(SqrlNut otherNut) {
        return otherNut != null ? checkIpMatch(otherNut.getHashedIp()) : false;
    }

    /**
     * This method is used to check if a requesting IP address matches this nut.
     * Since it's the least significant part of the IP hash that's saved, we will compare
     * the hashed values byte for byte.
     *
     * @param otherHashedIp The nut to compare IP addresses with
     * @return Returns true if the IP's match, false otherwise
     */
    public Boolean checkIpMatch(byte[] otherHashedIp) {

        boolean match = false;

        if (otherHashedIp != null && otherHashedIp.length >= 4) {
            //Check the least significant 4 bytes of each hash
            for (int i = 1; i <= 4; i++) {
                if (!(hashedIp[hashedIp.length - i] == otherHashedIp[otherHashedIp.length - i])) {
                    return false;
                }
            }
            match = true;
        }

        return match;

    }

}
