package org.jsqrl.nut;

import lombok.Getter;
import lombok.ToString;
import org.apache.commons.lang3.ArrayUtils;
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

        if (random % 2 != 0) {
            qr = true;
        } else {
            qr = false;
        }

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

        Boolean matched = false;

        if (otherNut != null && ArrayUtils.getLength(otherNut.getHashedIp()) >= 4) {

            byte[] otherHash = otherNut.getHashedIp();

            //Check the least significant 4 bytes of each hash
            for (int i = 1; i <= 4; i++) {
                if (!(hashedIp[hashedIp.length - i] == otherHash[otherHash.length - i])) {
                    return false;
                }
            }
            matched = true;
        }

        return matched;

    }

}
