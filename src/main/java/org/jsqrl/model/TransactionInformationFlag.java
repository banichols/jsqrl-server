package org.jsqrl.model;

import lombok.Getter;

/**
 * Enumeration for the SQRL Transaction Information Flags (tif)
 * Created by Brent Nichols
 */
public enum TransactionInformationFlag {

    ID_MATCH(0x01),
    PREVIOUS_ID_MATCH(0x02),
    IP_MATCHED(0x04),
    SQRL_DISABLED(0x08),
    FUNCTION_NOT_SUPPORTED(0x10),
    TRANSIENT_ERROR(0x20),
    COMMAND_FAILED(0x40),
    CLIENT_FAILURE(0x80),
    BAD_ID_ASSOCIATION(0x100);

    @Getter
    private final int hexValue;

    TransactionInformationFlag(int hexValue) {
        this.hexValue = hexValue;
    }

}
