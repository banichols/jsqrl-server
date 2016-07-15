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
