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

package org.jsqrl.config;

import lombok.Getter;
import lombok.Setter;

/**
 * This is the configuration bean class.
 * This object is required by the main JSQRL service.
 */
@Getter
@Setter
public class SqrlConfig {

    /**
     * This defines the SQRL Protocol version being used.
     * For the initial version of SQRL, this is 1
     */
    private String sqrlVersion;

    /**
     * The server friendly name that will be displayed to
     * the user when they are authenticating.
     */
    private String sfn;

    /**
     * The time that a nut is valid for in seconds.
     */
    private Long nutExpirationSeconds;

    /**
     * This should be set to the URI that handles your
     * SQRL HTTP POST requests. It will let the client
     * know where it needs to make its requests to.
     * <p>
     * Example: /sqrl
     */
    private String sqrlBaseUri;
    /**
     * IP Match required flag. Not currently used in JSQRL.
     */
    private Boolean ipAddressRequired;
}
