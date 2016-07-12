package org.jsqrl.config;

import lombok.Getter;
import lombok.Setter;

/**
 * This is the configuration bean class.
 * This object is required by the main JSQRL service.
 * <p>
 * Created by Brent Nichols
 */
@Getter
@Setter
public class SqrlConfig {
    private String sqrlVersion;
    private String sfn;
    private Long nutExpirationSeconds;
    private String sqrlBaseUri;
    private Boolean ipAddressRequired;
}
