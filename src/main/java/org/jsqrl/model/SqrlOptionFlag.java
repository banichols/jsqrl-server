package org.jsqrl.model;

import lombok.Getter;

import java.util.stream.Stream;

/**
 * Enumerations for the various SQRL Options (opt) flags that can be set
 * <p>
 * Created by Brent Nichols
 */
public enum SqrlOptionFlag {

    SQRL_ONLY("sqrlonly"),
    HARD_LOCK("hardlock"),
    CLIENT_PROVIDED_SESSION("cps"),
    SERVER_UNLOCK_KEY("suk");

    @Getter
    private String opt;

    SqrlOptionFlag(String opt) {
        this.opt = opt;
    }

    public static SqrlOptionFlag from(String opt) {
        return Stream.of(SqrlOptionFlag.values())
                .filter(s -> s.getOpt().equals(opt))
                .findFirst().orElse(null);
    }

}
