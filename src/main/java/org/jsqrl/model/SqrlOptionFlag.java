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
