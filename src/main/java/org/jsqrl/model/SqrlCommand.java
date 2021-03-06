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
 * The known SQRL Commands
 *
 * Created by Brent Nichols
 */
public enum SqrlCommand {
    QUERY("query"),
    IDENT("ident"),
    DISABLE("disable"),
    ENABLE("enable"),
    REMOVE("remove");

    @Getter
    private final String cmd;

    SqrlCommand(String cmd) {
        this.cmd = cmd;
    }

    public static SqrlCommand from(String cmd) {
        return Stream.of(SqrlCommand.values())
                .filter(s -> s.getCmd().equals(cmd))
                .findFirst().orElse(null);
    }


}
