package org.jsqrl.model;

import lombok.Getter;

import java.util.stream.Stream;

/**
 * Created by banic_000 on 7/9/2016.
 */
public enum SqrlCommand {
    QUERY("query"),
    IDENT("ident"),
    DISABLE("disable"),
    ENABLE("enable"),
    REMOVE("remove");

    @Getter
    private String cmd;

    SqrlCommand(String cmd) {
        this.cmd = cmd;
    }

    public static SqrlCommand from(String cmd) {
        return Stream.of(SqrlCommand.values())
                .filter(s -> s.getCmd().equals(cmd))
                .findFirst().orElse(null);
    }


}
