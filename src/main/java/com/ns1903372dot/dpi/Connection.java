package com.ns1903372dot.dpi;

import java.time.Instant;

final class Connection {
    enum State {
        NEW,
        ESTABLISHED,
        CLASSIFIED,
        BLOCKED,
        CLOSED
    }

    final FiveTuple tuple;
    State state = State.NEW;
    AppType appType = AppType.UNKNOWN;
    String domain = "";
    long packetsIn;
    long packetsOut;
    long bytesIn;
    long bytesOut;
    Instant firstSeen = Instant.now();
    Instant lastSeen = Instant.now();
    PacketAction action = PacketAction.FORWARD;
    boolean synSeen;
    boolean synAckSeen;
    boolean finSeen;

    Connection(FiveTuple tuple) {
        this.tuple = tuple;
    }
}

