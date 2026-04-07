package com.ns1903372dot.dpi;

import java.util.Objects;

public final class FiveTuple {
    private final int srcIp;
    private final int dstIp;
    private final int srcPort;
    private final int dstPort;
    private final int protocol;

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public int srcIp() { return srcIp; }
    public int dstIp() { return dstIp; }
    public int srcPort() { return srcPort; }
    public int dstPort() { return dstPort; }
    public int protocol() { return protocol; }

    public static int parseIpv4(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
        }
        int value = 0;
        value |= Integer.parseInt(parts[0]) & 0xFF;
        value |= (Integer.parseInt(parts[1]) & 0xFF) << 8;
        value |= (Integer.parseInt(parts[2]) & 0xFF) << 16;
        value |= (Integer.parseInt(parts[3]) & 0xFF) << 24;
        return value;
    }

    public static String ipv4ToString(int ip) {
        return (ip & 0xFF) + "."
                + ((ip >>> 8) & 0xFF) + "."
                + ((ip >>> 16) & 0xFF) + "."
                + ((ip >>> 24) & 0xFF);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof FiveTuple that)) return false;
        return srcIp == that.srcIp && dstIp == that.dstIp
                && srcPort == that.srcPort && dstPort == that.dstPort
                && protocol == that.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }
}
