package com.ns1903372dot.dpi;

import java.util.Locale;

final class PacketParser {
    static final int ETHER_TYPE_IPV4 = 0x0800;
    static final int PROTOCOL_TCP = 6;
    static final int PROTOCOL_UDP = 17;

    private PacketParser() {
    }

    static ParsedPacket parse(PcapIo.PacketRecord record) {
        byte[] data = record.data;
        if (data.length < 14) {
            return null;
        }

        ParsedPacket packet = new ParsedPacket();
        packet.timestampSec = record.tsSec;
        packet.timestampUsec = record.tsUsec;
        packet.sourceMac = macToString(data, 6);
        packet.destinationMac = macToString(data, 0);
        packet.etherType = PcapIo.readUInt16Big(data, 12);

        int offset = 14;
        if (packet.etherType != ETHER_TYPE_IPV4 || data.length < offset + 20) {
            packet.payloadOffset = offset;
            packet.payloadLength = Math.max(0, data.length - offset);
            return packet;
        }

        int versionIhl = data[offset] & 0xFF;
        int version = (versionIhl >>> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;
        int ipHeaderLength = ihl * 4;
        if (version != 4 || ipHeaderLength < 20 || data.length < offset + ipHeaderLength) {
            return null;
        }

        packet.hasIp = true;
        packet.ipVersion = version;
        packet.ttl = data[offset + 8] & 0xFF;
        packet.protocol = data[offset + 9] & 0xFF;
        packet.sourceIp = ipToString(data, offset + 12);
        packet.destinationIp = ipToString(data, offset + 16);
        offset += ipHeaderLength;

        if (packet.protocol == PROTOCOL_TCP) {
            if (data.length < offset + 20) {
                return null;
            }
            packet.hasTcp = true;
            packet.sourcePort = PcapIo.readUInt16Big(data, offset);
            packet.destinationPort = PcapIo.readUInt16Big(data, offset + 2);
            packet.sequenceNumber = PcapIo.readUInt32Big(data, offset + 4);
            packet.ackNumber = PcapIo.readUInt32Big(data, offset + 8);
            int dataOffsetWords = (data[offset + 12] >>> 4) & 0x0F;
            int tcpHeaderLength = dataOffsetWords * 4;
            if (tcpHeaderLength < 20 || data.length < offset + tcpHeaderLength) {
                return null;
            }
            packet.tcpFlags = data[offset + 13] & 0xFF;
            offset += tcpHeaderLength;
        } else if (packet.protocol == PROTOCOL_UDP) {
            if (data.length < offset + 8) {
                return null;
            }
            packet.hasUdp = true;
            packet.sourcePort = PcapIo.readUInt16Big(data, offset);
            packet.destinationPort = PcapIo.readUInt16Big(data, offset + 2);
            offset += 8;
        }

        packet.payloadOffset = offset;
        packet.payloadLength = Math.max(0, data.length - offset);
        return packet;
    }

    private static String macToString(byte[] data, int offset) {
        StringBuilder builder = new StringBuilder();
        for (int index = 0; index < 6; index++) {
            if (index > 0) builder.append(':');
            builder.append(String.format(Locale.ROOT, "%02x", data[offset + index] & 0xFF));
        }
        return builder.toString();
    }

    private static String ipToString(byte[] data, int offset) {
        return (data[offset] & 0xFF) + "."
                + (data[offset + 1] & 0xFF) + "."
                + (data[offset + 2] & 0xFF) + "."
                + (data[offset + 3] & 0xFF);
    }

    static final class ParsedPacket {
        long timestampSec;
        long timestampUsec;
        String sourceMac;
        String destinationMac;
        int etherType;
        boolean hasIp;
        int ipVersion;
        String sourceIp;
        String destinationIp;
        int protocol;
        int ttl;
        boolean hasTcp;
        boolean hasUdp;
        int sourcePort;
        int destinationPort;
        int tcpFlags;
        long sequenceNumber;
        long ackNumber;
        int payloadOffset;
        int payloadLength;
    }
}
