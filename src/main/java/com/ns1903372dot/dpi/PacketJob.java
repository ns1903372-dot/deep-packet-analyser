package com.ns1903372dot.dpi;

final class PacketJob {
    final int packetId;
    final PcapIo.PacketRecord record;
    final PacketParser.ParsedPacket parsed;
    final FiveTuple tuple;
    final byte[] payload;
    final boolean poisonPill;

    private PacketJob(int packetId, PcapIo.PacketRecord record, PacketParser.ParsedPacket parsed,
                      FiveTuple tuple, byte[] payload, boolean poisonPill) {
        this.packetId = packetId;
        this.record = record;
        this.parsed = parsed;
        this.tuple = tuple;
        this.payload = payload;
        this.poisonPill = poisonPill;
    }

    static PacketJob normal(int packetId, PcapIo.PacketRecord record, PacketParser.ParsedPacket parsed,
                            FiveTuple tuple, byte[] payload) {
        return new PacketJob(packetId, record, parsed, tuple, payload, false);
    }

    static PacketJob poison() {
        return new PacketJob(-1, null, null, null, new byte[0], true);
    }
}

