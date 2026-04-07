package com.ns1903372dot.dpi;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

final class PcapIo {
    private static final long PCAP_MAGIC_NATIVE = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;

    private PcapIo() {
    }

    static final class GlobalHeader {
        final long magicNumber;
        final int versionMajor;
        final int versionMinor;
        final long thisZone;
        final long sigFigs;
        final long snapLen;
        final long network;

        GlobalHeader(long magicNumber, int versionMajor, int versionMinor,
                     long thisZone, long sigFigs, long snapLen, long network) {
            this.magicNumber = magicNumber;
            this.versionMajor = versionMajor;
            this.versionMinor = versionMinor;
            this.thisZone = thisZone;
            this.sigFigs = sigFigs;
            this.snapLen = snapLen;
            this.network = network;
        }
    }

    static final class PacketRecord {
        final long tsSec;
        final long tsUsec;
        final long inclLen;
        final long origLen;
        final byte[] data;

        PacketRecord(long tsSec, long tsUsec, long inclLen, long origLen, byte[] data) {
            this.tsSec = tsSec;
            this.tsUsec = tsUsec;
            this.inclLen = inclLen;
            this.origLen = origLen;
            this.data = data;
        }
    }

    static final class Reader implements Closeable {
        private final DataInputStream input;
        private final boolean byteSwap;
        private final GlobalHeader globalHeader;

        Reader(Path path) throws IOException {
            this.input = new DataInputStream(new BufferedInputStream(Files.newInputStream(path)));
            byte[] headerBytes = input.readNBytes(24);
            if (headerBytes.length != 24) {
                throw new IOException("Could not read PCAP global header");
            }

            long nativeMagic = readUInt32Little(headerBytes, 0);
            if (nativeMagic == PCAP_MAGIC_NATIVE) {
                byteSwap = false;
            } else if (nativeMagic == PCAP_MAGIC_SWAPPED) {
                byteSwap = true;
            } else {
                throw new IOException("Invalid PCAP magic number");
            }

            globalHeader = new GlobalHeader(
                    byteSwap ? readUInt32Big(headerBytes, 0) : nativeMagic,
                    readUInt16(headerBytes, 4, byteSwap),
                    readUInt16(headerBytes, 6, byteSwap),
                    readUInt32(headerBytes, 8, byteSwap),
                    readUInt32(headerBytes, 12, byteSwap),
                    readUInt32(headerBytes, 16, byteSwap),
                    readUInt32(headerBytes, 20, byteSwap)
            );
        }

        GlobalHeader getGlobalHeader() {
            return globalHeader;
        }

        PacketRecord readNextPacket() throws IOException {
            byte[] packetHeader = new byte[16];
            int firstByte = input.read();
            if (firstByte == -1) {
                return null;
            }
            packetHeader[0] = (byte) firstByte;
            input.readFully(packetHeader, 1, 15);

            long tsSec = readUInt32(packetHeader, 0, byteSwap);
            long tsUsec = readUInt32(packetHeader, 4, byteSwap);
            long inclLen = readUInt32(packetHeader, 8, byteSwap);
            long origLen = readUInt32(packetHeader, 12, byteSwap);
            if (inclLen < 0 || inclLen > 65535 || inclLen > globalHeader.snapLen) {
                throw new IOException("Invalid packet length: " + inclLen);
            }

            byte[] data = input.readNBytes((int) inclLen);
            if (data.length != (int) inclLen) {
                throw new EOFException("Could not read packet payload");
            }
            return new PacketRecord(tsSec, tsUsec, inclLen, origLen, data);
        }

        @Override
        public void close() throws IOException {
            input.close();
        }
    }

    static final class Writer implements Closeable {
        private final DataOutputStream output;

        Writer(Path path) throws IOException {
            OutputStream stream = Files.newOutputStream(path);
            this.output = new DataOutputStream(new BufferedOutputStream(stream));
        }

        void writeGlobalHeader(GlobalHeader header) throws IOException {
            writeUInt32Little(output, header.magicNumber);
            writeUInt16Little(output, header.versionMajor);
            writeUInt16Little(output, header.versionMinor);
            writeUInt32Little(output, header.thisZone);
            writeUInt32Little(output, header.sigFigs);
            writeUInt32Little(output, header.snapLen);
            writeUInt32Little(output, header.network);
        }

        void writePacket(PacketRecord record) throws IOException {
            writeUInt32Little(output, record.tsSec);
            writeUInt32Little(output, record.tsUsec);
            writeUInt32Little(output, record.inclLen);
            writeUInt32Little(output, record.origLen);
            output.write(record.data);
        }

        @Override
        public void close() throws IOException {
            output.flush();
            output.close();
        }
    }

    static long readUInt32(byte[] bytes, int offset, boolean swap) {
        return swap ? readUInt32Big(bytes, offset) : readUInt32Little(bytes, offset);
    }

    static int readUInt16(byte[] bytes, int offset, boolean swap) {
        return swap ? readUInt16Big(bytes, offset) : readUInt16Little(bytes, offset);
    }

    static int readUInt16Big(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF);
    }

    static int readUInt16Little(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) | ((bytes[offset + 1] & 0xFF) << 8);
    }

    static long readUInt32Big(byte[] bytes, int offset) {
        return ((long) (bytes[offset] & 0xFF) << 24)
                | ((long) (bytes[offset + 1] & 0xFF) << 16)
                | ((long) (bytes[offset + 2] & 0xFF) << 8)
                | (bytes[offset + 3] & 0xFFL);
    }

    static long readUInt32Little(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFFL)
                | ((bytes[offset + 1] & 0xFFL) << 8)
                | ((bytes[offset + 2] & 0xFFL) << 16)
                | ((bytes[offset + 3] & 0xFFL) << 24);
    }

    static void writeUInt16Little(DataOutputStream output, long value) throws IOException {
        output.writeByte((int) (value & 0xFF));
        output.writeByte((int) ((value >>> 8) & 0xFF));
    }

    static void writeUInt32Little(DataOutputStream output, long value) throws IOException {
        output.writeByte((int) (value & 0xFF));
        output.writeByte((int) ((value >>> 8) & 0xFF));
        output.writeByte((int) ((value >>> 16) & 0xFF));
        output.writeByte((int) ((value >>> 24) & 0xFF));
    }
}
