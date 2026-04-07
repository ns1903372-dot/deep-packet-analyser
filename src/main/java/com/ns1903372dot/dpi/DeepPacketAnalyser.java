package com.ns1903372dot.dpi;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public final class DeepPacketAnalyser {
    private DeepPacketAnalyser() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            printUsage();
            return;
        }

        Path input = Path.of(args[0]);
        Path output = Path.of(args[1]);
        DpiSupport.BlockingRules rules = new DpiSupport.BlockingRules();

        for (int index = 2; index < args.length; index++) {
            String arg = args[index];
            if ("--block-ip".equals(arg) && index + 1 < args.length) {
                rules.blockIp(args[++index]);
            } else if ("--block-app".equals(arg) && index + 1 < args.length) {
                rules.blockApp(args[++index]);
            } else if ("--block-domain".equals(arg) && index + 1 < args.length) {
                rules.blockDomain(args[++index]);
            } else {
                throw new IllegalArgumentException("Unknown or incomplete option: " + arg);
            }
        }

        process(input, output, rules);
    }

    private static void process(Path input, Path output, DpiSupport.BlockingRules rules) throws IOException {
        Map<FiveTuple, DpiSupport.Flow> flows = new HashMap<>();
        Map<AppType, Long> appStats = new HashMap<>();
        long totalPackets = 0;
        long forwarded = 0;
        long dropped = 0;

        System.out.println();
        System.out.println("==============================================================");
        System.out.println("Java DPI Engine");
        System.out.println("==============================================================");

        try (PcapIo.Reader reader = new PcapIo.Reader(input);
             PcapIo.Writer writer = new PcapIo.Writer(output)) {
            writer.writeGlobalHeader(reader.getGlobalHeader());
            System.out.println("[DPI] Processing packets...");

            PcapIo.PacketRecord record;
            while ((record = reader.readNextPacket()) != null) {
                totalPackets++;
                PacketParser.ParsedPacket parsed = PacketParser.parse(record);
                if (parsed == null || !parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                    continue;
                }

                FiveTuple tuple = new FiveTuple(
                        FiveTuple.parseIpv4(parsed.sourceIp),
                        FiveTuple.parseIpv4(parsed.destinationIp),
                        parsed.sourcePort,
                        parsed.destinationPort,
                        parsed.protocol
                );

                DpiSupport.Flow flow = flows.computeIfAbsent(tuple, DpiSupport.Flow::new);
                flow.packets++;
                flow.bytes += record.data.length;

                byte[] payload = parsed.payloadLength > 0
                        ? Arrays.copyOfRange(record.data, parsed.payloadOffset, record.data.length)
                        : new byte[0];

                if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTPS)
                        && flow.domain.isEmpty() && parsed.hasTcp && parsed.destinationPort == 443) {
                    Optional<String> sni = DpiSupport.extractTlsSni(payload);
                    if (sni.isPresent()) {
                        flow.domain = sni.get();
                        flow.appType = DpiSupport.classifyDomain(flow.domain);
                    }
                }

                if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTP)
                        && flow.domain.isEmpty() && parsed.hasTcp && parsed.destinationPort == 80) {
                    Optional<String> host = DpiSupport.extractHttpHost(payload);
                    if (host.isPresent()) {
                        flow.domain = host.get();
                        flow.appType = DpiSupport.classifyDomain(flow.domain);
                    }
                }

                if (flow.appType == AppType.UNKNOWN && (parsed.destinationPort == 53 || parsed.sourcePort == 53)) {
                    flow.appType = AppType.DNS;
                }
                if (flow.appType == AppType.UNKNOWN) {
                    if (parsed.destinationPort == 443) flow.appType = AppType.HTTPS;
                    else if (parsed.destinationPort == 80) flow.appType = AppType.HTTP;
                }

                if (!flow.blocked) {
                    flow.blocked = rules.isBlocked(tuple.srcIp(), flow.appType, flow.domain);
                    if (flow.blocked) {
                        System.out.printf("[BLOCKED] %s -> %s (%s%s)%n",
                                parsed.sourceIp, parsed.destinationIp, flow.appType.displayName(),
                                flow.domain.isEmpty() ? "" : ": " + flow.domain);
                    }
                }

                appStats.merge(flow.appType, 1L, Long::sum);
                if (flow.blocked) {
                    dropped++;
                } else {
                    forwarded++;
                    writer.writePacket(record);
                }
            }
        }

        System.out.println(DpiSupport.buildReport(totalPackets, forwarded, dropped, flows, appStats));
        System.out.println("Output written to: " + output.toAbsolutePath());
    }

    private static void printUsage() {
        System.out.println("""
                Java Deep Packet Analyser
                =========================

                Usage:
                  java -cp out com.ns1903372dot.dpi.DeepPacketAnalyser <input.pcap> <output.pcap> [options]

                Options:
                  --block-ip <ip>        Block traffic from source IP
                  --block-app <app>      Block application (YouTube, Facebook, GitHub, ...)
                  --block-domain <dom>   Block any domain containing the substring
                """);
    }
}
