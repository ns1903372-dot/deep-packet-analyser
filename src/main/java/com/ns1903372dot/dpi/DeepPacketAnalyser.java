package com.ns1903372dot.dpi;

import java.nio.file.Path;

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

        DpiEngine.Config config = new DpiEngine.Config();
        RuleManager ruleManager = new RuleManager();

        for (int index = 2; index < args.length; index++) {
            String arg = args[index];
            switch (arg) {
                case "--block-ip" -> ruleManager.blockIp(args[++index]);
                case "--block-app" -> ruleManager.blockApp(args[++index]);
                case "--block-domain" -> ruleManager.blockDomain(args[++index]);
                case "--block-port" -> ruleManager.blockPort(Integer.parseInt(args[++index]));
                case "--rules-file" -> config.rulesFile = Path.of(args[++index]);
                case "--lbs" -> config.numLoadBalancers = Integer.parseInt(args[++index]);
                case "--fps-per-lb" -> config.fpsPerLoadBalancer = Integer.parseInt(args[++index]);
                case "--queue-size" -> config.queueSize = Integer.parseInt(args[++index]);
                case "--verbose" -> config.verbose = true;
                default -> throw new IllegalArgumentException("Unknown or incomplete option: " + arg);
            }
        }

        DpiEngine engine = new DpiEngine(config, ruleManager);
        DpiEngine.EngineStats stats = engine.processFile(input, output);
        System.out.println(engine.generateReport());
        System.out.println("Output written to: " + output.toAbsolutePath());
        if (config.verbose) {
            System.out.printf("Summary -> packets=%d forwarded=%d dropped=%d activeFlows=%d%n",
                    stats.totalPackets(), stats.forwarded(), stats.dropped(), stats.activeConnections());
        }
    }

    private static void printUsage() {
        System.out.println("""
                Java Deep Packet Analyser
                =========================

                Usage:
                  java -cp out com.ns1903372dot.dpi.DeepPacketAnalyser <input.pcap> <output.pcap> [options]

                Options:
                  --block-ip <ip>          Block traffic from source IP
                  --block-app <app>        Block application (YouTube, Facebook, GitHub, ...)
                  --block-domain <domain>  Block domain or wildcard pattern
                  --block-port <port>      Block destination port
                  --rules-file <file>      Load additional rules from file
                  --lbs <count>            Number of load balancers
                  --fps-per-lb <count>     Fast-path processors per load balancer
                  --queue-size <count>     Queue capacity for worker pipelines
                  --verbose                Print final summary line
                """);
    }
}
