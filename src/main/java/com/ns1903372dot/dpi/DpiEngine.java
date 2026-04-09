package com.ns1903372dot.dpi;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;

final class DpiEngine {
    static final class Config {
        int numLoadBalancers = 2;
        int fpsPerLoadBalancer = 2;
        int queueSize = 10_000;
        boolean verbose;
        Path rulesFile;
    }

    record EngineStats(long totalPackets, long forwarded, long dropped, int activeConnections) {
    }

    record ThreadSnapshot(String name, long dispatched, long processed, long forwarded, long dropped) {
    }

    record EngineSnapshot(
            EngineStats stats,
            Map<String, Long> appBreakdown,
            List<ThreadSnapshot> threadStats,
            List<String> detectedDomains
    ) {
    }

    private final Config config;
    private final RuleManager ruleManager;
    private final List<LoadBalancer> loadBalancers = new ArrayList<>();
    private final List<FastPathProcessor> fastPaths = new ArrayList<>();
    private final ThreadSafeQueue<FastPathProcessor.PacketResult> outputQueue;
    private final AtomicInteger poisonResultsSeen = new AtomicInteger();
    private final TreeMap<Integer, FastPathProcessor.PacketResult> pendingOutput = new TreeMap<>();
    private long totalPackets;
    private long forwardedPackets;
    private long droppedPackets;
    private int nextPacketToWrite = 1;

    DpiEngine(Config config, RuleManager ruleManager) {
        this.config = config;
        this.ruleManager = ruleManager;
        this.outputQueue = new ThreadSafeQueue<>(config.queueSize);
    }

    EngineStats processFile(Path inputFile, Path outputFile) throws Exception {
        if (config.rulesFile != null) {
            ruleManager.loadRules(config.rulesFile);
        }

        createWorkers();
        startWorkers();

        try (PcapIo.Reader reader = new PcapIo.Reader(inputFile);
             PcapIo.Writer writer = new PcapIo.Writer(outputFile)) {
            writer.writeGlobalHeader(reader.getGlobalHeader());

            Thread writerThread = new Thread(() -> runWriter(writer), "output-writer");
            writerThread.start();

            readPackets(reader);
            stopLoadBalancers();
            joinLoadBalancers();
            joinFastPaths();
            writerThread.join();
        }

        return new EngineStats(totalPackets, forwardedPackets, droppedPackets, countActiveConnections());
    }

    String generateReport() {
        StringBuilder builder = new StringBuilder();
        builder.append(System.lineSeparator());
        builder.append("==============================================================").append(System.lineSeparator());
        builder.append("PROCESSING REPORT").append(System.lineSeparator());
        builder.append("==============================================================").append(System.lineSeparator());
        builder.append("Total Packets: ").append(totalPackets).append(System.lineSeparator());
        builder.append("Forwarded:     ").append(forwardedPackets).append(System.lineSeparator());
        builder.append("Dropped:       ").append(droppedPackets).append(System.lineSeparator());
        builder.append("Active Flows:  ").append(countActiveConnections()).append(System.lineSeparator());
        builder.append(System.lineSeparator()).append("THREAD STATISTICS").append(System.lineSeparator());
        for (LoadBalancer lb : loadBalancers) {
            LoadBalancer.Stats stats = lb.getStats();
            builder.append("LB").append(stats.lbId()).append(" dispatched: ").append(stats.dispatched()).append(System.lineSeparator());
        }
        for (FastPathProcessor fp : fastPaths) {
            FastPathProcessor.Stats stats = fp.getStats();
            builder.append("FP").append(fastPaths.indexOf(fp))
                    .append(" processed: ").append(stats.processed())
                    .append(", forwarded: ").append(stats.forwarded())
                    .append(", dropped: ").append(stats.dropped())
                    .append(System.lineSeparator());
        }

        Map<AppType, Long> appDistribution = new TreeMap<>((left, right) -> left.displayName().compareToIgnoreCase(right.displayName()));
        for (FastPathProcessor fp : fastPaths) {
            for (Connection connection : fp.tracker().getAllConnections()) {
                appDistribution.merge(connection.appType, connection.packetsIn + connection.packetsOut, Long::sum);
            }
        }
        builder.append(System.lineSeparator()).append("APPLICATION BREAKDOWN").append(System.lineSeparator());
        for (Map.Entry<AppType, Long> entry : appDistribution.entrySet()) {
            builder.append(entry.getKey().displayName()).append(": ").append(entry.getValue()).append(System.lineSeparator());
        }
        return builder.toString();
    }

    EngineSnapshot snapshot() {
        Map<String, Long> appDistribution = new TreeMap<>(String::compareToIgnoreCase);
        List<String> domains = new ArrayList<>();
        for (FastPathProcessor fp : fastPaths) {
            for (Connection connection : fp.tracker().getAllConnections()) {
                appDistribution.merge(connection.appType.displayName(), connection.packetsIn + connection.packetsOut, Long::sum);
                if (connection.domain != null && !connection.domain.isBlank() && !domains.contains(connection.domain)) {
                    domains.add(connection.domain);
                }
            }
        }

        List<ThreadSnapshot> threadStats = new ArrayList<>();
        for (LoadBalancer lb : loadBalancers) {
            LoadBalancer.Stats stats = lb.getStats();
            threadStats.add(new ThreadSnapshot("LB" + stats.lbId(), stats.dispatched(), 0, 0, 0));
        }
        for (FastPathProcessor fp : fastPaths) {
            FastPathProcessor.Stats stats = fp.getStats();
            threadStats.add(new ThreadSnapshot(
                    "FP" + fastPaths.indexOf(fp),
                    0,
                    stats.processed(),
                    stats.forwarded(),
                    stats.dropped()
            ));
        }

        return new EngineSnapshot(
                new EngineStats(totalPackets, forwardedPackets, droppedPackets, countActiveConnections()),
                appDistribution,
                threadStats,
                domains
        );
    }

    private void createWorkers() {
        if (!fastPaths.isEmpty()) return;

        for (int index = 0; index < config.numLoadBalancers * config.fpsPerLoadBalancer; index++) {
            int fpId = index;
            fastPaths.add(new FastPathProcessor(fpId, config.queueSize, ruleManager, result -> {
                try {
                    outputQueue.put(result);
                } catch (InterruptedException interruptedException) {
                    Thread.currentThread().interrupt();
                }
            }));
        }

        for (int lbId = 0; lbId < config.numLoadBalancers; lbId++) {
            int start = lbId * config.fpsPerLoadBalancer;
            List<ThreadSafeQueue<PacketJob>> fpQueues = new ArrayList<>();
            for (int offset = 0; offset < config.fpsPerLoadBalancer; offset++) {
                fpQueues.add(fastPaths.get(start + offset).queue());
            }
            loadBalancers.add(new LoadBalancer(lbId, start, fpQueues, config.queueSize));
        }
    }

    private void startWorkers() {
        for (FastPathProcessor fp : fastPaths) fp.start();
        for (LoadBalancer lb : loadBalancers) lb.start();
    }

    private void readPackets(PcapIo.Reader reader) throws Exception {
        PcapIo.PacketRecord record;
        int packetId = 0;
        while ((record = reader.readNextPacket()) != null) {
            packetId++;
            totalPackets++;
            PacketParser.ParsedPacket parsed = PacketParser.parse(record);
            if (parsed == null || !parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                outputQueue.put(new FastPathProcessor.PacketResult(packetId, record, PacketAction.FORWARD, false));
                continue;
            }

            FiveTuple tuple = new FiveTuple(
                    FiveTuple.parseIpv4(parsed.sourceIp),
                    FiveTuple.parseIpv4(parsed.destinationIp),
                    parsed.sourcePort,
                    parsed.destinationPort,
                    parsed.protocol
            );

            byte[] payload = parsed.payloadLength > 0
                    ? Arrays.copyOfRange(record.data, parsed.payloadOffset, record.data.length)
                    : new byte[0];
            PacketJob job = PacketJob.normal(packetId, record, parsed, tuple, payload);
            int lbIndex = Math.floorMod(tuple.hashCode(), loadBalancers.size());
            loadBalancers.get(lbIndex).queue().put(job);
        }
    }

    private void stopLoadBalancers() throws InterruptedException {
        for (LoadBalancer lb : loadBalancers) lb.stop();
    }

    private void joinLoadBalancers() throws InterruptedException {
        for (LoadBalancer lb : loadBalancers) lb.join();
    }

    private void joinFastPaths() throws InterruptedException {
        for (FastPathProcessor fp : fastPaths) fp.join();
    }

    private void runWriter(PcapIo.Writer writer) {
        try {
            while (poisonResultsSeen.get() < fastPaths.size()) {
                FastPathProcessor.PacketResult result = outputQueue.take();
                if (result.poisonPill()) {
                    poisonResultsSeen.incrementAndGet();
                    continue;
                }
                pendingOutput.put(result.packetId(), result);
                drainPending(writer);
            }
            drainPending(writer);
        } catch (InterruptedException | IOException exception) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(exception);
        }
    }

    private void drainPending(PcapIo.Writer writer) throws IOException {
        while (pendingOutput.containsKey(nextPacketToWrite)) {
            FastPathProcessor.PacketResult result = pendingOutput.remove(nextPacketToWrite);
            if (result.action() == PacketAction.FORWARD) {
                writer.writePacket(result.record());
                forwardedPackets++;
            } else {
                droppedPackets++;
            }
            nextPacketToWrite++;
        }
    }

    private int countActiveConnections() {
        int total = 0;
        for (FastPathProcessor fp : fastPaths) {
            fp.tracker().cleanupStale(Duration.ofMinutes(5));
            total += fp.tracker().getStats().activeConnections();
        }
        return total;
    }
}
