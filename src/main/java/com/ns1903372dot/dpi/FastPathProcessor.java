package com.ns1903372dot.dpi;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

final class FastPathProcessor {
    record PacketResult(int packetId, PcapIo.PacketRecord record, PacketAction action, boolean poisonPill) {
        static PacketResult poison() {
            return new PacketResult(-1, null, PacketAction.DROP, true);
        }
    }

    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final ConnectionTracker connectionTracker;
    private final RuleManager ruleManager;
    private final Consumer<PacketResult> outputCallback;
    private final AtomicLong packetsProcessed = new AtomicLong();
    private final AtomicLong packetsForwarded = new AtomicLong();
    private final AtomicLong packetsDropped = new AtomicLong();
    private final AtomicLong sniExtractions = new AtomicLong();
    private final AtomicLong classificationHits = new AtomicLong();
    private Thread thread;

    FastPathProcessor(int fpId, int queueSize, RuleManager ruleManager, Consumer<PacketResult> outputCallback) {
        this.fpId = fpId;
        this.inputQueue = new ThreadSafeQueue<>(queueSize);
        this.connectionTracker = new ConnectionTracker(fpId, 100_000);
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
    }

    void start() {
        thread = new Thread(this::run, "fp-" + fpId);
        thread.start();
    }

    void stop() throws InterruptedException {
        inputQueue.put(PacketJob.poison());
    }

    void join() throws InterruptedException {
        if (thread != null) thread.join();
    }

    ThreadSafeQueue<PacketJob> queue() {
        return inputQueue;
    }

    ConnectionTracker tracker() {
        return connectionTracker;
    }

    Stats getStats() {
        return new Stats(
                packetsProcessed.get(),
                packetsForwarded.get(),
                packetsDropped.get(),
                sniExtractions.get(),
                classificationHits.get(),
                connectionTracker.getStats().activeConnections()
        );
    }

    private void run() {
        try {
            while (true) {
                PacketJob job = inputQueue.take();
                if (job.poisonPill) {
                    outputCallback.accept(PacketResult.poison());
                    break;
                }
                PacketAction action = processPacket(job);
                outputCallback.accept(new PacketResult(job.packetId, job.record, action, false));
            }
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
        }
    }

    private PacketAction processPacket(PacketJob job) {
        packetsProcessed.incrementAndGet();

        Connection connection = connectionTracker.getOrCreateConnection(job.tuple);
        boolean outbound = job.parsed.sourcePort >= 1024;
        connectionTracker.updateConnection(connection, job.record.data.length, outbound);

        inspectPayload(job, connection);
        updateTcpState(connection, job.parsed.tcpFlags);
        Optional<RuleManager.BlockReason> blockReason = ruleManager.shouldBlock(
                job.tuple.srcIp(), job.tuple.dstPort(), connection.appType, connection.domain
        );

        if (blockReason.isPresent()) {
            connectionTracker.blockConnection(connection);
            packetsDropped.incrementAndGet();
            return PacketAction.DROP;
        }

        packetsForwarded.incrementAndGet();
        return PacketAction.FORWARD;
    }

    private void inspectPayload(PacketJob job, Connection connection) {
        if ((connection.appType == AppType.UNKNOWN || connection.appType == AppType.HTTPS)
                && connection.domain.isEmpty() && job.parsed.hasTcp && job.parsed.destinationPort == 443) {
            Optional<String> sni = DpiSupport.extractTlsSni(job.payload);
            if (sni.isPresent()) {
                sniExtractions.incrementAndGet();
                AppType appType = DpiSupport.classifyDomain(sni.get());
                connectionTracker.classifyConnection(connection, appType, sni.get());
                classificationHits.incrementAndGet();
                return;
            }
        }

        if ((connection.appType == AppType.UNKNOWN || connection.appType == AppType.HTTP)
                && connection.domain.isEmpty() && job.parsed.hasTcp && job.parsed.destinationPort == 80) {
            Optional<String> host = DpiSupport.extractHttpHost(job.payload);
            if (host.isPresent()) {
                AppType appType = DpiSupport.classifyDomain(host.get());
                connectionTracker.classifyConnection(connection, appType, host.get());
                classificationHits.incrementAndGet();
                return;
            }
        }

        if (connection.appType == AppType.UNKNOWN && (job.parsed.destinationPort == 53 || job.parsed.sourcePort == 53)) {
            connectionTracker.classifyConnection(connection, AppType.DNS, connection.domain);
        } else if (connection.appType == AppType.UNKNOWN && job.parsed.destinationPort == 443) {
            connectionTracker.classifyConnection(connection, AppType.HTTPS, connection.domain);
        } else if (connection.appType == AppType.UNKNOWN && job.parsed.destinationPort == 80) {
            connectionTracker.classifyConnection(connection, AppType.HTTP, connection.domain);
        }
    }

    private void updateTcpState(Connection connection, int tcpFlags) {
        if ((tcpFlags & 0x02) != 0) connection.synSeen = true;
        if ((tcpFlags & 0x12) == 0x12) connection.synAckSeen = true;
        if ((tcpFlags & 0x01) != 0) {
            connection.finSeen = true;
            connectionTracker.closeConnection(connection.tuple);
        }
    }

    record Stats(long processed, long forwarded, long dropped, long sniExtractions, long classificationHits,
                 int activeConnections) {
    }
}

