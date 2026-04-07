package com.ns1903372dot.dpi;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

final class ConnectionTracker {
    private final int fpId;
    private final int maxConnections;
    private final Map<FiveTuple, Connection> connections = new HashMap<>();
    private long totalSeen;
    private long classifiedCount;
    private long blockedCount;

    ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    Connection getOrCreateConnection(FiveTuple tuple) {
        Connection connection = connections.get(tuple);
        if (connection != null) {
            return connection;
        }
        if (connections.size() >= maxConnections) {
            evictOldest();
        }
        Connection created = new Connection(tuple);
        connections.put(tuple, created);
        totalSeen++;
        return created;
    }

    void updateConnection(Connection connection, int packetSize, boolean outbound) {
        connection.lastSeen = Instant.now();
        if (outbound) {
            connection.packetsOut++;
            connection.bytesOut += packetSize;
        } else {
            connection.packetsIn++;
            connection.bytesIn += packetSize;
        }
        if (connection.state == Connection.State.NEW) {
            connection.state = Connection.State.ESTABLISHED;
        }
    }

    void classifyConnection(Connection connection, AppType appType, String domain) {
        if (connection.appType == AppType.UNKNOWN && appType != AppType.UNKNOWN) {
            classifiedCount++;
        }
        connection.appType = appType;
        connection.domain = domain == null ? "" : domain;
        connection.state = Connection.State.CLASSIFIED;
    }

    void blockConnection(Connection connection) {
        if (connection.state != Connection.State.BLOCKED) {
            blockedCount++;
        }
        connection.action = PacketAction.DROP;
        connection.state = Connection.State.BLOCKED;
    }

    void closeConnection(FiveTuple tuple) {
        Connection connection = connections.get(tuple);
        if (connection != null) {
            connection.state = Connection.State.CLOSED;
        }
    }

    int cleanupStale(Duration timeout) {
        Instant cutoff = Instant.now().minus(timeout);
        int removed = 0;
        Iterator<Map.Entry<FiveTuple, Connection>> iterator = connections.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<FiveTuple, Connection> entry = iterator.next();
            if (entry.getValue().lastSeen.isBefore(cutoff)) {
                iterator.remove();
                removed++;
            }
        }
        return removed;
    }

    List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    TrackerStats getStats() {
        return new TrackerStats(fpId, connections.size(), totalSeen, classifiedCount, blockedCount);
    }

    private void evictOldest() {
        FiveTuple oldestKey = null;
        Instant oldestTime = Instant.now();
        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            if (entry.getValue().lastSeen.isBefore(oldestTime)) {
                oldestKey = entry.getKey();
                oldestTime = entry.getValue().lastSeen;
            }
        }
        if (oldestKey != null) {
            connections.remove(oldestKey);
        }
    }

    record TrackerStats(int fpId, int activeConnections, long totalSeen, long classifiedConnections, long blockedConnections) {
    }
}
