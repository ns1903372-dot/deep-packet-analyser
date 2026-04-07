package com.ns1903372dot.dpi;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

final class LoadBalancer {
    private final int lbId;
    private final int fpStartId;
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final AtomicLong packetsReceived = new AtomicLong();
    private final AtomicLong packetsDispatched = new AtomicLong();
    private Thread thread;

    LoadBalancer(int lbId, int fpStartId, List<ThreadSafeQueue<PacketJob>> fpQueues, int queueSize) {
        this.lbId = lbId;
        this.fpStartId = fpStartId;
        this.fpQueues = fpQueues;
        this.inputQueue = new ThreadSafeQueue<>(queueSize);
    }

    void start() {
        thread = new Thread(this::run, "lb-" + lbId);
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

    Stats getStats() {
        return new Stats(lbId, packetsReceived.get(), packetsDispatched.get());
    }

    private void run() {
        try {
            while (true) {
                PacketJob job = inputQueue.take();
                if (job.poisonPill) {
                    for (ThreadSafeQueue<PacketJob> fpQueue : fpQueues) {
                        fpQueue.put(PacketJob.poison());
                    }
                    break;
                }
                packetsReceived.incrementAndGet();
                int relativeFp = Math.floorMod(job.tuple.hashCode(), fpQueues.size());
                fpQueues.get(relativeFp).put(job);
                packetsDispatched.incrementAndGet();
            }
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
        }
    }

    record Stats(int lbId, long received, long dispatched) {
    }
}
