package com.ns1903372dot.dpi;

import java.util.concurrent.LinkedBlockingQueue;

final class ThreadSafeQueue<T> {
    private final LinkedBlockingQueue<T> queue;

    ThreadSafeQueue(int capacity) {
        this.queue = new LinkedBlockingQueue<>(capacity);
    }

    void put(T value) throws InterruptedException {
        queue.put(value);
    }

    T take() throws InterruptedException {
        return queue.take();
    }
}
