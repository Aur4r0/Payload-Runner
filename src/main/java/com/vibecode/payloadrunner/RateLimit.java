package com.vibecode.payloadrunner;

enum RateLimit {
    LOW("低速", 1000L),
    MEDIUM("标准", 250L),
    HIGH("高速", 0L);

    private final String label;
    private final long delayMillis;

    RateLimit(String label, long delayMillis) {
        this.label = label;
        this.delayMillis = delayMillis;
    }

    long getDelayMillis() {
        return delayMillis;
    }

    @Override
    public String toString() {
        return label;
    }
}
