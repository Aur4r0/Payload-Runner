package com.vibecode.payloadrunner;

enum RateLimit {
    LOW("Low", 1000L),
    MEDIUM("Medium", 250L),
    HIGH("High", 0L);

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
