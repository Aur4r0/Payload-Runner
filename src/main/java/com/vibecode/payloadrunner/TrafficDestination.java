package com.vibecode.payloadrunner;

enum TrafficDestination {
    DIRECT("直接发送"),
    BURP_PROXY("经 Burp Proxy 发送");

    private final String label;

    TrafficDestination(String label) {
        this.label = label;
    }

    static TrafficDestination fromSetting(String value) {
        if (value == null || value.trim().isEmpty()) {
            return DIRECT;
        }
        try {
            return valueOf(value.trim());
        } catch (IllegalArgumentException ex) {
            return DIRECT;
        }
    }

    @Override
    public String toString() {
        return label;
    }
}
