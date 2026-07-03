package com.vibecode.payloadrunner;

final class EscapeRead {
    private final String value;
    private final int nextIndex;

    EscapeRead(String value, int nextIndex) {
        this.value = value;
        this.nextIndex = nextIndex;
    }

    String getValue() {
        return value;
    }

    int getNextIndex() {
        return nextIndex;
    }
}

