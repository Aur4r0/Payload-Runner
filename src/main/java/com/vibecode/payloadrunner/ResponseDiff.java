package com.vibecode.payloadrunner;

import burp.IExtensionHelpers;
import burp.IResponseInfo;

final class ResponseDiff {
    private final boolean available;
    private final int baselineLength;
    private final int responseLength;
    private final int lengthDelta;
    private final int baselineStatus;
    private final int statusDelta;
    private final int similarityPercent;

    private ResponseDiff(boolean available, int baselineLength, int responseLength, int lengthDelta,
            int baselineStatus, int statusDelta, int similarityPercent) {
        this.available = available;
        this.baselineLength = baselineLength;
        this.responseLength = responseLength;
        this.lengthDelta = lengthDelta;
        this.baselineStatus = baselineStatus;
        this.statusDelta = statusDelta;
        this.similarityPercent = similarityPercent;
    }

    static ResponseDiff unavailable() {
        return new ResponseDiff(false, 0, 0, 0, -1, 0, -1);
    }

    static ResponseDiff between(IExtensionHelpers helpers, byte[] baseline, byte[] response,
            int responseStatus) {
        if (baseline == null || response == null) {
            return unavailable();
        }
        int baselineStatus = -1;
        try {
            IResponseInfo responseInfo = helpers.analyzeResponse(baseline);
            baselineStatus = responseInfo.getStatusCode();
        } catch (RuntimeException ex) {
            baselineStatus = -1;
        }
        return new ResponseDiff(true, baseline.length, response.length,
                response.length - baseline.length, baselineStatus,
                baselineStatus < 0 || responseStatus < 0 ? 0 : responseStatus - baselineStatus,
                similarityPercent(baseline, response));
    }

    boolean isAvailable() {
        return available;
    }

    int getLengthDelta() {
        return lengthDelta;
    }

    int getStatusDelta() {
        return statusDelta;
    }

    int getSimilarityPercent() {
        return similarityPercent;
    }

    String summary() {
        if (!available) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        result.append("len ");
        if (lengthDelta >= 0) {
            result.append('+');
        }
        result.append(lengthDelta);
        result.append(", sim ").append(similarityPercent).append('%');
        if (baselineStatus >= 0 && statusDelta != 0) {
            result.append(", status ");
            if (statusDelta >= 0) {
                result.append('+');
            }
            result.append(statusDelta);
        }
        return result.toString();
    }

    private static int similarityPercent(byte[] baseline, byte[] response) {
        int max = Math.max(baseline.length, response.length);
        if (max == 0) {
            return 100;
        }
        int min = Math.min(baseline.length, response.length);
        int same = 0;
        for (int i = 0; i < min; i++) {
            if (baseline[i] == response[i]) {
                same++;
            }
        }
        return (int) Math.round((same * 100.0d) / max);
    }
}

