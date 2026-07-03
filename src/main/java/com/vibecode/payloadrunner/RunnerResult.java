package com.vibecode.payloadrunner;

final class RunnerResult {
    private final RequestTemplate template;
    private final HistoryRecord historyRecord;
    private final String hitMatch;
    private final String diffSummary;
    private final int score;
    private final String repeaterError;
    private final String error;

    RunnerResult(RequestTemplate template, HistoryRecord historyRecord, String hitMatch,
            String diffSummary, String error) {
        this(template, historyRecord, hitMatch, diffSummary,
                scoreFromSummary(historyRecord, hitMatch, error), error);
    }

    RunnerResult(RequestTemplate template, HistoryRecord historyRecord, String hitMatch,
            String diffSummary, int score, String error) {
        this.template = template;
        this.historyRecord = historyRecord;
        this.hitMatch = hitMatch == null ? "" : hitMatch;
        this.diffSummary = diffSummary == null ? "" : diffSummary;
        this.score = clampScore(score);
        this.repeaterError = "";
        this.error = error;
    }

    RunnerResult(RequestTemplate template, String parameterName, String category, String payload,
            byte[] request, byte[] response, int statusCode, int responseLength, long elapsedMillis,
            String hitMatch, String diffSummary, boolean sentToRepeater, String repeaterError,
            String error) {
        this(template, parameterName, category, payload, request, response, statusCode,
                responseLength, elapsedMillis, hitMatch, diffSummary,
                scoreFromValues(statusCode, elapsedMillis, hitMatch, error),
                sentToRepeater, repeaterError, error);
    }

    RunnerResult(RequestTemplate template, String parameterName, String category, String payload,
            byte[] request, byte[] response, int statusCode, int responseLength, long elapsedMillis,
            String hitMatch, String diffSummary, int score, boolean sentToRepeater,
            String repeaterError, String error) {
        this.template = template;
        this.historyRecord = new HistoryRecord(0L, template, parameterName, category, payload,
                request, response, statusCode, responseLength, elapsedMillis,
                System.currentTimeMillis());
        this.historyRecord.setSentToRepeater(sentToRepeater);
        this.hitMatch = hitMatch == null ? "" : hitMatch;
        this.diffSummary = diffSummary == null ? "" : diffSummary;
        this.score = clampScore(score);
        this.repeaterError = repeaterError == null ? "" : repeaterError;
        this.error = error;
    }

    RequestTemplate getTemplate() {
        return template;
    }

    HistoryRecord getHistoryRecord() {
        return historyRecord;
    }

    String getParameterName() {
        return historyRecord.getParameterName();
    }

    String getCategory() {
        return historyRecord.getCategory();
    }

    String getPayload() {
        return historyRecord.getPayload();
    }

    byte[] getRequest() {
        return historyRecord.getRequestBytes();
    }

    byte[] getResponse() {
        return historyRecord.getResponseBytes();
    }

    int getStatusCode() {
        return historyRecord.getStatusCode();
    }

    int getResponseLength() {
        return historyRecord.getResponseLength();
    }

    long getElapsedMillis() {
        return historyRecord.getResponseTimeMs();
    }

    String getHitMatch() {
        return hitMatch;
    }

    String getDiffSummary() {
        return diffSummary;
    }

    int getScore() {
        return score;
    }

    boolean isSentToRepeater() {
        return historyRecord.isSentToRepeater();
    }

    String getRepeaterError() {
        return repeaterError;
    }

    String getError() {
        return error;
    }

    private static int scoreFromSummary(HistoryRecord record, String hitMatch, String error) {
        if (record == null) {
            return scoreFromValues(-1, 0L, hitMatch, error);
        }
        return scoreFromValues(record.getStatusCode(), record.getResponseTimeMs(), hitMatch, error);
    }

    private static int scoreFromValues(int statusCode, long elapsedMillis, String hitMatch,
            String error) {
        int value = 0;
        if (hitMatch != null && !hitMatch.trim().isEmpty()) {
            value += 40;
        }
        if (error != null && !error.trim().isEmpty()) {
            value += 35;
        }
        if (statusCode >= 500) {
            value += 25;
        } else if (statusCode >= 400) {
            value += 10;
        }
        if (elapsedMillis >= 2000L) {
            value += 10;
        }
        return clampScore(value);
    }

    private static int clampScore(int value) {
        if (value < 0) {
            return 0;
        }
        return Math.min(100, value);
    }
}
