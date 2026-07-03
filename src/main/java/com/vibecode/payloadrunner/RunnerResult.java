package com.vibecode.payloadrunner;

final class RunnerResult {
    private final RequestTemplate template;
    private final HistoryRecord historyRecord;
    private final String hitMatch;
    private final String diffSummary;
    private final String repeaterError;
    private final String error;

    RunnerResult(RequestTemplate template, HistoryRecord historyRecord, String hitMatch,
            String diffSummary, String error) {
        this.template = template;
        this.historyRecord = historyRecord;
        this.hitMatch = hitMatch == null ? "" : hitMatch;
        this.diffSummary = diffSummary == null ? "" : diffSummary;
        this.repeaterError = "";
        this.error = error;
    }

    RunnerResult(RequestTemplate template, String parameterName, String category, String payload,
            byte[] request, byte[] response, int statusCode, int responseLength, long elapsedMillis,
            String hitMatch, String diffSummary, boolean sentToRepeater, String repeaterError,
            String error) {
        this.template = template;
        this.historyRecord = new HistoryRecord(0L, template, parameterName, category, payload,
                request, response, statusCode, responseLength, elapsedMillis,
                System.currentTimeMillis());
        this.historyRecord.setSentToRepeater(sentToRepeater);
        this.hitMatch = hitMatch == null ? "" : hitMatch;
        this.diffSummary = diffSummary == null ? "" : diffSummary;
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

    boolean isSentToRepeater() {
        return historyRecord.isSentToRepeater();
    }

    String getRepeaterError() {
        return repeaterError;
    }

    String getError() {
        return error;
    }
}
