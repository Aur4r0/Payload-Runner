package com.vibecode.payloadrunner;

final class RunnerResult {
    private final RequestTemplate template;
    private final String parameterName;
    private final String category;
    private final String payload;
    private final byte[] request;
    private final byte[] response;
    private final int statusCode;
    private final int responseLength;
    private final long elapsedMillis;
    private final String hitMatch;
    private final String diffSummary;
    private final boolean sentToRepeater;
    private final String repeaterError;
    private final String error;

    RunnerResult(RequestTemplate template, String parameterName, String category, String payload,
            byte[] request, byte[] response, int statusCode, int responseLength, long elapsedMillis,
            String hitMatch, String diffSummary, boolean sentToRepeater, String repeaterError,
            String error) {
        this.template = template;
        this.parameterName = parameterName;
        this.category = category;
        this.payload = payload;
        this.request = request;
        this.response = response;
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.elapsedMillis = elapsedMillis;
        this.hitMatch = hitMatch == null ? "" : hitMatch;
        this.diffSummary = diffSummary == null ? "" : diffSummary;
        this.sentToRepeater = sentToRepeater;
        this.repeaterError = repeaterError == null ? "" : repeaterError;
        this.error = error;
    }

    RequestTemplate getTemplate() {
        return template;
    }

    String getParameterName() {
        return parameterName;
    }

    String getCategory() {
        return category;
    }

    String getPayload() {
        return payload;
    }

    byte[] getRequest() {
        return request;
    }

    byte[] getResponse() {
        return response;
    }

    int getStatusCode() {
        return statusCode;
    }

    int getResponseLength() {
        return responseLength;
    }

    long getElapsedMillis() {
        return elapsedMillis;
    }

    String getHitMatch() {
        return hitMatch;
    }

    String getDiffSummary() {
        return diffSummary;
    }

    boolean isSentToRepeater() {
        return sentToRepeater;
    }

    String getRepeaterError() {
        return repeaterError;
    }

    String getError() {
        return error;
    }
}
