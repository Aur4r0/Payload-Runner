package com.vibecode.payloadrunner;

import burp.IHttpService;

import java.util.Arrays;

final class HistoryRecord {
    private final long id;
    private final String endpointKey;
    private byte[] requestBytes;
    private byte[] responseBytes;
    private final boolean responseTruncated;
    private final String method;
    private final String path;
    private final String endpointPath;
    private final String host;
    private final int port;
    private final boolean useHttps;
    private final String category;
    private final String parameterName;
    private final String payload;
    private final int statusCode;
    private final int responseLength;
    private final long responseTimeMs;
    private final long timestamp;
    private boolean interesting;
    private boolean sentToRepeater;
    private int resultRowId = -1;

    HistoryRecord(long id, RequestTemplate template, String parameterName, String category,
            String payload, byte[] requestBytes, byte[] responseBytes, int statusCode,
            int responseLength, long responseTimeMs, long timestamp) {
        this(id, template, parameterName, category, payload, requestBytes, responseBytes,
                statusCode, responseLength, responseTimeMs, timestamp, Integer.MAX_VALUE);
    }

    HistoryRecord(long id, RequestTemplate template, String parameterName, String category,
            String payload, byte[] requestBytes, byte[] responseBytes, int statusCode,
            int responseLength, long responseTimeMs, long timestamp, int maxResponseBytes) {
        this.id = id;
        this.requestBytes = copy(requestBytes);
        int responseLimit = maxResponseBytes <= 0 ? Integer.MAX_VALUE : maxResponseBytes;
        this.responseBytes = copy(responseBytes, responseLimit);
        this.responseTruncated = responseBytes != null && responseBytes.length > responseLimit;
        this.method = safe(template.getMethod());
        this.path = safe(template.getPath());
        this.endpointPath = stripQuery(this.path);
        this.host = safe(template.getHost());
        IHttpService service = template.getService();
        this.port = service == null ? -1 : service.getPort();
        this.useHttps = service != null && "https".equalsIgnoreCase(service.getProtocol());
        this.category = safe(category);
        this.parameterName = safe(parameterName);
        this.payload = safe(payload);
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.responseTimeMs = responseTimeMs;
        this.timestamp = timestamp;
        String scheme = this.useHttps ? "https" : "http";
        this.endpointKey = this.method + " " + scheme + "://" + this.host + ":"
                + this.port + this.endpointPath;
    }

    long getId() {
        return id;
    }

    String getEndpointKey() {
        return endpointKey;
    }

    byte[] getRequestBytes() {
        return requestBytes;
    }

    byte[] getResponseBytes() {
        return responseBytes;
    }

    boolean hasRequestBytes() {
        return requestBytes != null;
    }

    boolean isResponseTruncated() {
        return responseTruncated;
    }

    void discardMessages() {
        requestBytes = null;
        responseBytes = null;
    }

    String getMethod() {
        return method;
    }

    String getPath() {
        return path;
    }

    String getEndpointPath() {
        return endpointPath;
    }

    String getHost() {
        return host;
    }

    int getPort() {
        return port;
    }

    boolean isUseHttps() {
        return useHttps;
    }

    String getCategory() {
        return category;
    }

    String getParameterName() {
        return parameterName;
    }

    String getPayload() {
        return payload;
    }

    int getStatusCode() {
        return statusCode;
    }

    int getResponseLength() {
        return responseLength;
    }

    long getResponseTimeMs() {
        return responseTimeMs;
    }

    long getTimestamp() {
        return timestamp;
    }

    boolean isInteresting() {
        return interesting;
    }

    void setInteresting(boolean interesting) {
        this.interesting = interesting;
    }

    boolean isSentToRepeater() {
        return sentToRepeater;
    }

    void setSentToRepeater(boolean sentToRepeater) {
        this.sentToRepeater = sentToRepeater;
    }

    int getResultRowId() {
        return resultRowId;
    }

    void setResultRowId(int resultRowId) {
        this.resultRowId = resultRowId;
    }

    String payloadPreview() {
        if (payload.length() <= 80) {
            return payload;
        }
        return payload.substring(0, 77) + "...";
    }

    private static String stripQuery(String value) {
        int query = value.indexOf('?');
        if (query >= 0) {
            return value.substring(0, query);
        }
        return value.isEmpty() ? "/" : value;
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static byte[] copy(byte[] value) {
        return value == null ? null : Arrays.copyOf(value, value.length);
    }

    private static byte[] copy(byte[] value, int maxBytes) {
        if (value == null) {
            return null;
        }
        int length = Math.min(value.length, Math.max(0, maxBytes));
        return Arrays.copyOf(value, length);
    }
}
