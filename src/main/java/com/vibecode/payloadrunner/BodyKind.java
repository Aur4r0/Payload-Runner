package com.vibecode.payloadrunner;

import java.util.List;
import java.util.Locale;

enum BodyKind {
    JSON("JSON"),
    FORM_URLENCODED("表单"),
    MULTIPART("多段表单"),
    XML("XML"),
    RAW("原始请求体"),
    UNSUPPORTED("暂不支持");

    private final String label;

    BodyKind(String label) {
        this.label = label;
    }

    String getLabel() {
        return label;
    }

    static BodyKind detect(List<String> headers, String body) {
        String contentType = "";
        for (String header : headers) {
            int colon = header.indexOf(':');
            if (colon > 0 && "content-type".equalsIgnoreCase(header.substring(0, colon).trim())) {
                contentType = header.substring(colon + 1).toLowerCase(Locale.ROOT);
                break;
            }
        }

        String trimmed = body.trim();
        if (contentType.contains("multipart/form-data")) {
            return MULTIPART;
        }
        if (contentType.contains("application/json")
                || trimmed.startsWith("{")
                || trimmed.startsWith("[")) {
            return JSON;
        }
        if (contentType.contains("xml")
                || contentType.contains("+xml")
                || trimmed.startsWith("<?xml")
                || (trimmed.startsWith("<") && trimmed.endsWith(">"))) {
            return XML;
        }
        if (contentType.contains("application/x-www-form-urlencoded")
                || looksLikeFormUrlEncoded(trimmed)) {
            return FORM_URLENCODED;
        }
        if (PayloadMarker.contains(body)) {
            return RAW;
        }
        return UNSUPPORTED;
    }

    private static boolean looksLikeFormUrlEncoded(String body) {
        if (body.indexOf('=') < 1 || body.indexOf('\n') >= 0 || body.indexOf('\r') >= 0) {
            return false;
        }
        return !body.startsWith("{") && !body.startsWith("[");
    }
}
