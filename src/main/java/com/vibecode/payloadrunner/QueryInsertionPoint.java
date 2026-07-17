package com.vibecode.payloadrunner;

import burp.IExtensionHelpers;

import java.util.ArrayList;
import java.util.List;

final class QueryInsertionPoint implements PayloadInsertionPoint {
    private final IExtensionHelpers helpers;
    private final List<String> headers;
    private final String body;
    private final String name;
    private final QueryMutation mutation;

    private QueryInsertionPoint(IExtensionHelpers helpers, List<String> headers, String body,
            String name, QueryMutation mutation) {
        this.helpers = helpers;
        this.headers = new ArrayList<String>(headers);
        this.body = body;
        this.name = name;
        this.mutation = mutation;
    }

    static List<QueryInsertionPoint> fromRequestLine(IExtensionHelpers helpers,
            List<String> headers, String body) {
        List<QueryInsertionPoint> points = new ArrayList<QueryInsertionPoint>();
        if (headers.isEmpty()) {
            return points;
        }

        RequestLine requestLine = RequestLine.parse(headers.get(0));
        if (requestLine == null) {
            return points;
        }

        String target = requestLine.getTarget();
        int queryStart = target.indexOf('?');
        if (queryStart < 0 || queryStart == target.length() - 1) {
            return points;
        }

        String query = target.substring(queryStart + 1);
        int cursor = 0;
        while (cursor <= query.length()) {
            int end = query.indexOf('&', cursor);
            if (end < 0) {
                end = query.length();
            }

            String pair = query.substring(cursor, end);
            int equals = pair.indexOf('=');
            if (equals >= 0) {
                String rawName = pair.substring(0, equals);
                String rawValue = pair.substring(equals + 1);
                int valueStart = queryStart + 1 + cursor + equals + 1;
                int valueEnd = queryStart + 1 + end;
                String decodedValue = safeUrlDecode(helpers, rawValue);
                if (PayloadMarker.contains(rawValue) || PayloadMarker.contains(decodedValue)) {
                    String decodedName = safeUrlDecode(helpers, rawName);
                    points.add(new QueryInsertionPoint(helpers, headers, body,
                            "url:" + decodedName,
                            (payload, encodingStrategy) -> replaceQueryValue(helpers, target,
                                    valueStart, valueEnd, rawValue, decodedValue, payload,
                                    encodingStrategy)));
                }
            }

            if (end == query.length()) {
                break;
            }
            cursor = end + 1;
        }
        return points;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public byte[] buildRequest(String payload, EncodingStrategy encodingStrategy) {
        RequestLine requestLine = RequestLine.parse(headers.get(0));
        if (requestLine == null) {
            return helpers.buildHttpMessage(new ArrayList<String>(headers), helpers.stringToBytes(body));
        }

        List<String> newHeaders = new ArrayList<String>(headers);
        newHeaders.set(0, requestLine.withTarget(mutation.buildTarget(payload, encodingStrategy)));
        return helpers.buildHttpMessage(newHeaders, helpers.stringToBytes(body));
    }

    private static String replaceQueryValue(IExtensionHelpers helpers, String target,
            int valueStart, int valueEnd, String rawValue, String decodedValue, String payload,
            EncodingStrategy encodingStrategy) {
        String newRawValue;
        if (PayloadMarker.contains(rawValue)) {
            newRawValue = PayloadMarker.replaceRegions(rawValue, encodingStrategy.encode(helpers, payload));
        } else {
            newRawValue = encodeWholeValue(helpers, PayloadMarker.replaceRegions(decodedValue, payload),
                    encodingStrategy);
        }
        return target.substring(0, valueStart) + newRawValue + target.substring(valueEnd);
    }

    private static String encodeWholeValue(IExtensionHelpers helpers, String value,
            EncodingStrategy encodingStrategy) {
        if (encodingStrategy == EncodingStrategy.URL_ENCODE) {
            return helpers.urlEncode(value);
        }
        if (encodingStrategy == EncodingStrategy.JSON_ESCAPE) {
            return JsonStrings.escape(value);
        }
        return value;
    }

    private static String safeUrlDecode(IExtensionHelpers helpers, String value) {
        try {
            return helpers.urlDecode(value);
        } catch (RuntimeException ex) {
            return value;
        }
    }

    private interface QueryMutation {
        String buildTarget(String payload, EncodingStrategy encodingStrategy);
    }
}
