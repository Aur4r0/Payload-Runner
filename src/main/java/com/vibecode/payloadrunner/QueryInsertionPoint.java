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
                boolean rawHas = PayloadMarker.contains(rawValue);
                boolean decodedHas = !rawHas && PayloadMarker.contains(decodedValue);
                if (rawHas || decodedHas) {
                    String decodedName = safeUrlDecode(helpers, rawName);
                    String baseName = "url:" + decodedName;
                    int regionCount = rawHas
                            ? PayloadMarker.countRegions(rawValue)
                            : PayloadMarker.countRegions(decodedValue);
                    for (int regionIndex = 0; regionIndex < regionCount; regionIndex++) {
                        final int activeRegion = regionIndex;
                        final boolean useRaw = rawHas;
                        points.add(new QueryInsertionPoint(helpers, headers, body,
                                baseName + PayloadMarker.regionSuffix(regionIndex),
                                (payload, encodingStrategy) -> replaceQueryValue(helpers, target,
                                        valueStart, valueEnd, rawValue, decodedValue, payload,
                                        encodingStrategy, activeRegion, useRaw)));
                    }
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
            return helpers.buildHttpMessage(PayloadMarker.stripMarkersInHeaders(headers),
                    helpers.stringToBytes(PayloadMarker.stripMarkers(body)));
        }

        // Active region is injected first; remaining § pairs elsewhere are stripped to original text.
        // Payload itself should not contain § (same constraint as Burp Intruder markers).
        List<String> newHeaders = PayloadMarker.stripMarkersInHeaders(headers);
        String target = mutation.buildTarget(payload, encodingStrategy);
        newHeaders.set(0, requestLine.withTarget(PayloadMarker.stripMarkers(target)));
        return helpers.buildHttpMessage(newHeaders,
                helpers.stringToBytes(PayloadMarker.stripMarkers(body)));
    }

    private static String replaceQueryValue(IExtensionHelpers helpers, String target,
            int valueStart, int valueEnd, String rawValue, String decodedValue, String payload,
            EncodingStrategy encodingStrategy, int regionIndex, boolean useRaw) {
        String newRawValue;
        if (useRaw) {
            newRawValue = PayloadMarker.replaceRegionAt(rawValue, regionIndex,
                    encodingStrategy.encode(helpers, payload));
        } else {
            newRawValue = encodeWholeValue(helpers,
                    PayloadMarker.replaceRegionAt(decodedValue, regionIndex, payload),
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
