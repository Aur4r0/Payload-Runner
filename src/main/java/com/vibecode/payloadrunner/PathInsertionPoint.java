package com.vibecode.payloadrunner;

import burp.IExtensionHelpers;

import java.util.ArrayList;
import java.util.List;

final class PathInsertionPoint implements PayloadInsertionPoint {
    private final IExtensionHelpers helpers;
    private final List<String> headers;
    private final String body;
    private final String name;
    private final PathMutation mutation;

    private PathInsertionPoint(IExtensionHelpers helpers, List<String> headers, String body,
            String name, PathMutation mutation) {
        this.helpers = helpers;
        this.headers = new ArrayList<String>(headers);
        this.body = body;
        this.name = name;
        this.mutation = mutation;
    }

    static List<PathInsertionPoint> fromRequestLine(IExtensionHelpers helpers,
            List<String> headers, String body) {
        List<PathInsertionPoint> points = new ArrayList<PathInsertionPoint>();
        if (headers.isEmpty()) {
            return points;
        }

        RequestLine requestLine = RequestLine.parse(headers.get(0));
        if (requestLine == null) {
            return points;
        }
        String target = requestLine.getTarget();
        if ("*".equals(target)) {
            return points;
        }

        int pathStart = pathStart(target);
        int pathEnd = pathEnd(target, pathStart);
        if (pathStart < 0 || pathEnd <= pathStart) {
            return points;
        }

        String path = target.substring(pathStart, pathEnd);
        int segmentIndex = 0;
        int cursor = 0;
        while (cursor <= path.length()) {
            int end = path.indexOf('/', cursor);
            if (end < 0) {
                end = path.length();
            }
            String rawSegment = path.substring(cursor, end);
            if (!rawSegment.isEmpty()) {
                segmentIndex++;
                String decodedSegment = safeUrlDecode(helpers, rawSegment);
                if (rawSegment.contains("*") || decodedSegment.contains("*")) {
                    final int valueStart = pathStart + cursor;
                    final int valueEnd = pathStart + end;
                    final String originalRaw = rawSegment;
                    final String originalDecoded = decodedSegment;
                    points.add(new PathInsertionPoint(helpers, headers, body,
                            "url:path[" + segmentIndex + "]",
                            (payload, encodingStrategy) -> replacePathSegment(helpers, target,
                                    valueStart, valueEnd, originalRaw, originalDecoded, payload,
                                    encodingStrategy)));
                }
            }
            if (end == path.length()) {
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
            return helpers.buildHttpMessage(new ArrayList<String>(headers),
                    helpers.stringToBytes(body));
        }
        List<String> newHeaders = new ArrayList<String>(headers);
        newHeaders.set(0, requestLine.withTarget(mutation.buildTarget(payload, encodingStrategy)));
        return helpers.buildHttpMessage(newHeaders, helpers.stringToBytes(body));
    }

    private static String replacePathSegment(IExtensionHelpers helpers, String target,
            int valueStart, int valueEnd, String rawSegment, String decodedSegment,
            String payload, EncodingStrategy encodingStrategy) {
        String replacement;
        if (rawSegment.contains("*")) {
            replacement = rawSegment.replace("*", encodingStrategy.encode(helpers, payload));
        } else {
            replacement = encodeWholeValue(helpers, decodedSegment.replace("*", payload),
                    encodingStrategy);
        }
        return target.substring(0, valueStart) + replacement + target.substring(valueEnd);
    }

    private static int pathStart(String target) {
        int scheme = target.indexOf("://");
        if (scheme < 0) {
            return target.startsWith("/") ? 0 : -1;
        }
        int authorityStart = scheme + 3;
        int slash = target.indexOf('/', authorityStart);
        int query = target.indexOf('?', authorityStart);
        return slash >= 0 && (query < 0 || slash < query) ? slash : -1;
    }

    private static int pathEnd(String target, int pathStart) {
        if (pathStart < 0) {
            return -1;
        }
        int query = target.indexOf('?', pathStart);
        int fragment = target.indexOf('#', pathStart);
        int end = target.length();
        if (query >= 0) {
            end = Math.min(end, query);
        }
        if (fragment >= 0) {
            end = Math.min(end, fragment);
        }
        return end;
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

    private interface PathMutation {
        String buildTarget(String payload, EncodingStrategy encodingStrategy);
    }
}
