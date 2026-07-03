package com.vibecode.payloadrunner;

import burp.IExtensionHelpers;

import java.util.ArrayList;
import java.util.List;

final class BodyInsertionPoint implements PayloadInsertionPoint {
    private final IExtensionHelpers helpers;
    private final List<String> headers;
    private final String name;
    private final BodyMutation bodyMutation;

    private BodyInsertionPoint(IExtensionHelpers helpers, List<String> headers, String name,
            BodyMutation bodyMutation) {
        this.helpers = helpers;
        this.headers = new ArrayList<String>(headers);
        this.name = name;
        this.bodyMutation = bodyMutation;
    }

    static List<BodyInsertionPoint> fromFormUrlEncoded(IExtensionHelpers helpers,
            List<String> headers, String body) {
        List<BodyInsertionPoint> points = new ArrayList<BodyInsertionPoint>();
        int cursor = 0;
        while (cursor <= body.length()) {
            int end = body.indexOf('&', cursor);
            if (end < 0) {
                end = body.length();
            }
            String pair = body.substring(cursor, end);
            int equals = pair.indexOf('=');
            if (equals >= 0) {
                String rawName = pair.substring(0, equals);
                String rawValue = pair.substring(equals + 1);
                int valueStart = cursor + equals + 1;
                int valueEnd = end;
                String decodedValue = safeUrlDecode(helpers, rawValue);
                if (rawValue.contains("*") || decodedValue.contains("*")) {
                    String decodedName = safeUrlDecode(helpers, rawName);
                    points.add(new BodyInsertionPoint(helpers, headers, decodedName,
                            (payload, encodingStrategy) -> replaceFormValue(helpers, body,
                                    valueStart, valueEnd, rawValue, decodedValue, payload,
                                    encodingStrategy)));
                }
            }
            if (end == body.length()) {
                break;
            }
            cursor = end + 1;
        }
        return points;
    }

    static List<BodyInsertionPoint> fromJson(IExtensionHelpers helpers, List<String> headers,
            String body) {
        List<BodyInsertionPoint> points = new ArrayList<BodyInsertionPoint>();
        List<JsonStringToken> tokens = JsonStringToken.scan(body);
        String lastKey = null;
        for (JsonStringToken token : tokens) {
            if (token.isObjectKey(body)) {
                lastKey = token.getValue();
                continue;
            }
            if (token.getValue().contains("*")) {
                String name = lastKey == null || lastKey.isEmpty()
                        ? "json@" + token.getStart()
                        : lastKey;
                points.add(new BodyInsertionPoint(helpers, headers, name,
                        (payload, encodingStrategy) -> replaceJsonString(helpers, body, token,
                                payload, encodingStrategy)));
            }
        }
        return points;
    }

    static List<BodyInsertionPoint> fromMultipart(IExtensionHelpers helpers, List<String> headers,
            String body) {
        List<BodyInsertionPoint> points = new ArrayList<BodyInsertionPoint>();
        String boundary = multipartBoundary(headers);
        if (boundary.isEmpty()) {
            return points;
        }

        String marker = "--" + boundary;
        int markerStart = body.indexOf(marker);
        while (markerStart >= 0) {
            int partStart = markerStart + marker.length();
            if (partStart + 1 < body.length() && body.startsWith("--", partStart)) {
                break;
            }
            partStart = skipLineBreak(body, partStart);
            int nextMarker = body.indexOf(marker, partStart);
            if (nextMarker < 0) {
                break;
            }

            int headersEnd = headerEnd(body, partStart, nextMarker);
            if (headersEnd > 0) {
                int contentStart = headersEnd + headerSeparatorLength(body, headersEnd);
                int contentEnd = trimPartTerminator(body, contentStart, nextMarker);
                if (contentStart <= contentEnd) {
                    String content = body.substring(contentStart, contentEnd);
                    if (content.contains("*")) {
                        String partHeaders = body.substring(partStart, headersEnd);
                        String name = multipartName(partHeaders);
                        final int start = contentStart;
                        final int end = contentEnd;
                        points.add(new BodyInsertionPoint(helpers, headers, "multipart:" + name,
                                (payload, encodingStrategy) -> replaceBodySegment(helpers, body,
                                        start, end, payload, encodingStrategy)));
                    }
                }
            }
            markerStart = nextMarker;
        }
        return points;
    }

    static List<BodyInsertionPoint> fromXml(IExtensionHelpers helpers, List<String> headers,
            String body) {
        List<BodyInsertionPoint> points = new ArrayList<BodyInsertionPoint>();
        addXmlAttributePoints(helpers, headers, body, points);
        addXmlTextPoints(helpers, headers, body, points);
        return points;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public byte[] buildRequest(String payload, EncodingStrategy encodingStrategy) {
        String newBody = bodyMutation.buildBody(payload, encodingStrategy);
        return helpers.buildHttpMessage(new ArrayList<String>(headers), helpers.stringToBytes(newBody));
    }

    private static String replaceFormValue(IExtensionHelpers helpers, String body, int valueStart,
            int valueEnd, String rawValue, String decodedValue, String payload,
            EncodingStrategy encodingStrategy) {
        String newRawValue;
        if (rawValue.contains("*")) {
            newRawValue = rawValue.replace("*", encodingStrategy.encode(helpers, payload));
        } else {
            newRawValue = encodeWholeValue(helpers, decodedValue.replace("*", payload),
                    encodingStrategy);
        }
        return body.substring(0, valueStart) + newRawValue + body.substring(valueEnd);
    }

    private static String replaceJsonString(IExtensionHelpers helpers, String body,
            JsonStringToken token, String payload, EncodingStrategy encodingStrategy) {
        String newValue = token.getValue().replace("*", payload);
        if (encodingStrategy == EncodingStrategy.RAW) {
            return body.substring(0, token.getStart() + 1)
                    + newValue
                    + body.substring(token.getEnd() - 1);
        }
        if (encodingStrategy == EncodingStrategy.URL_ENCODE) {
            newValue = token.getValue().replace("*", encodingStrategy.encode(helpers, payload));
        }
        return body.substring(0, token.getStart())
                + JsonStrings.quote(newValue)
                + body.substring(token.getEnd());
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

    private static String replaceBodySegment(IExtensionHelpers helpers, String body, int start,
            int end, String payload, EncodingStrategy encodingStrategy) {
        String value = body.substring(start, end);
        return body.substring(0, start)
                + value.replace("*", encodingStrategy.encode(helpers, payload))
                + body.substring(end);
    }

    private static void addXmlAttributePoints(IExtensionHelpers helpers, List<String> headers,
            String body, List<BodyInsertionPoint> points) {
        int tagStart = body.indexOf('<');
        while (tagStart >= 0) {
            int tagEnd = body.indexOf('>', tagStart + 1);
            if (tagEnd < 0) {
                break;
            }
            if (isXmlDataTag(body, tagStart, tagEnd)) {
                String elementName = xmlElementName(body, tagStart + 1, tagEnd);
                int cursor = tagStart + 1 + elementName.length();
                while (cursor < tagEnd) {
                    int equals = body.indexOf('=', cursor);
                    if (equals < 0 || equals >= tagEnd) {
                        break;
                    }
                    int nameEnd = equals;
                    int nameStart = nameEnd - 1;
                    while (nameStart >= cursor && isXmlNameChar(body.charAt(nameStart))) {
                        nameStart--;
                    }
                    nameStart++;
                    int quoteStart = skipWhitespace(body, equals + 1, tagEnd);
                    if (quoteStart >= tagEnd) {
                        break;
                    }
                    char quote = body.charAt(quoteStart);
                    if (quote != '"' && quote != '\'') {
                        cursor = equals + 1;
                        continue;
                    }
                    int quoteEnd = body.indexOf(quote, quoteStart + 1);
                    if (quoteEnd < 0 || quoteEnd > tagEnd) {
                        break;
                    }
                    String value = body.substring(quoteStart + 1, quoteEnd);
                    if (value.contains("*")) {
                        String attrName = body.substring(nameStart, nameEnd).trim();
                        final int start = quoteStart + 1;
                        final int end = quoteEnd;
                        points.add(new BodyInsertionPoint(helpers, headers,
                                "xml:" + elementName + "@" + attrName,
                                (payload, encodingStrategy) -> replaceBodySegment(helpers, body,
                                        start, end, payload, encodingStrategy)));
                    }
                    cursor = quoteEnd + 1;
                }
            }
            tagStart = body.indexOf('<', tagEnd + 1);
        }
    }

    private static void addXmlTextPoints(IExtensionHelpers helpers, List<String> headers,
            String body, List<BodyInsertionPoint> points) {
        int textStart = body.indexOf('>');
        while (textStart >= 0 && textStart + 1 < body.length()) {
            textStart++;
            int textEnd = body.indexOf('<', textStart);
            if (textEnd < 0) {
                break;
            }
            String text = body.substring(textStart, textEnd);
            if (text.contains("*")) {
                String name = xmlTextElementName(body, textStart);
                final int start = textStart;
                final int end = textEnd;
                points.add(new BodyInsertionPoint(helpers, headers, "xml:" + name,
                        (payload, encodingStrategy) -> replaceBodySegment(helpers, body,
                                start, end, payload, encodingStrategy)));
            }
            textStart = body.indexOf('>', textEnd + 1);
        }
    }

    private static String multipartBoundary(List<String> headers) {
        for (String header : headers) {
            int colon = header.indexOf(':');
            if (colon <= 0 || !"content-type".equalsIgnoreCase(header.substring(0, colon).trim())) {
                continue;
            }
            String[] parts = header.substring(colon + 1).split(";");
            for (String part : parts) {
                String trimmed = part.trim();
                int equals = trimmed.indexOf('=');
                if (equals > 0 && "boundary".equalsIgnoreCase(trimmed.substring(0, equals).trim())) {
                    String value = trimmed.substring(equals + 1).trim();
                    if (value.length() >= 2 && value.charAt(0) == '"'
                            && value.charAt(value.length() - 1) == '"') {
                        value = value.substring(1, value.length() - 1);
                    }
                    return value;
                }
            }
        }
        return "";
    }

    private static int skipLineBreak(String body, int index) {
        if (index + 1 < body.length() && body.charAt(index) == '\r'
                && body.charAt(index + 1) == '\n') {
            return index + 2;
        }
        if (index < body.length() && body.charAt(index) == '\n') {
            return index + 1;
        }
        return index;
    }

    private static int headerEnd(String body, int start, int end) {
        int crlf = body.indexOf("\r\n\r\n", start);
        int lf = body.indexOf("\n\n", start);
        int result = -1;
        if (crlf >= 0 && crlf < end) {
            result = crlf;
        }
        if (lf >= 0 && lf < end && (result < 0 || lf < result)) {
            result = lf;
        }
        return result;
    }

    private static int headerSeparatorLength(String body, int headersEnd) {
        return body.startsWith("\r\n\r\n", headersEnd) ? 4 : 2;
    }

    private static int trimPartTerminator(String body, int contentStart, int nextMarker) {
        int end = nextMarker;
        if (end - 2 >= contentStart && body.substring(end - 2, end).equals("\r\n")) {
            return end - 2;
        }
        if (end - 1 >= contentStart && body.charAt(end - 1) == '\n') {
            return end - 1;
        }
        return end;
    }

    private static String multipartName(String partHeaders) {
        String lower = partHeaders.toLowerCase();
        int nameAt = lower.indexOf("name=");
        if (nameAt < 0) {
            return "part";
        }
        int start = nameAt + 5;
        if (start >= partHeaders.length()) {
            return "part";
        }
        char quote = partHeaders.charAt(start);
        if (quote == '"' || quote == '\'') {
            int end = partHeaders.indexOf(quote, start + 1);
            return end > start ? partHeaders.substring(start + 1, end) : "part";
        }
        int end = start;
        while (end < partHeaders.length() && partHeaders.charAt(end) != ';'
                && !Character.isWhitespace(partHeaders.charAt(end))) {
            end++;
        }
        return partHeaders.substring(start, end);
    }

    private static boolean isXmlDataTag(String body, int tagStart, int tagEnd) {
        if (tagStart + 1 >= tagEnd) {
            return false;
        }
        char next = body.charAt(tagStart + 1);
        return next != '/' && next != '?' && next != '!';
    }

    private static String xmlElementName(String body, int start, int end) {
        int cursor = skipWhitespace(body, start, end);
        int nameEnd = cursor;
        while (nameEnd < end && isXmlNameChar(body.charAt(nameEnd))) {
            nameEnd++;
        }
        return nameEnd > cursor ? body.substring(cursor, nameEnd) : "element";
    }

    private static String xmlTextElementName(String body, int textStart) {
        int tagStart = body.lastIndexOf('<', textStart);
        int tagEnd = body.indexOf('>', tagStart);
        if (tagStart < 0 || tagEnd < 0 || tagEnd >= textStart || !isXmlDataTag(body, tagStart, tagEnd)) {
            return "text";
        }
        return xmlElementName(body, tagStart + 1, tagEnd);
    }

    private static int skipWhitespace(String body, int start, int end) {
        int cursor = start;
        while (cursor < end && Character.isWhitespace(body.charAt(cursor))) {
            cursor++;
        }
        return cursor;
    }

    private static boolean isXmlNameChar(char ch) {
        return Character.isLetterOrDigit(ch) || ch == '_' || ch == ':' || ch == '-' || ch == '.';
    }

    private static String safeUrlDecode(IExtensionHelpers helpers, String value) {
        try {
            return helpers.urlDecode(value);
        } catch (RuntimeException ex) {
            return value;
        }
    }

    private interface BodyMutation {
        String buildBody(String payload, EncodingStrategy encodingStrategy);
    }
}
