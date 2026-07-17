package com.vibecode.payloadrunner;

import burp.IExtensionHelpers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class HeaderInsertionPoint implements PayloadInsertionPoint {
    private final IExtensionHelpers helpers;
    private final List<String> headers;
    private final String body;
    private final String name;
    private final int headerIndex;
    private final String headerName;
    private final String headerValue;

    private HeaderInsertionPoint(IExtensionHelpers helpers, List<String> headers, String body,
            String name, int headerIndex, String headerName, String headerValue) {
        this.helpers = helpers;
        this.headers = new ArrayList<String>(headers);
        this.body = body;
        this.name = name;
        this.headerIndex = headerIndex;
        this.headerName = headerName;
        this.headerValue = headerValue;
    }

    static List<HeaderInsertionPoint> fromHeaders(IExtensionHelpers helpers,
            List<String> headers, String body) {
        List<HeaderInsertionPoint> points = new ArrayList<HeaderInsertionPoint>();
        Map<String, Integer> occurrences = new LinkedHashMap<String, Integer>();
        for (int index = 1; index < headers.size(); index++) {
            String header = headers.get(index);
            int colon = header.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String headerName = header.substring(0, colon).trim();
            String headerValue = header.substring(colon + 1);
            if ("content-length".equalsIgnoreCase(headerName) || !PayloadMarker.contains(headerValue)) {
                continue;
            }
            String occurrenceKey = headerName.toLowerCase(java.util.Locale.ROOT);
            Integer previous = occurrences.get(occurrenceKey);
            int occurrence = previous == null ? 1 : previous.intValue() + 1;
            occurrences.put(occurrenceKey, Integer.valueOf(occurrence));
            String pointName = "header:" + headerName
                    + (occurrence == 1 ? "" : "#" + occurrence);
            points.add(new HeaderInsertionPoint(helpers, headers, body,
                    pointName, index, headerName, headerValue));
        }
        return points;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public byte[] buildRequest(String payload, EncodingStrategy encodingStrategy) {
        List<String> newHeaders = new ArrayList<String>(headers);
        String replacement = PayloadMarker.replaceRegions(headerValue, encodingStrategy.encode(helpers, payload));
        newHeaders.set(headerIndex, headerName + ":" + replacement);
        return helpers.buildHttpMessage(newHeaders, helpers.stringToBytes(body));
    }
}
