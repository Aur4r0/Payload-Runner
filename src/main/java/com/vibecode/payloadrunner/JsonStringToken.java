package com.vibecode.payloadrunner;

import java.util.ArrayList;
import java.util.List;

final class JsonStringToken {
    private final int start;
    private final int end;
    private final String value;

    private JsonStringToken(int start, int end, String value) {
        this.start = start;
        this.end = end;
        this.value = value;
    }

    static List<JsonStringToken> scan(String body) {
        List<JsonStringToken> tokens = new ArrayList<JsonStringToken>();
        int index = 0;
        while (index < body.length()) {
            if (body.charAt(index) != '"') {
                index++;
                continue;
            }
            int start = index;
            StringBuilder value = new StringBuilder();
            index++;
            boolean closed = false;
            while (index < body.length()) {
                char ch = body.charAt(index);
                if (ch == '\\' && index + 1 < body.length()) {
                    EscapeRead escapeRead = JsonStrings.readEscape(body, index);
                    value.append(escapeRead.getValue());
                    index = escapeRead.getNextIndex();
                    continue;
                }
                if (ch == '"') {
                    index++;
                    closed = true;
                    break;
                }
                value.append(ch);
                index++;
            }
            if (closed) {
                tokens.add(new JsonStringToken(start, index, value.toString()));
            }
        }
        return tokens;
    }

    boolean isObjectKey(String body) {
        int index = end;
        while (index < body.length() && Character.isWhitespace(body.charAt(index))) {
            index++;
        }
        return index < body.length() && body.charAt(index) == ':';
    }

    int getStart() {
        return start;
    }

    int getEnd() {
        return end;
    }

    String getValue() {
        return value;
    }
}

