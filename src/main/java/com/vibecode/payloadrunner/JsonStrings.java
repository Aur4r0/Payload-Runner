package com.vibecode.payloadrunner;

final class JsonStrings {
    private JsonStrings() {
    }

    static EscapeRead readEscape(String text, int slashIndex) {
        int escapedIndex = slashIndex + 1;
        if (escapedIndex >= text.length()) {
            return new EscapeRead("\\", slashIndex + 1);
        }
        char escaped = text.charAt(escapedIndex);
        switch (escaped) {
            case '"':
                return new EscapeRead("\"", escapedIndex + 1);
            case '\\':
                return new EscapeRead("\\", escapedIndex + 1);
            case '/':
                return new EscapeRead("/", escapedIndex + 1);
            case 'b':
                return new EscapeRead("\b", escapedIndex + 1);
            case 'f':
                return new EscapeRead("\f", escapedIndex + 1);
            case 'n':
                return new EscapeRead("\n", escapedIndex + 1);
            case 'r':
                return new EscapeRead("\r", escapedIndex + 1);
            case 't':
                return new EscapeRead("\t", escapedIndex + 1);
            case 'u':
                return readUnicodeEscape(text, escapedIndex + 1);
            default:
                return new EscapeRead(String.valueOf(escaped), escapedIndex + 1);
        }
    }

    static String quote(String value) {
        return "\"" + escape(value) + "\"";
    }

    static String escape(String value) {
        StringBuilder quoted = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"':
                    quoted.append("\\\"");
                    break;
                case '\\':
                    quoted.append("\\\\");
                    break;
                case '\b':
                    quoted.append("\\b");
                    break;
                case '\f':
                    quoted.append("\\f");
                    break;
                case '\n':
                    quoted.append("\\n");
                    break;
                case '\r':
                    quoted.append("\\r");
                    break;
                case '\t':
                    quoted.append("\\t");
                    break;
                default:
                    if (ch < 0x20) {
                        appendUnicodeEscape(quoted, ch);
                    } else {
                        quoted.append(ch);
                }
                break;
            }
        }
        return quoted.toString();
    }

    private static EscapeRead readUnicodeEscape(String text, int hexStart) {
        if (hexStart + 4 > text.length()) {
            return new EscapeRead("u", hexStart);
        }
        String hex = text.substring(hexStart, hexStart + 4);
        try {
            return new EscapeRead(String.valueOf((char) Integer.parseInt(hex, 16)), hexStart + 4);
        } catch (NumberFormatException ex) {
            return new EscapeRead("u" + hex, hexStart + 4);
        }
    }

    private static void appendUnicodeEscape(StringBuilder target, char ch) {
        String hex = Integer.toHexString(ch);
        target.append("\\u");
        for (int i = hex.length(); i < 4; i++) {
            target.append('0');
        }
        target.append(hex);
    }
}
