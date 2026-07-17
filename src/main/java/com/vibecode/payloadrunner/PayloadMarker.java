package com.vibecode.payloadrunner;

/**
 * 配对注入标记 {@code §…§}。一对定界符界定一个注入区域，替换时整段（含两个定界符与其间内容）
 * 一起被 payload 取代。空区域 {@code §§} 是合法的“插入点”标记，行为等价于旧的裸 {@code *}。
 * 末尾落单、无法配对的定界符按字面量处理。
 */
final class PayloadMarker {
    static final String MARKER = "§";

    private PayloadMarker() {
    }

    /** 是否至少含一对完整的 {@code §…§}。 */
    static boolean contains(String value) {
        if (value == null) {
            return false;
        }
        int first = value.indexOf(MARKER);
        if (first < 0) {
            return false;
        }
        return value.indexOf(MARKER, first + MARKER.length()) >= 0;
    }

    /** 把每一对完整的 {@code §…§}（含定界符与其间内容）替换为 replacement；落单定界符保留。 */
    static String replaceRegions(String value, String replacement) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        int markerLength = MARKER.length();
        StringBuilder result = new StringBuilder(value.length());
        int cursor = 0;
        while (cursor < value.length()) {
            int open = value.indexOf(MARKER, cursor);
            if (open < 0) {
                result.append(value, cursor, value.length());
                break;
            }
            int close = value.indexOf(MARKER, open + markerLength);
            if (close < 0) {
                result.append(value, cursor, value.length());
                break;
            }
            result.append(value, cursor, open);
            result.append(replacement);
            cursor = close + markerLength;
        }
        return result.toString();
    }

    /** 去掉所有定界符 {@code §}，保留其间的原始内容。 */
    static String stripMarkers(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        return value.replace(MARKER, "");
    }
}
