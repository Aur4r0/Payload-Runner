package com.vibecode.payloadrunner;

import java.util.ArrayList;
import java.util.List;

/**
 * 配对注入标记 {@code §…§}。一对定界符界定一个注入区域，替换时整段（含两个定界符与其间内容）
 * 一起被 payload 取代。空区域 {@code §§} 是合法的“插入点”标记，行为等价于旧的裸 {@code *}。
 * 末尾落单、无法配对的定界符按字面量处理。
 *
 * <p>发送采用 Intruder Sniper 语义：每一对 {@code §…§} 是独立注入点；跑某一个点时，
 * 仅该对替换为 payload，其余配对区域去掉定界符并保留中间原文，发出的报文中不应再含 {@code §}。
 */
final class PayloadMarker {
    static final String MARKER = "§";

    private PayloadMarker() {
    }

    /** 是否至少含一对完整的 {@code §…§}。 */
    static boolean contains(String value) {
        return countRegions(value) > 0;
    }

    /** 完整配对区域的数量（0-based 下标范围 {@code [0, count)}）。 */
    static int countRegions(String value) {
        if (value == null || value.isEmpty()) {
            return 0;
        }
        int markerLength = MARKER.length();
        int count = 0;
        int cursor = 0;
        while (cursor < value.length()) {
            int open = value.indexOf(MARKER, cursor);
            if (open < 0) {
                break;
            }
            int close = value.indexOf(MARKER, open + markerLength);
            if (close < 0) {
                break;
            }
            count++;
            cursor = close + markerLength;
        }
        return count;
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
            result.append(replacement == null ? "" : replacement);
            cursor = close + markerLength;
        }
        return result.toString();
    }

    /**
     * Sniper：只把第 {@code regionIndex} 对（0-based）替换为 {@code replacement}，
     * 其余配对区域去掉定界符并保留中间原文；落单定界符保留。
     * 下标越界时等价于对全部配对区域做 {@link #stripMarkers(String)}（不含落单处理差异：
     * 落单仍保留）。
     */
    static String replaceRegionAt(String value, int regionIndex, String replacement) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        int markerLength = MARKER.length();
        StringBuilder result = new StringBuilder(value.length());
        int cursor = 0;
        int index = 0;
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
            if (index == regionIndex) {
                result.append(replacement == null ? "" : replacement);
            } else {
                result.append(value, open + markerLength, close);
            }
            index++;
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

    /** 对每个 header 行去掉 {@code §}，用于 sniper 清理非活跃标记。 */
    static List<String> stripMarkersInHeaders(List<String> headers) {
        List<String> cleaned = new ArrayList<String>(headers.size());
        for (String header : headers) {
            cleaned.add(stripMarkers(header));
        }
        return cleaned;
    }

    /**
     * 同一字段内第 regionIndex 对（0-based）的展示名后缀：首个无后缀，其后 {@code @2}…
     * 使用 {@code @} 而非 {@code #}，避免与同名 header 第 N 次出现的 {@code #N} 冲突。
     */
    static String regionSuffix(int regionIndex) {
        return regionIndex <= 0 ? "" : "@" + (regionIndex + 1);
    }
}
