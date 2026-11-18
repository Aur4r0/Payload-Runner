package com.vibecode.payloadrunner;

/** Valid UTF-8 sequences must be skipped as a whole when looking for legacy A7 markers. */
final class Utf8Sequence {
    private Utf8Sequence() { }

    static int length(byte[] value, int offset) {
        return length(at(value, offset), at(value, offset + 1), at(value, offset + 2), at(value, offset + 3));
    }

    static int length(String value, int offset) {
        return length(at(value, offset), at(value, offset + 1), at(value, offset + 2), at(value, offset + 3));
    }

    private static int at(byte[] value, int offset) { return offset < value.length ? value[offset] & 255 : -1; }
    private static int at(String value, int offset) { return offset < value.length() ? value.charAt(offset) : -1; }
    private static boolean continuation(int value) { return value >= 128 && value <= 191; }

    private static int length(int a, int b, int c, int d) {
        if (!continuation(b)) { return 1; }
        if (a >= 194 && a <= 223) { return 2; }
        if (!continuation(c)) { return 1; }
        if (a >= 224 && a <= 239) {
            return (a == 224 && b < 160) || (a == 237 && b >= 160) ? 1 : 3;
        }
        if (a >= 240 && a <= 244 && continuation(d)) {
            return (a == 240 && b < 144) || (a == 244 && b >= 144) ? 1 : 4;
        }
        return 1;
    }
}
