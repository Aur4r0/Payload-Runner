package com.vibecode.payloadrunner;

import burp.IExtensionHelpers;

enum EncodingStrategy {
    URL_ENCODE("URL 编码"),
    JSON_ESCAPE("JSON 转义"),
    RAW("原始内容");

    private final String label;

    EncodingStrategy(String label) {
        this.label = label;
    }

    String encode(IExtensionHelpers helpers, String payload) {
        switch (this) {
            case URL_ENCODE:
                return helpers.urlEncode(payload);
            case JSON_ESCAPE:
                return JsonStrings.escape(payload);
            case RAW:
            default:
                return payload;
        }
    }

    @Override
    public String toString() {
        return label;
    }
}
