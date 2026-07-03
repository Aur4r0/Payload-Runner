package com.vibecode.payloadrunner;

interface PayloadInsertionPoint {
    String getName();

    byte[] buildRequest(String payload, EncodingStrategy encodingStrategy);

    default byte[] buildRequest(String payload) {
        return buildRequest(payload, EncodingStrategy.URL_ENCODE);
    }
}
