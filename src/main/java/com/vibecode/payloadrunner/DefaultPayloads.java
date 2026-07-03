package com.vibecode.payloadrunner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

final class DefaultPayloads {
    private DefaultPayloads() {
    }

    static String load() {
        InputStream input = DefaultPayloads.class.getResourceAsStream("/payloads.yaml");
        if (input == null) {
            return fallback();
        }
        try {
            return read(input);
        } catch (IOException ex) {
            return fallback();
        }
    }

    private static String read(InputStream input) throws IOException {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
            }
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        } finally {
            input.close();
        }
    }

    private static String fallback() {
        return "xss:\n"
                + "  - \"<script>alert(1)</script>\"\n"
                + "\n"
                + "sqli:\n"
                + "  - \"' OR '1'='1\"\n";
    }
}

