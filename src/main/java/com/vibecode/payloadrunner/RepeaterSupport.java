package com.vibecode.payloadrunner;

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;

final class RepeaterSupport {
    private static final int MAX_CAPTION_LENGTH = 80;

    private RepeaterSupport() {
    }

    static SendResult maybeSend(IBurpExtenderCallbacks callbacks, IHttpService service,
            byte[] request, String method, String path, String category, String parameterName,
            String customCaptionPrefix, int index, boolean enabled) {
        if (!enabled) {
            return SendResult.disabled();
        }
        String caption = buildCaption(method, path, category, parameterName,
                customCaptionPrefix, index);
        try {
            callbacks.sendToRepeater(service.getHost(), service.getPort(), useHttps(service),
                    request, caption);
            return SendResult.sent(caption);
        } catch (Exception ex) {
            String message = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
            try {
                callbacks.printError("sendToRepeater failed: " + message);
            } catch (Exception ignored) {
                // Some test doubles or older environments may not surface extension stderr.
            }
            return SendResult.failed(caption, message);
        }
    }

    static String buildCaption(String method, String path, String category, String parameterName,
            int index) {
        return buildDefaultCaption(method, path, category, parameterName, index);
    }

    static String buildCaption(String method, String path, String category, String parameterName,
            String customCaptionPrefix, int index) {
        String customPrefix = clean(nullToEmpty(customCaptionPrefix)).trim();
        return buildCustomCaption(customPrefix, index);
    }

    private static String buildDefaultCaption(String method, String path, String category,
            String parameterName, int index) {
        String prefix = clean(nullToEmpty(method) + " " + nullToEmpty(path)).trim();
        String safeCategory = clean(nullToEmpty(category));
        String safeParameter = clean(nullToEmpty(parameterName));
        String indexLabel = "#" + padIndex(index);

        String full = prefix + " | " + safeCategory + " | " + safeParameter + " | " + indexLabel;
        if (full.length() <= MAX_CAPTION_LENGTH) {
            return full;
        }

        String suffix = " | " + safeCategory + " | " + indexLabel;
        if (prefix.length() + suffix.length() <= MAX_CAPTION_LENGTH) {
            return prefix + suffix;
        }

        int prefixMax = MAX_CAPTION_LENGTH - suffix.length();
        if (prefixMax < 8) {
            suffix = " | " + indexLabel;
            prefixMax = MAX_CAPTION_LENGTH - suffix.length();
        }
        int keep = Math.max(1, prefixMax - 3);
        String shortenedPrefix = prefix.length() <= keep ? prefix : prefix.substring(0, keep) + "...";
        return shortenedPrefix + suffix;
    }

    private static String buildCustomCaption(String prefix, int index) {
        String indexLabel = Integer.toString(index < 0 ? 0 : index);
        if (prefix.length() + indexLabel.length() <= MAX_CAPTION_LENGTH) {
            return prefix + indexLabel;
        }
        int keep = MAX_CAPTION_LENGTH - indexLabel.length();
        if (keep <= 3) {
            return prefix.substring(0, Math.max(1, keep)) + indexLabel;
        }
        return prefix.substring(0, keep - 3) + "..." + indexLabel;
    }

    private static boolean useHttps(IHttpService service) {
        String protocol = service.getProtocol();
        return protocol != null && "https".equalsIgnoreCase(protocol);
    }

    private static String padIndex(int index) {
        if (index < 0) {
            index = 0;
        }
        if (index < 1000) {
            String value = Integer.toString(index);
            StringBuilder padded = new StringBuilder();
            for (int i = value.length(); i < 3; i++) {
                padded.append('0');
            }
            padded.append(value);
            return padded.toString();
        }
        return Integer.toString(index);
    }

    private static String clean(String value) {
        return value.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ');
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    static final class SendResult {
        private final boolean sent;
        private final String caption;
        private final String error;

        private SendResult(boolean sent, String caption, String error) {
            this.sent = sent;
            this.caption = caption;
            this.error = error;
        }

        static SendResult disabled() {
            return new SendResult(false, "", "");
        }

        static SendResult sent(String caption) {
            return new SendResult(true, caption, "");
        }

        static SendResult failed(String caption, String error) {
            return new SendResult(false, caption, error == null ? "" : error);
        }

        boolean isSent() {
            return sent;
        }

        String getCaption() {
            return caption;
        }

        String getError() {
            return error;
        }
    }
}
