package com.vibecode.payloadrunner;

import burp.IBurpExtenderCallbacks;

final class RepeaterSupport {
    private static final int MAX_CAPTION_LENGTH = 80;

    private RepeaterSupport() {
    }

    static SendResult sendRecord(IBurpExtenderCallbacks callbacks, HistoryRecord record,
            int displayIndex) {
        return sendRecord(callbacks, record, displayIndex, "");
    }

    static SendResult sendRecord(IBurpExtenderCallbacks callbacks, HistoryRecord record,
            int displayIndex, String captionPrefix) {
        String caption = buildCaption(record.getMethod(), record.getEndpointPath(),
                record.getCategory(), record.getParameterName(), displayIndex, captionPrefix);
        if (!record.hasRequestBytes()) {
            String message = "request bytes were dropped due to max history";
            logError(callbacks, "sendToRepeater failed: " + message);
            return SendResult.failed(caption, message);
        }
        try {
            callbacks.sendToRepeater(record.getHost(), record.getPort(), record.isUseHttps(),
                    record.getRequestBytes(), caption);
            record.setSentToRepeater(true);
            return SendResult.sent(caption);
        } catch (Exception ex) {
            String message = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
            logError(callbacks, "sendToRepeater failed: " + message);
            return SendResult.failed(caption, message);
        }
    }

    private static void logError(IBurpExtenderCallbacks callbacks, String message) {
        try {
            callbacks.printError(message);
        } catch (Exception ignored) {
            // Some test doubles or older environments may not surface extension stderr.
        }
    }

    static String buildCaption(String method, String path, String category, String parameterName,
            int index) {
        return buildCaption(method, path, category, parameterName, index, "");
    }

    static String buildCaption(String method, String path, String category, String parameterName,
            int index, String captionPrefix) {
        String customPrefix = clean(nullToEmpty(captionPrefix)).trim();
        return buildPrefixCaption(customPrefix, index);
    }

    private static String buildPrefixCaption(String prefix, int index) {
        String indexLabel = Integer.toString(index < 0 ? 0 : index);
        String caption = prefix + indexLabel;
        if (caption.length() <= MAX_CAPTION_LENGTH) {
            return caption;
        }
        int keep = MAX_CAPTION_LENGTH - indexLabel.length();
        if (keep <= 3) {
            return prefix.substring(0, Math.max(1, keep)) + indexLabel;
        }
        return prefix.substring(0, keep - 3) + "..." + indexLabel;
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
