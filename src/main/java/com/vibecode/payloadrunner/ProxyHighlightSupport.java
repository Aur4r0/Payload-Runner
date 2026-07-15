package com.vibecode.payloadrunner;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

final class ProxyHighlightSupport implements IProxyListener {
    private final IBurpExtenderCallbacks callbacks;
    private final Map<String, PendingMessage> active =
            new LinkedHashMap<String, PendingMessage>();

    ProxyHighlightSupport(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    synchronized String begin(IHttpService service, byte[] request) {
        String traceId = UUID.randomUUID().toString();
        active.put(traceId, new PendingMessage(signature(service, request)));
        return traceId;
    }

    void complete(String traceId, boolean hit, HitHighlightColor color) {
        PendingMessage pending;
        synchronized (this) {
            pending = active.remove(traceId);
        }
        if (!hit || color == null || !color.isEnabled()
                || pending == null || pending.message == null) {
            return;
        }
        highlight(pending.message, color);
    }

    void highlight(IHttpRequestResponse message, HitHighlightColor color) {
        if (message == null || color == null || !color.isEnabled()) {
            return;
        }
        try {
            message.setHighlight(color.getBurpColor());
        } catch (RuntimeException ex) {
            callbacks.printError("设置 Burp 数据包颜色失败：" + safeMessage(ex));
        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (!messageIsRequest || message == null || message.getMessageInfo() == null) {
            return;
        }
        IHttpRequestResponse messageInfo = message.getMessageInfo();
        String actualSignature = signature(messageInfo.getHttpService(), messageInfo.getRequest());
        synchronized (this) {
            for (PendingMessage pending : active.values()) {
                if (pending.message == null && pending.signature.equals(actualSignature)) {
                    pending.message = messageInfo;
                    return;
                }
            }
        }
    }

    private static String signature(IHttpService service, byte[] request) {
        if (service == null || request == null) {
            return "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            update(digest, service.getProtocol() == null
                    ? ""
                    : service.getProtocol().toLowerCase(Locale.ROOT));
            update(digest, service.getHost() == null
                    ? ""
                    : service.getHost().toLowerCase(Locale.ROOT));
            update(digest, Integer.toString(service.getPort()));
            digest.update(canonicalRequest(request));
            return hex(digest.digest());
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static byte[] canonicalRequest(byte[] request) {
        int lineEnd = firstLineEnd(request);
        if (lineEnd < 0) {
            return request;
        }
        int contentEnd = lineEnd > 0 && request[lineEnd - 1] == '\r' ? lineEnd - 1 : lineEnd;
        String line = new String(request, 0, contentEnd, StandardCharsets.ISO_8859_1);
        RequestLine requestLine = RequestLine.parse(line);
        if (requestLine == null) {
            return request;
        }
        String canonicalLine = requestLine.withTarget(originForm(requestLine.getTarget()));
        byte[] replacement = canonicalLine.getBytes(StandardCharsets.ISO_8859_1);
        ByteArrayOutputStream output = new ByteArrayOutputStream(
                request.length + Math.max(0, replacement.length - contentEnd));
        output.write(replacement, 0, replacement.length);
        output.write(request, contentEnd, request.length - contentEnd);
        return output.toByteArray();
    }

    private static String originForm(String target) {
        if (target == null || target.isEmpty()) {
            return "/";
        }
        int scheme = target.indexOf("://");
        if (scheme < 0) {
            return target.startsWith("?") ? "/" + target : target;
        }
        int authorityStart = scheme + 3;
        int slash = target.indexOf('/', authorityStart);
        int query = target.indexOf('?', authorityStart);
        if (slash >= 0 && (query < 0 || slash < query)) {
            return target.substring(slash);
        }
        if (query >= 0) {
            return "/" + target.substring(query);
        }
        return "/";
    }

    private static int firstLineEnd(byte[] request) {
        for (int i = 0; i < request.length; i++) {
            if (request[i] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static void update(MessageDigest digest, String value) {
        digest.update(value.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) 0);
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format("%02x", value & 0xff));
        }
        return result.toString();
    }

    private static String safeMessage(RuntimeException exception) {
        return exception.getMessage() == null
                ? exception.getClass().getSimpleName()
                : exception.getMessage();
    }

    private static final class PendingMessage {
        private final String signature;
        private IHttpRequestResponse message;

        private PendingMessage(String signature) {
            this.signature = signature;
        }
    }
}
