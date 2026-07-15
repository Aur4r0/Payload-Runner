package com.vibecode.payloadrunner;

import burp.IHttpService;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

final class ProxyTransport {
    private static final int CONNECT_TIMEOUT_MILLIS = 10000;
    private static final int READ_TIMEOUT_MILLIS = 60000;
    private static final int MAX_HEADER_BYTES = 1024 * 1024;

    private ProxyTransport() {
    }

    static byte[] send(IHttpService targetService, byte[] request, String proxyHost,
            int proxyPort) throws IOException {
        return send(targetService, request, proxyHost, proxyPort, null);
    }

    static byte[] send(IHttpService targetService, byte[] request, String proxyHost,
            int proxyPort, X509Certificate proxyCa) throws IOException {
        return send(targetService, request, proxyHost, proxyPort, proxyCa, new Cancellation());
    }

    static byte[] send(IHttpService targetService, byte[] request, String proxyHost,
            int proxyPort, X509Certificate proxyCa, Cancellation cancellation) throws IOException {
        validate(targetService, request, proxyHost, proxyPort);
        if (cancellation == null) {
            cancellation = new Cancellation();
        }
        cancellation.throwIfCancelled();
        Socket proxySocket = new Socket();
        try {
            cancellation.register(proxySocket);
            proxySocket.connect(new InetSocketAddress(normalizedHost(proxyHost), proxyPort),
                    CONNECT_TIMEOUT_MILLIS);
            cancellation.throwIfCancelled();
            proxySocket.setSoTimeout(READ_TIMEOUT_MILLIS);
            if (isHttps(targetService)) {
                return sendHttps(proxySocket, targetService, request, proxyCa, cancellation);
            }
            return sendHttp(proxySocket, targetService, request);
        } catch (SocketTimeoutException ex) {
            if (cancellation.isCancelled()) {
                throw new RequestCancelledException();
            }
            throw new IOException("连接或读取 Proxy 超时。", ex);
        } catch (IOException ex) {
            if (cancellation.isCancelled()) {
                throw new RequestCancelledException();
            }
            throw ex;
        } finally {
            cancellation.unregister(proxySocket);
            closeQuietly(proxySocket);
        }
    }

    private static byte[] sendHttp(Socket socket, IHttpService targetService, byte[] request)
            throws IOException {
        byte[] proxyRequest = withProxyRequestTarget(request, targetService, true);
        OutputStream output = socket.getOutputStream();
        output.write(proxyRequest);
        output.flush();
        return readResponse(socket.getInputStream(), requestMethod(request));
    }

    private static byte[] sendHttps(Socket proxySocket, IHttpService targetService,
            byte[] request, X509Certificate proxyCa, Cancellation cancellation) throws IOException {
        String host = normalizedHost(targetService.getHost());
        String authority = authority(host, targetService.getPort());
        String connectRequest = "CONNECT " + authority + " HTTP/1.1\r\n"
                + "Host: " + authority + "\r\n"
                + "Proxy-Connection: keep-alive\r\n"
                + "\r\n";
        OutputStream proxyOutput = proxySocket.getOutputStream();
        proxyOutput.write(connectRequest.getBytes(StandardCharsets.ISO_8859_1));
        proxyOutput.flush();

        byte[] connectResponse = readHeader(proxySocket.getInputStream());
        int connectStatus = statusCode(connectResponse);
        if (connectStatus < 200 || connectStatus >= 300) {
            throw new IOException("Proxy CONNECT 失败（HTTP "
                    + (connectStatus < 0 ? "未知" : Integer.toString(connectStatus)) + "）。");
        }

        SSLSocketFactory factory = ProxyTlsTrust.socketFactory(proxyCa);
        SSLSocket tlsSocket = (SSLSocket) factory.createSocket(proxySocket, host,
                targetService.getPort(), true);
        try {
            cancellation.register(tlsSocket);
            cancellation.throwIfCancelled();
            tlsSocket.setSoTimeout(READ_TIMEOUT_MILLIS);
            SSLParameters parameters = tlsSocket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            if (!isIpLiteral(host)) {
                List<javax.net.ssl.SNIServerName> serverNames =
                        new ArrayList<javax.net.ssl.SNIServerName>();
                serverNames.add(new SNIHostName(host));
                parameters.setServerNames(serverNames);
            }
            tlsSocket.setSSLParameters(parameters);
            tlsSocket.startHandshake();

            byte[] tunneledRequest = withProxyRequestTarget(request, targetService, false);
            OutputStream output = tlsSocket.getOutputStream();
            output.write(tunneledRequest);
            output.flush();
            return readResponse(tlsSocket.getInputStream(), requestMethod(request));
        } finally {
            cancellation.unregister(tlsSocket);
            closeQuietly(tlsSocket);
        }
    }

    private static byte[] readResponse(InputStream input, String requestMethod) throws IOException {
        while (true) {
            byte[] header = readHeader(input);
            int statusCode = statusCode(header);
            if (statusCode >= 100 && statusCode < 200 && statusCode != 101) {
                continue;
            }

            ByteArrayOutputStream response = new ByteArrayOutputStream(header.length + 4096);
            response.write(header);
            if (hasNoBody(requestMethod, statusCode)) {
                return response.toByteArray();
            }

            HeaderInfo headerInfo = HeaderInfo.parse(header);
            if (headerInfo.chunked) {
                readChunkedBody(input, response);
            } else if (headerInfo.contentLength >= 0) {
                copyExactly(input, response, headerInfo.contentLength);
            } else {
                copyUntilEof(input, response);
            }
            return response.toByteArray();
        }
    }

    private static void readChunkedBody(InputStream input, ByteArrayOutputStream output)
            throws IOException {
        while (true) {
            byte[] sizeLine = readLine(input);
            output.write(sizeLine);
            String line = lineText(sizeLine).trim();
            int semicolon = line.indexOf(';');
            String sizeText = semicolon >= 0 ? line.substring(0, semicolon).trim() : line;
            long chunkSize;
            try {
                chunkSize = Long.parseLong(sizeText, 16);
            } catch (NumberFormatException ex) {
                throw new IOException("Proxy 返回了无效的分块响应。", ex);
            }
            if (chunkSize < 0) {
                throw new IOException("Proxy 返回了无效的分块响应。");
            }
            if (chunkSize == 0) {
                while (true) {
                    byte[] trailer = readLine(input);
                    output.write(trailer);
                    if (lineText(trailer).isEmpty()) {
                        return;
                    }
                }
            }
            copyExactly(input, output, chunkSize);
            byte[] terminator = readLine(input);
            output.write(terminator);
            if (!lineText(terminator).isEmpty()) {
                throw new IOException("Proxy 返回了无效的分块响应结尾。");
            }
        }
    }

    private static void copyExactly(InputStream input, ByteArrayOutputStream output, long length)
            throws IOException {
        byte[] buffer = new byte[8192];
        long remaining = length;
        while (remaining > 0) {
            int count = input.read(buffer, 0, (int) Math.min(buffer.length, remaining));
            if (count < 0) {
                throw new EOFException("Proxy 响应在预期长度之前结束。");
            }
            output.write(buffer, 0, count);
            remaining -= count;
        }
    }

    private static void copyUntilEof(InputStream input, ByteArrayOutputStream output)
            throws IOException {
        byte[] buffer = new byte[8192];
        int count;
        while ((count = input.read(buffer)) >= 0) {
            output.write(buffer, 0, count);
        }
    }

    private static byte[] readHeader(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(512);
        int state = 0;
        while (output.size() < MAX_HEADER_BYTES) {
            int value = input.read();
            if (value < 0) {
                throw new EOFException("Proxy 在返回完整响应头之前关闭了连接。");
            }
            output.write(value);
            if (state == 0) {
                state = value == '\r' ? 1 : value == '\n' ? 4 : 0;
            } else if (state == 1) {
                state = value == '\n' ? 2 : value == '\r' ? 1 : 0;
            } else if (state == 2) {
                state = value == '\r' ? 3 : value == '\n' ? 4 : 0;
            } else if (state == 3) {
                if (value == '\n') {
                    return output.toByteArray();
                }
                state = 0;
            } else if (state == 4) {
                if (value == '\n') {
                    return output.toByteArray();
                }
                state = value == '\r' ? 1 : 0;
            }
        }
        throw new IOException("Proxy 响应头超过 1 MB。" );
    }

    private static byte[] readLine(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(64);
        while (output.size() < MAX_HEADER_BYTES) {
            int value = input.read();
            if (value < 0) {
                throw new EOFException("Proxy 响应意外结束。");
            }
            output.write(value);
            if (value == '\n') {
                return output.toByteArray();
            }
        }
        throw new IOException("Proxy 响应行超过 1 MB。" );
    }

    private static byte[] withProxyRequestTarget(byte[] request, IHttpService targetService,
            boolean absoluteForm) throws IOException {
        int lineEnd = firstLineEnd(request);
        int contentEnd = lineEnd > 0 && request[lineEnd - 1] == '\r' ? lineEnd - 1 : lineEnd;
        String line = new String(request, 0, contentEnd, StandardCharsets.ISO_8859_1);
        RequestLine requestLine = RequestLine.parse(line);
        if (requestLine == null) {
            throw new IOException("请求行格式无效，无法通过 Proxy 发送。");
        }
        String path = originForm(requestLine.getTarget());
        String target = absoluteForm ? absoluteTarget(targetService, path) : path;
        byte[] replacement = requestLine.withTarget(target)
                .getBytes(StandardCharsets.ISO_8859_1);
        ByteArrayOutputStream output = new ByteArrayOutputStream(
                request.length + Math.max(0, replacement.length - contentEnd));
        output.write(replacement);
        output.write(request, contentEnd, request.length - contentEnd);
        return output.toByteArray();
    }

    private static String absoluteTarget(IHttpService service, String path) {
        String protocol = service.getProtocol() == null
                ? "http"
                : service.getProtocol().toLowerCase(Locale.ROOT);
        String host = normalizedHost(service.getHost());
        int port = service.getPort();
        boolean defaultPort = ("http".equals(protocol) && port == 80)
                || ("https".equals(protocol) && port == 443);
        return protocol + "://" + authority(host, defaultPort ? -1 : port) + path;
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

    private static int firstLineEnd(byte[] request) throws IOException {
        for (int i = 0; i < request.length; i++) {
            if (request[i] == '\n') {
                return i;
            }
        }
        throw new IOException("请求缺少完整请求行。");
    }

    private static String requestMethod(byte[] request) throws IOException {
        int lineEnd = firstLineEnd(request);
        int contentEnd = lineEnd > 0 && request[lineEnd - 1] == '\r' ? lineEnd - 1 : lineEnd;
        String line = new String(request, 0, contentEnd, StandardCharsets.ISO_8859_1);
        int space = line.indexOf(' ');
        return space <= 0 ? "" : line.substring(0, space);
    }

    private static int statusCode(byte[] header) {
        String text = new String(header, StandardCharsets.ISO_8859_1);
        int lineEnd = text.indexOf('\n');
        String statusLine = (lineEnd >= 0 ? text.substring(0, lineEnd) : text).trim();
        String[] parts = statusLine.split("\\s+", 3);
        if (parts.length < 2) {
            return -1;
        }
        try {
            return Integer.parseInt(parts[1]);
        } catch (NumberFormatException ex) {
            return -1;
        }
    }

    private static boolean hasNoBody(String method, int statusCode) {
        return "HEAD".equalsIgnoreCase(method)
                || (statusCode >= 100 && statusCode < 200)
                || statusCode == 204
                || statusCode == 304;
    }

    private static boolean isHttps(IHttpService service) {
        return "https".equalsIgnoreCase(service.getProtocol());
    }

    private static String authority(String host, int port) {
        String formattedHost = host.indexOf(':') >= 0 && !host.startsWith("[")
                ? "[" + host + "]"
                : host;
        return port > 0 ? formattedHost + ":" + port : formattedHost;
    }

    private static String normalizedHost(String host) {
        String normalized = host == null ? "" : host.trim();
        if (normalized.startsWith("[") && normalized.endsWith("]")) {
            return normalized.substring(1, normalized.length() - 1);
        }
        return normalized;
    }

    private static boolean isIpLiteral(String host) {
        if (host.indexOf(':') >= 0) {
            return true;
        }
        return host.matches("\\d{1,3}(?:\\.\\d{1,3}){3}");
    }

    private static String lineText(byte[] line) {
        String text = new String(line, StandardCharsets.ISO_8859_1);
        if (text.endsWith("\n")) {
            text = text.substring(0, text.length() - 1);
        }
        if (text.endsWith("\r")) {
            text = text.substring(0, text.length() - 1);
        }
        return text;
    }

    private static void validate(IHttpService service, byte[] request, String proxyHost,
            int proxyPort) throws IOException {
        if (service == null || normalizedHost(service.getHost()).isEmpty()) {
            throw new IOException("目标服务信息不完整。");
        }
        if (service.getPort() < 1 || service.getPort() > 65535) {
            throw new IOException("目标服务端口无效。");
        }
        if (request == null || request.length == 0) {
            throw new IOException("请求报文为空。");
        }
        if (proxyHost == null || proxyHost.trim().isEmpty()) {
            throw new IOException("Proxy 地址为空。");
        }
        if (proxyPort < 1 || proxyPort > 65535) {
            throw new IOException("Proxy 端口无效。");
        }
        if (normalizedHost(service.getHost()).equalsIgnoreCase(normalizedHost(proxyHost))
                && service.getPort() == proxyPort) {
            throw new IOException("目标服务与 Proxy 地址和端口相同，已阻止可能的代理循环。");
        }
        if (!"http".equalsIgnoreCase(service.getProtocol())
                && !"https".equalsIgnoreCase(service.getProtocol())) {
            throw new IOException("仅支持通过 Proxy 发送 HTTP 和 HTTPS 请求。");
        }
    }

    private static void closeQuietly(Socket socket) {
        if (socket == null) {
            return;
        }
        try {
            socket.close();
        } catch (IOException ignored) {
            // Best effort only.
        }
    }

    static final class Cancellation {
        private boolean cancelled;
        private Socket socket;

        synchronized void register(Socket activeSocket) throws RequestCancelledException {
            if (cancelled) {
                closeQuietly(activeSocket);
                throw new RequestCancelledException();
            }
            socket = activeSocket;
        }

        synchronized void unregister(Socket activeSocket) {
            if (socket == activeSocket) {
                socket = null;
            }
        }

        synchronized void cancel() {
            cancelled = true;
            closeQuietly(socket);
        }

        synchronized boolean isCancelled() {
            return cancelled;
        }

        synchronized void throwIfCancelled() throws RequestCancelledException {
            if (cancelled) {
                throw new RequestCancelledException();
            }
        }
    }

    static final class RequestCancelledException extends IOException {
        private RequestCancelledException() {
            super("Proxy 请求已取消。");
        }
    }

    private static final class HeaderInfo {
        private final long contentLength;
        private final boolean chunked;

        private HeaderInfo(long contentLength, boolean chunked) {
            this.contentLength = contentLength;
            this.chunked = chunked;
        }

        private static HeaderInfo parse(byte[] header) throws IOException {
            String text = new String(header, StandardCharsets.ISO_8859_1);
            String[] lines = text.split("\\r?\\n");
            long contentLength = -1;
            boolean chunked = false;
            for (int i = 1; i < lines.length; i++) {
                int colon = lines[i].indexOf(':');
                if (colon <= 0) {
                    continue;
                }
                String name = lines[i].substring(0, colon).trim();
                String value = lines[i].substring(colon + 1).trim();
                if ("transfer-encoding".equalsIgnoreCase(name)
                        && value.toLowerCase(Locale.ROOT).contains("chunked")) {
                    chunked = true;
                } else if ("content-length".equalsIgnoreCase(name)) {
                    try {
                        long parsed = Long.parseLong(value);
                        if (parsed < 0 || (contentLength >= 0 && contentLength != parsed)) {
                            throw new IOException("Proxy 返回了无效的 Content-Length。");
                        }
                        contentLength = parsed;
                    } catch (NumberFormatException ex) {
                        throw new IOException("Proxy 返回了无效的 Content-Length。", ex);
                    }
                }
            }
            return new HeaderInfo(contentLength, chunked);
        }
    }
}
