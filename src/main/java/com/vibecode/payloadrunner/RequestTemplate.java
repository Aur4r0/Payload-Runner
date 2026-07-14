package com.vibecode.payloadrunner;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

final class RequestTemplate {
    private final IHttpService service;
    private final String method;
    private final String host;
    private final String path;
    private final String bodyType;
    private final byte[] baselineResponse;
    private final List<PayloadInsertionPoint> insertionPoints;

    private RequestTemplate(IHttpService service, String method, String host, String path,
            String bodyType, byte[] baselineResponse,
            List<PayloadInsertionPoint> insertionPoints) {
        this.service = service;
        this.method = method;
        this.host = host;
        this.path = path;
        this.bodyType = bodyType;
        this.baselineResponse = baselineResponse;
        this.insertionPoints = insertionPoints;
    }

    static RequestTemplate fromMessage(IExtensionHelpers helpers, IHttpRequestResponse message) {
        if (message == null || message.getRequest() == null) {
            throw new IllegalArgumentException("请求报文不完整。");
        }

        byte[] request = Arrays.copyOf(message.getRequest(), message.getRequest().length);
        IHttpService service = message.getHttpService();
        IRequestInfo requestInfo = service == null
                ? helpers.analyzeRequest(request)
                : helpers.analyzeRequest(service, request);
        List<String> headers = new ArrayList<String>(requestInfo.getHeaders());
        if (service == null) {
            service = buildServiceFromRequest(helpers, requestInfo, headers);
        }
        if (service == null) {
            throw new IllegalArgumentException("请求缺少 HTTP 服务信息。");
        }
        String body = extractBody(helpers, request, requestInfo.getBodyOffset());

        List<PayloadInsertionPoint> insertionPoints = new ArrayList<PayloadInsertionPoint>();
        insertionPoints.addAll(QueryInsertionPoint.fromRequestLine(helpers, headers, body));

        BodyKind bodyKind = BodyKind.UNSUPPORTED;
        if (!body.trim().isEmpty()) {
            bodyKind = BodyKind.detect(headers, body);
            if (bodyKind == BodyKind.JSON) {
                insertionPoints.addAll(BodyInsertionPoint.fromJson(helpers, headers, body));
            } else if (bodyKind == BodyKind.FORM_URLENCODED) {
                insertionPoints.addAll(BodyInsertionPoint.fromFormUrlEncoded(helpers, headers, body));
            } else if (bodyKind == BodyKind.MULTIPART) {
                insertionPoints.addAll(BodyInsertionPoint.fromMultipart(helpers, headers, body));
            } else if (bodyKind == BodyKind.XML) {
                insertionPoints.addAll(BodyInsertionPoint.fromXml(helpers, headers, body));
            }
        }

        byte[] baselineResponse = message.getResponse() == null
                ? null
                : Arrays.copyOf(message.getResponse(), message.getResponse().length);
        return new RequestTemplate(service, safeMethod(requestInfo), safeHost(service, requestInfo),
                safePath(requestInfo), bodyLabel(bodyKind, body, insertionPoints), baselineResponse,
                insertionPoints);
    }

    IHttpService getService() {
        return service;
    }

    String getMethod() {
        return method;
    }

    String getHost() {
        return host;
    }

    String getPath() {
        return path;
    }

    List<PayloadInsertionPoint> getInsertionPoints() {
        return insertionPoints;
    }

    byte[] getBaselineResponse() {
        return baselineResponse;
    }

    @Override
    public String toString() {
        return method + " " + host + path + " [" + bodyType + ", "
                + insertionPoints.size() + " 个标记点]";
    }

    private static String safeMethod(IRequestInfo requestInfo) {
        String method = requestInfo.getMethod();
        return method == null || method.trim().isEmpty() ? "HTTP" : method;
    }

    private static String safeHost(IHttpService service, IRequestInfo requestInfo) {
        if (service.getHost() != null && !service.getHost().trim().isEmpty()) {
            return service.getHost();
        }
        URL url = requestInfo.getUrl();
        return url == null ? "" : url.getHost();
    }

    private static IHttpService buildServiceFromRequest(IExtensionHelpers helpers,
            IRequestInfo requestInfo, List<String> headers) {
        URL url = requestInfo.getUrl();
        if (url != null && url.getHost() != null && !url.getHost().isEmpty()) {
            String protocol = url.getProtocol() == null || url.getProtocol().isEmpty()
                    ? "http"
                    : url.getProtocol();
            int port = url.getPort() > 0 ? url.getPort() : url.getDefaultPort();
            if (port <= 0) {
                port = "https".equalsIgnoreCase(protocol) ? 443 : 80;
            }
            return helpers.buildHttpService(url.getHost(), port, protocol);
        }

        String host = hostHeader(headers);
        if (host.isEmpty()) {
            return null;
        }
        int port = 80;
        int colon = host.lastIndexOf(':');
        if (colon > 0 && colon < host.length() - 1) {
            try {
                port = Integer.parseInt(host.substring(colon + 1));
                host = host.substring(0, colon);
            } catch (NumberFormatException ex) {
                port = 80;
            }
        }
        return helpers.buildHttpService(host, port, "http");
    }

    private static String hostHeader(List<String> headers) {
        for (String header : headers) {
            int colon = header.indexOf(':');
            if (colon > 0 && "host".equalsIgnoreCase(header.substring(0, colon).trim())) {
                return header.substring(colon + 1).trim();
            }
        }
        return "";
    }

    private static String safePath(IRequestInfo requestInfo) {
        URL url = requestInfo.getUrl();
        if (url == null || url.getFile() == null || url.getFile().isEmpty()) {
            return "/";
        }
        return url.getFile();
    }

    private static String extractBody(IExtensionHelpers helpers, byte[] request, int bodyOffset) {
        if (bodyOffset < 0 || bodyOffset >= request.length) {
            return "";
        }
        return helpers.bytesToString(Arrays.copyOfRange(request, bodyOffset, request.length));
    }

    private static String bodyLabel(BodyKind bodyKind, String body,
            List<PayloadInsertionPoint> insertionPoints) {
        boolean hasUrlMarkers = false;
        for (PayloadInsertionPoint insertionPoint : insertionPoints) {
            if (insertionPoint.getName().startsWith("url:")) {
                hasUrlMarkers = true;
                break;
            }
        }
        if (body.trim().isEmpty()) {
            return hasUrlMarkers ? "URL 查询参数" : "无请求体";
        }
        if (bodyKind == BodyKind.UNSUPPORTED) {
            return hasUrlMarkers ? "URL 查询参数 + 暂不支持的请求体" : "暂不支持的请求体";
        }
        return hasUrlMarkers ? "URL 查询参数 + " + bodyKind.getLabel() : bodyKind.getLabel();
    }
}
