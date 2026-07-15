package com.vibecode.payloadrunner;

import java.security.cert.X509Certificate;

final class TransportConfig {
    static final String DEFAULT_PROXY_HOST = "127.0.0.1";
    static final int DEFAULT_PROXY_PORT = 8080;

    private final TrafficDestination destination;
    private final String proxyHost;
    private final int proxyPort;
    private final X509Certificate proxyCa;

    private TransportConfig(TrafficDestination destination, String proxyHost, int proxyPort,
            X509Certificate proxyCa) {
        this.destination = destination;
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.proxyCa = proxyCa;
    }

    static TransportConfig parse(TrafficDestination destination, String proxyHost,
            String proxyPort) {
        TrafficDestination selected = destination == null
                ? TrafficDestination.DIRECT
                : destination;
        String host = proxyHost == null ? "" : proxyHost.trim();
        int port;
        try {
            port = Integer.parseInt(proxyPort == null ? "" : proxyPort.trim());
        } catch (NumberFormatException ex) {
            if (selected == TrafficDestination.DIRECT) {
                port = DEFAULT_PROXY_PORT;
            } else {
                throw new IllegalArgumentException("Proxy 端口必须是 1 到 65535 之间的整数。");
            }
        }
        if ((port < 1 || port > 65535) && selected == TrafficDestination.DIRECT) {
            port = DEFAULT_PROXY_PORT;
        } else if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Proxy 端口必须是 1 到 65535 之间的整数。");
        }
        if (selected == TrafficDestination.BURP_PROXY && host.isEmpty()) {
            throw new IllegalArgumentException("Proxy 地址不能为空。");
        }
        if (host.isEmpty()) {
            host = DEFAULT_PROXY_HOST;
        }
        return new TransportConfig(selected, host, port, null);
    }

    TransportConfig withProxyCa(X509Certificate certificate) {
        return new TransportConfig(destination, proxyHost, proxyPort, certificate);
    }

    TrafficDestination getDestination() {
        return destination;
    }

    String getProxyHost() {
        return proxyHost;
    }

    int getProxyPort() {
        return proxyPort;
    }

    X509Certificate getProxyCa() {
        return proxyCa;
    }

    boolean usesProxy() {
        return destination == TrafficDestination.BURP_PROXY;
    }
}
