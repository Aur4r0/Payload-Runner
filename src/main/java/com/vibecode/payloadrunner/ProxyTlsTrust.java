package com.vibecode.payloadrunner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

final class ProxyTlsTrust {
    private static final int MAX_CERTIFICATE_BYTES = 1024 * 1024;

    private ProxyTlsTrust() {
    }

    static X509Certificate parse(byte[] certificateBytes) throws IOException {
        if (certificateBytes == null || certificateBytes.length == 0) {
            throw new IOException("证书文件为空。");
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(certificateBytes));
            certificate.checkValidity();
            if (certificate.getBasicConstraints() < 0) {
                throw new IOException("所选证书不是 CA 证书。");
            }
            return certificate;
        } catch (CertificateException ex) {
            throw new IOException("无法解析 X.509 CA 证书。", ex);
        }
    }

    static X509Certificate decode(String encoded) throws IOException {
        if (encoded == null || encoded.trim().isEmpty()) {
            return null;
        }
        try {
            return parse(Base64.getDecoder().decode(encoded.trim()));
        } catch (IllegalArgumentException ex) {
            throw new IOException("已保存的 Burp CA 数据无效。", ex);
        }
    }

    static X509Certificate fetchFromProxy(String proxyHost, int proxyPort) throws IOException {
        String host = proxyHost == null ? "" : proxyHost.trim();
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        if (host.isEmpty() || proxyPort < 1 || proxyPort > 65535) {
            throw new IOException("Proxy 地址或端口无效。");
        }
        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, proxyPort));
        HttpURLConnection connection = (HttpURLConnection) new URL("http://burp/cert")
                .openConnection(proxy);
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(30000);
        connection.setInstanceFollowRedirects(false);
        connection.setRequestProperty("Connection", "close");
        try {
            int status = connection.getResponseCode();
            if (status != 200) {
                throw new IOException("获取 Burp CA 失败（HTTP " + status + "）。");
            }
            InputStream input = connection.getInputStream();
            try {
                ByteArrayOutputStream output = new ByteArrayOutputStream(2048);
                byte[] buffer = new byte[4096];
                int count;
                while ((count = input.read(buffer)) >= 0) {
                    if (output.size() + count > MAX_CERTIFICATE_BYTES) {
                        throw new IOException("Burp CA 响应超过 1 MB。");
                    }
                    output.write(buffer, 0, count);
                }
                return parse(output.toByteArray());
            } finally {
                input.close();
            }
        } finally {
            connection.disconnect();
        }
    }

    static String encode(X509Certificate certificate) throws IOException {
        if (certificate == null) {
            return "";
        }
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (CertificateException ex) {
            throw new IOException("无法保存 Burp CA 证书。", ex);
        }
    }

    static String fingerprint(X509Certificate certificate) throws IOException {
        if (certificate == null) {
            return "";
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(certificate.getEncoded());
            StringBuilder result = new StringBuilder(digest.length * 3 - 1);
            for (int i = 0; i < digest.length; i++) {
                if (i > 0) {
                    result.append(':');
                }
                result.append(String.format("%02X", digest[i] & 0xff));
            }
            return result.toString();
        } catch (GeneralSecurityException ex) {
            throw new IOException("无法计算 Burp CA 指纹。", ex);
        }
    }

    static SSLSocketFactory socketFactory(X509Certificate proxyCa) throws IOException {
        if (proxyCa == null) {
            return (SSLSocketFactory) SSLSocketFactory.getDefault();
        }
        try {
            X509TrustManager defaultTrust = defaultTrustManager();
            X509TrustManager proxyTrust = trustManagerFor(proxyCa);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] {
                    new CombinedTrustManager(defaultTrust, proxyTrust)
            }, new SecureRandom());
            return context.getSocketFactory();
        } catch (GeneralSecurityException ex) {
            throw new IOException("无法初始化 Burp CA TLS 信任。", ex);
        }
    }

    private static X509TrustManager defaultTrustManager() throws GeneralSecurityException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        return x509TrustManager(factory.getTrustManagers());
    }

    private static X509TrustManager trustManagerFor(X509Certificate certificate)
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            keyStore.load(null, null);
        } catch (IOException ex) {
            throw new IOException("无法创建 Burp CA 信任库。", ex);
        }
        keyStore.setCertificateEntry("burp-proxy-ca", certificate);
        TrustManagerFactory factory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        factory.init(keyStore);
        return x509TrustManager(factory.getTrustManagers());
    }

    private static X509TrustManager x509TrustManager(TrustManager[] managers)
            throws GeneralSecurityException {
        for (TrustManager manager : managers) {
            if (manager instanceof X509TrustManager) {
                return (X509TrustManager) manager;
            }
        }
        throw new GeneralSecurityException("未找到 X.509 TrustManager。");
    }

    private static final class CombinedTrustManager implements X509TrustManager {
        private final X509TrustManager defaultTrust;
        private final X509TrustManager proxyTrust;

        private CombinedTrustManager(X509TrustManager defaultTrust,
                X509TrustManager proxyTrust) {
            this.defaultTrust = defaultTrust;
            this.proxyTrust = proxyTrust;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            defaultTrust.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            try {
                defaultTrust.checkServerTrusted(chain, authType);
            } catch (CertificateException defaultFailure) {
                try {
                    proxyTrust.checkServerTrusted(chain, authType);
                } catch (CertificateException proxyFailure) {
                    proxyFailure.addSuppressed(defaultFailure);
                    throw proxyFailure;
                }
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            List<X509Certificate> accepted = new ArrayList<X509Certificate>();
            for (X509Certificate certificate : defaultTrust.getAcceptedIssuers()) {
                accepted.add(certificate);
            }
            for (X509Certificate certificate : proxyTrust.getAcceptedIssuers()) {
                accepted.add(certificate);
            }
            return accepted.toArray(new X509Certificate[accepted.size()]);
        }
    }
}
