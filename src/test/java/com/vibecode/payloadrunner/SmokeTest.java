package com.vibecode.payloadrunner;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpService;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IContextMenuFactory;
import burp.ITab;
import burp.IProxyListener;

import java.awt.Component;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.JTable;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public final class SmokeTest {
    public static void main(String[] args) throws Exception {
        testYamlParser();
        testDefaultPayloadResource();
        testPayloadMarker();
        testAcceptHeaderNotMarked();
        testQueryInsertionPoints();
        testPathInsertionPoints();
        testHeaderInsertionPoints();
        testEncodingStrategies();
        testRateLimitDefaultsAndDelays();
        testTransportConfigDefaultsAndValidation();
        testProxyTlsTrustCertificate();
        testProxyTransportHttp();
        testProxyCancellationInterruptsBlockedRequest();
        testPauseAndStopCancelActiveProxyRequest();
        testProxyTransportHttpsConnectFailure();
        testProxyFailureDoesNotStopNextPayload();
        testRequestTemplateAcceptsUrlMarkerWithoutBody();
        testRequestTemplateBuildsMissingService();
        testFormInsertionPoints();
        testJsonInsertionPoints();
        testMultipartInsertionPoints();
        testRawBodyInsertionPoints();
        testXmlInsertionPoints();
        testResponseDiffAndHitRules();
        testPracticalHitRules();
        testProxyHighlightSupport();
        testProxyHitHighlightsHistory();
        testHitResultRowColor();
        testRepeaterCaptionAndSend();
        testRepeaterSendFailureDoesNotThrow();
        testRepeaterSkippedWhenHistoryBytesDropped();
        testSendPayloadCreatesHistoryWithoutAutoRepeater();
        testHistoryStoreNavigationAndLimit();
        testHistoryResponseTruncationAndScore();
        testEndpointKeyExcludesQuery();
        testResultRowSelectsHistoryRecord();
        testManualRepeaterButtons();
        testProfileSaveAndLoad();
        testRerunSelectedResults();
        testResultFiltersAndSummary();
        testUiSettingsPersistenceAndPayloadDedupe();
        testHitRuleTemplate();
        testCsvExport();
        testExtensionLoadBanner();
        testLocalizedUiLabels();
        testContextMenuCapturesSelectionSnapshot();
        testCategorySelectionDoesNotExpandOnParse();
        testQueuedRequestSelectionControlsRunSnapshot();
        testQueuedRequestDeleteSelected();
        testNewlyQueuedRequestsBecomeSelected();
        testResultSelectionUsesSortedViewRow();
        testRawRequestAcceptedIntoQueue();
        testMarkSelectionInsertsPair();
        testClearMarkersRemovesAllPoints();
        testRunBlocksUnmarkedRequest();
        System.out.println("Smoke tests passed");
    }

    private static void testYamlParser() {
        String yaml = ""
                + "xss:\n"
                + "  - \"<script>alert(1)</script>\"\n"
                + "ids: [\"1\", '2']\n"
                + "nested:\n"
                + "  payloads:\n"
                + "    - abc\n";

        Map<String, List<String>> payloads = YamlPayloadParser.parse(yaml);
        assertEquals(3, payloads.size(), "category count");
        assertEquals("<script>alert(1)</script>", payloads.get("xss").get(0), "xss payload");
        assertEquals("2", payloads.get("ids").get(1), "inline payload");
        assertEquals("abc", payloads.get("nested").get(0), "nested payloads key");
    }

    private static void testDefaultPayloadResource() {
        Map<String, List<String>> payloads = YamlPayloadParser.parse(DefaultPayloads.load());
        assertEquals(true, payloads.containsKey("XSS"), "default XSS category");
        assertEquals(true, payloads.containsKey("sql注入"), "default SQL category");
        assertEquals(true, payloads.get("XSS").size() > 0, "default XSS payloads");
    }

    private static void testPayloadMarker() {
        assertEquals(true, PayloadMarker.contains("§§"), "empty pair is a region");
        assertEquals(true, PayloadMarker.contains("pre§x§post"), "wrapped region detected");
        assertEquals(false, PayloadMarker.contains("a§b"), "lone delimiter is not a region");
        assertEquals(false, PayloadMarker.contains("*/*"), "star content is not a marker");
        assertEquals(false, PayloadMarker.contains(""), "empty string has no region");
        assertEquals(false, PayloadMarker.contains(null), "null has no region");

        assertEquals(0, PayloadMarker.countRegions("a§b"), "lone delimiter count");
        assertEquals(1, PayloadMarker.countRegions("pre§x§post"), "single region count");
        assertEquals(2, PayloadMarker.countRegions("a§1§b§2§c"), "two region count");

        assertEquals("preXpost", PayloadMarker.replaceRegions("pre§§post", "X"),
                "empty pair replaced");
        assertEquals("preXpost", PayloadMarker.replaceRegions("pre§abc§post", "X"),
                "wrapped region replaced whole");
        assertEquals("aXbXc", PayloadMarker.replaceRegions("a§1§b§2§c", "X"),
                "two regions replaced");
        assertEquals("a§b", PayloadMarker.replaceRegions("a§b", "X"),
                "lone delimiter preserved");
        assertEquals("*/*", PayloadMarker.replaceRegions("*/*", "X"),
                "star content untouched");

        assertEquals("aXb2c", PayloadMarker.replaceRegionAt("a§1§b§2§c", 0, "X"),
                "sniper first region");
        assertEquals("a1bXc", PayloadMarker.replaceRegionAt("a§1§b§2§c", 1, "X"),
                "sniper second region keeps first original");
        assertEquals("a1b2c", PayloadMarker.replaceRegionAt("a§1§b§2§c", 9, "X"),
                "sniper out-of-range strips all pairs");
        assertEquals("preXpost", PayloadMarker.replaceRegionAt("pre§§post", 0, "X"),
                "sniper empty pair");

        assertEquals("prepost", PayloadMarker.stripMarkers("pre§§post"),
                "empty pair markers stripped");
        assertEquals("preabcpost", PayloadMarker.stripMarkers("pre§abc§post"),
                "wrapped markers stripped, content kept");
        assertEquals("a1b2c", PayloadMarker.stripMarkers("a§1§b§2§c"),
                "all markers stripped");
        assertEquals("plain", PayloadMarker.stripMarkers("plain"),
                "no markers unchanged");
    }

    private static void testAcceptHeaderNotMarked() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "GET /search HTTP/1.1",
                "Host: example.test",
                "Accept: */*",
                "Accept-Encoding: text/*",
                "X-Custom: a*b");
        List<HeaderInsertionPoint> points = HeaderInsertionPoint.fromHeaders(helpers, headers, "");
        assertEquals(0, points.size(), "headers containing bare stars are not marked");
    }

    private static void testRawRequestAcceptedIntoQueue() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                panel.addRequests(new IHttpRequestResponse[] {
                        FakeMessage.rawRequestWithoutMarker()});
                @SuppressWarnings("unchecked")
                DefaultListModel<RequestTemplate> requestModel =
                        (DefaultListModel<RequestTemplate>) privateField(panel, "requestModel");
                assertEquals(1, requestModel.size(), "raw request accepted into queue");
                assertEquals(0, requestModel.getElementAt(0).getInsertionPoints().size(),
                        "raw request has no insertion points yet");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testMarkSelectionInsertsPair() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                panel.addRequests(new IHttpRequestResponse[] {
                        FakeMessage.rawRequestWithoutMarker()});
                @SuppressWarnings("unchecked")
                JList<RequestTemplate> requestList =
                        (JList<RequestTemplate>) privateField(panel, "requestList");
                @SuppressWarnings("unchecked")
                DefaultListModel<RequestTemplate> requestModel =
                        (DefaultListModel<RequestTemplate>) privateField(panel, "requestModel");
                FakeMessageEditor markerEditor =
                        (FakeMessageEditor) privateField(panel, "markerEditor");

                requestList.setSelectedIndex(0);
                String message = callbacks.helpers.bytesToString(markerEditor.getMessage());
                int start = message.indexOf("id=") + 3;
                int end = message.indexOf(' ', start);
                markerEditor.selectionBounds = new int[] {start, end};
                invokePrivate(panel, "markEditorSelection", new Class<?>[0]);

                String marked = callbacks.helpers.bytesToString(markerEditor.getMessage());
                assertContains(marked, "id=§1§", "selection wrapped in marker pair");
                assertEquals(1, requestModel.getElementAt(0).getInsertionPoints().size(),
                        "marked request has one insertion point");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testClearMarkersRemovesAllPoints() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                panel.addRequests(new IHttpRequestResponse[] {
                        FakeMessage.rawRequestWithoutMarker()});
                @SuppressWarnings("unchecked")
                JList<RequestTemplate> requestList =
                        (JList<RequestTemplate>) privateField(panel, "requestList");
                @SuppressWarnings("unchecked")
                DefaultListModel<RequestTemplate> requestModel =
                        (DefaultListModel<RequestTemplate>) privateField(panel, "requestModel");
                FakeMessageEditor markerEditor =
                        (FakeMessageEditor) privateField(panel, "markerEditor");

                requestList.setSelectedIndex(0);
                String message = callbacks.helpers.bytesToString(markerEditor.getMessage());
                int start = message.indexOf("id=") + 3;
                int end = message.indexOf(' ', start);
                markerEditor.selectionBounds = new int[] {start, end};
                invokePrivate(panel, "markEditorSelection", new Class<?>[0]);
                assertEquals(1, requestModel.getElementAt(0).getInsertionPoints().size(),
                        "request marked before clear");

                invokePrivate(panel, "clearEditorMarkers", new Class<?>[0]);
                String cleared = callbacks.helpers.bytesToString(markerEditor.getMessage());
                assertEquals(false, cleared.contains("§"), "all markers stripped from message");
                assertEquals(0, requestModel.getElementAt(0).getInsertionPoints().size(),
                        "cleared request has no insertion points");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testRunBlocksUnmarkedRequest() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                panel.addRequests(new IHttpRequestResponse[] {
                        FakeMessage.rawRequestWithoutMarker()});
                @SuppressWarnings("unchecked")
                JList<String> categories = (JList<String>) privateField(panel, "categoryList");
                categories.setSelectedIndex(indexOfCategory(categories, "XSS"));
                invokePrivate(panel, "runSelectedCategories", new Class<?>[0]);

                assertEquals(true, privateField(panel, "activeWorker") == null,
                        "unmarked request does not start a worker");
                JLabel statusLabel = (JLabel) privateField(panel, "statusLabel");
                assertContains(statusLabel.getText(), "尚未标记注入点",
                        "unmarked run shows blocking message");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testQueryInsertionPoints() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "POST /submit?name=pre§§post&encoded=%2A HTTP/1.1",
                "Host: example.test");
        List<QueryInsertionPoint> points = QueryInsertionPoint.fromRequestLine(helpers, headers, "");

        assertEquals(1, points.size(), "query marker count");
        assertEquals("url:name", points.get(0).getName(), "query parameter name");

        String firstRequest = helpers.bytesToString(points.get(0).buildRequest("A B"));
        assertContains(firstRequest, "POST /submit?name=preA+Bpost&encoded=%2A HTTP/1.1",
                "raw query replacement");
        assertEquals(false, firstRequest.contains("§"), "query request has no leftover markers");

        List<String> multiHeaders = Arrays.asList(
                "GET /x?a=§foo§&b=§bar§ HTTP/1.1",
                "Host: example.test",
                "X-Extra: §keep§");
        List<QueryInsertionPoint> multi = QueryInsertionPoint.fromRequestLine(
                helpers, multiHeaders, "body=§z§");
        assertEquals(2, multi.size(), "one point per query region");
        assertEquals("url:a", multi.get(0).getName(), "first query param");
        assertEquals("url:b", multi.get(1).getName(), "second query param");

        String hitA = helpers.bytesToString(multi.get(0).buildRequest("PAY", EncodingStrategy.RAW));
        assertContains(hitA, "GET /x?a=PAY&b=bar HTTP/1.1", "sniper hits a, b keeps original");
        assertContains(hitA, "X-Extra: keep", "inactive header marker stripped to original");
        assertContains(hitA, "body=z", "inactive body marker stripped to original");
        assertEquals(false, hitA.contains("§"), "sniper request has no leftover markers");

        String hitB = helpers.bytesToString(multi.get(1).buildRequest("PAY", EncodingStrategy.RAW));
        assertContains(hitB, "GET /x?a=foo&b=PAY HTTP/1.1", "sniper hits b, a keeps original");

        List<String> multiRegionHeaders = Arrays.asList(
                "GET /x?v=pre§one§mid§two§post HTTP/1.1",
                "Host: example.test");
        List<QueryInsertionPoint> multiRegion = QueryInsertionPoint.fromRequestLine(
                helpers, multiRegionHeaders, "");
        assertEquals(2, multiRegion.size(), "same value yields one point per region");
        assertEquals("url:v", multiRegion.get(0).getName(), "first region name");
        assertEquals("url:v@2", multiRegion.get(1).getName(), "second region name");
        String r1 = helpers.bytesToString(multiRegion.get(0).buildRequest("X", EncodingStrategy.RAW));
        assertContains(r1, "v=preXmidtwopost", "first region only");
        String r2 = helpers.bytesToString(multiRegion.get(1).buildRequest("X", EncodingStrategy.RAW));
        assertContains(r2, "v=preonemidXpost", "second region only");
    }

    private static void testPathInsertionPoints() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "GET /api/users/parameter§§/detail?id=§§ HTTP/1.1",
                "Host: example.test");
        List<PathInsertionPoint> points = PathInsertionPoint.fromRequestLine(helpers, headers, "");
        assertEquals(1, points.size(), "path marker count");
        assertEquals("url:path[3]", points.get(0).getName(), "path marker name");
        String request = helpers.bytesToString(points.get(0)
                .buildRequest("A/B", EncodingStrategy.URL_ENCODE));
        assertContains(request, "GET /api/users/parameterA%2FB/detail?id= HTTP/1.1",
                "path marker replacement strips inactive query markers");
        assertEquals(false, request.contains("§"), "path sniper request has no leftover markers");

        List<String> absoluteHeaders = Arrays.asList(
                "GET http://example.test/root/%2A/end?next=§§ HTTP/1.1",
                "Host: example.test");
        List<PathInsertionPoint> encodedPoints = PathInsertionPoint.fromRequestLine(
                helpers, absoluteHeaders, "");
        assertEquals(0, encodedPoints.size(),
                "percent-encoded star is no longer a marker");
    }

    private static void testHeaderInsertionPoints() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "POST /submit HTTP/1.1",
                "Host: example.test",
                "X-Test: pre§§post",
                "Cookie: session=§§",
                "Accept: */*",
                "Content-Length: §§");
        List<HeaderInsertionPoint> points = HeaderInsertionPoint.fromHeaders(
                helpers, headers, "body");
        assertEquals(2, points.size(), "header marker count");
        assertEquals("header:X-Test", points.get(0).getName(), "header marker name");
        String firstRequest = helpers.bytesToString(points.get(0)
                .buildRequest("payload", EncodingStrategy.RAW));
        assertContains(firstRequest, "X-Test: prepayloadpost", "header marker replacement");
        assertContains(firstRequest, "Cookie: session=", "other header marker stripped to original");
        assertEquals(false, firstRequest.contains("§"), "header sniper has no leftover markers");
        assertContains(firstRequest, "Accept: */*", "accept header left untouched");

        String secondRequest = helpers.bytesToString(points.get(1)
                .buildRequest("a/b", EncodingStrategy.URL_ENCODE));
        assertContains(secondRequest, "Cookie: session=a%2Fb",
                "header marker encoding strategy");
        assertContains(secondRequest, "X-Test: prepost", "inactive header keeps original text");

        List<String> wrappedHeaders = Arrays.asList(
                "POST /submit HTTP/1.1",
                "Host: example.test",
                "X-Test: §*/*§");
        List<HeaderInsertionPoint> wrappedPoints = HeaderInsertionPoint.fromHeaders(
                helpers, wrappedHeaders, "body");
        assertEquals(1, wrappedPoints.size(), "wrapped header marker count");
        String wrappedRequest = helpers.bytesToString(wrappedPoints.get(0)
                .buildRequest("payload", EncodingStrategy.RAW));
        assertContains(wrappedRequest, "X-Test: payload",
                "wrapped region replaced whole, inner stars literal");
    }

    private static void testEncodingStrategies() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "POST /submit?name=§§ HTTP/1.1",
                "Host: example.test");
        List<QueryInsertionPoint> queryPoints =
                QueryInsertionPoint.fromRequestLine(helpers, headers, "");

        String rawQuery = helpers.bytesToString(
                queryPoints.get(0).buildRequest("A B", EncodingStrategy.RAW));
        assertContains(rawQuery, "POST /submit?name=A B HTTP/1.1", "raw query strategy");

        String jsonEscapedQuery = helpers.bytesToString(
                queryPoints.get(0).buildRequest("\"x\"", EncodingStrategy.JSON_ESCAPE));
        assertContains(jsonEscapedQuery, "POST /submit?name=\\\"x\\\" HTTP/1.1",
                "json escape query strategy");

        List<String> jsonHeaders = Arrays.asList(
                "POST /api HTTP/1.1",
                "Host: example.test",
                "Content-Type: application/json");
        List<BodyInsertionPoint> jsonPoints = BodyInsertionPoint.fromJson(
                helpers, jsonHeaders, "{\"name\":\"§§\"}");

        String rawJson = helpers.bytesToString(
                jsonPoints.get(0).buildRequest("\"x\"", EncodingStrategy.RAW));
        assertContains(rawJson, "\"name\":\"\"x\"\"", "raw json strategy");

        String escapedJson = helpers.bytesToString(
                jsonPoints.get(0).buildRequest("\"x\"", EncodingStrategy.JSON_ESCAPE));
        assertContains(escapedJson, "\"name\":\"\\\"x\\\"\"", "json escape json strategy");
    }

    private static void testRateLimitDefaultsAndDelays() throws Exception {
        assertEquals(1000L, RateLimit.LOW.getDelayMillis(), "low rate delay");
        assertEquals(250L, RateLimit.MEDIUM.getDelayMillis(), "medium rate delay");
        assertEquals(0L, RateLimit.HIGH.getDelayMillis(), "high rate delay");

        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                @SuppressWarnings("unchecked")
                JComboBox<RateLimit> rateLimitCombo =
                        (JComboBox<RateLimit>) privateField(panel, "rateLimitCombo");
                assertEquals(RateLimit.MEDIUM, rateLimitCombo.getSelectedItem(),
                        "default rate limit");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testTransportConfigDefaultsAndValidation() {
        assertEquals(TrafficDestination.DIRECT, TrafficDestination.fromSetting(null),
                "default traffic destination");
        assertEquals(TrafficDestination.DIRECT, TrafficDestination.fromSetting("unknown"),
                "unknown traffic destination fallback");

        TransportConfig direct = TransportConfig.parse(TrafficDestination.DIRECT, "", "bad");
        assertEquals(false, direct.usesProxy(), "direct transport selection");
        assertEquals(TransportConfig.DEFAULT_PROXY_HOST, direct.getProxyHost(),
                "direct fallback proxy host");
        assertEquals(TransportConfig.DEFAULT_PROXY_PORT, direct.getProxyPort(),
                "direct fallback proxy port");

        TransportConfig proxy = TransportConfig.parse(TrafficDestination.BURP_PROXY,
                "localhost", "9090");
        assertEquals(true, proxy.usesProxy(), "proxy transport selection");
        assertEquals("localhost", proxy.getProxyHost(), "parsed proxy host");
        assertEquals(9090, proxy.getProxyPort(), "parsed proxy port");

        boolean rejected = false;
        try {
            TransportConfig.parse(TrafficDestination.BURP_PROXY, "localhost", "70000");
        } catch (IllegalArgumentException ex) {
            rejected = true;
        }
        assertEquals(true, rejected, "invalid proxy port rejected");
    }

    private static void testProxyTlsTrustCertificate() throws Exception {
        javax.net.ssl.TrustManagerFactory factory = javax.net.ssl.TrustManagerFactory.getInstance(
                javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        factory.init((java.security.KeyStore) null);
        java.security.cert.X509Certificate selected = null;
        for (javax.net.ssl.TrustManager manager : factory.getTrustManagers()) {
            if (!(manager instanceof javax.net.ssl.X509TrustManager)) {
                continue;
            }
            for (java.security.cert.X509Certificate certificate :
                    ((javax.net.ssl.X509TrustManager) manager).getAcceptedIssuers()) {
                try {
                    certificate.checkValidity();
                    if (certificate.getBasicConstraints() >= 0) {
                        selected = certificate;
                        break;
                    }
                } catch (java.security.cert.CertificateException ignored) {
                    // Try another default trusted CA.
                }
            }
        }
        if (selected == null) {
            throw new AssertionError("no current default trusted CA available for TLS trust test");
        }

        String encoded = ProxyTlsTrust.encode(selected);
        java.security.cert.X509Certificate decoded = ProxyTlsTrust.decode(encoded);
        assertEquals(ProxyTlsTrust.fingerprint(selected), ProxyTlsTrust.fingerprint(decoded),
                "proxy CA persistence fingerprint");
        assertEquals(true, ProxyTlsTrust.socketFactory(decoded) != null,
                "proxy CA socket factory");
        TransportConfig config = TransportConfig.parse(TrafficDestination.BURP_PROXY,
                "127.0.0.1", "8080").withProxyCa(decoded);
        assertEquals(true, config.getProxyCa() != null, "transport config carries proxy CA");

        final byte[] certificateBytes = selected.getEncoded();
        final ServerSocket server = new ServerSocket(0);
        server.setSoTimeout(5000);
        final byte[][] captured = new byte[1][];
        final Throwable[] serverError = new Throwable[1];
        Thread proxyThread = new Thread(() -> {
            try (Socket socket = server.accept()) {
                socket.setSoTimeout(5000);
                captured[0] = readHttpMessage(socket.getInputStream());
                OutputStream output = socket.getOutputStream();
                output.write(("HTTP/1.1 200 OK\r\nContent-Length: "
                        + certificateBytes.length + "\r\n\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1));
                output.write(certificateBytes);
                output.flush();
            } catch (Throwable ex) {
                serverError[0] = ex;
            }
        }, "fake-burp-ca-proxy");
        proxyThread.start();
        java.security.cert.X509Certificate fetched;
        try {
            fetched = ProxyTlsTrust.fetchFromProxy("127.0.0.1", server.getLocalPort());
        } finally {
            proxyThread.join(6000L);
            server.close();
        }
        assertThreadFinished(proxyThread, serverError[0], "Burp CA fake proxy");
        assertContains(new String(captured[0], StandardCharsets.ISO_8859_1),
                "GET http://burp/cert HTTP/1.1", "Burp CA proxy request target");
        assertEquals(ProxyTlsTrust.fingerprint(selected), ProxyTlsTrust.fingerprint(fetched),
                "Burp CA fetched from proxy");

        final FakeCallbacks callbacks = new FakeCallbacks();
        callbacks.settings.put("proxyCaCertificate", encoded);
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                assertEquals(true, privateField(panel, "proxyCaCertificate") != null,
                        "saved proxy CA loaded");
                assertContains(((JLabel) privateField(panel, "proxyCaStatusLabel")).getText(),
                        "已信任", "saved proxy CA status");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testProxyTransportHttp() throws Exception {
        final ServerSocket server = new ServerSocket(0);
        server.setSoTimeout(5000);
        final byte[][] captured = new byte[1][];
        final Throwable[] serverError = new Throwable[1];
        Thread proxyThread = new Thread(() -> {
            try (Socket socket = server.accept()) {
                socket.setSoTimeout(5000);
                captured[0] = readHttpMessage(socket.getInputStream());
                OutputStream output = socket.getOutputStream();
                output.write(("HTTP/1.1 200 OK\r\n"
                        + "Content-Length: 2\r\n"
                        + "\r\n"
                        + "OK").getBytes(StandardCharsets.ISO_8859_1));
                output.flush();
            } catch (Throwable ex) {
                serverError[0] = ex;
            }
        }, "fake-http-proxy");
        proxyThread.start();

        byte[] request = ("POST /submit?id=42 HTTP/1.1\r\n"
                + "Host: example.test:8081\r\n"
                + "X-Test: keep-me\r\n"
                + "Content-Length: 4\r\n"
                + "\r\n"
                + "BODY").getBytes(StandardCharsets.ISO_8859_1);
        byte[] response;
        try {
            response = ProxyTransport.send(
                    new FakeHttpService("example.test", 8081, "http"), request,
                    "127.0.0.1", server.getLocalPort());
        } finally {
            proxyThread.join(6000L);
            server.close();
        }
        assertThreadFinished(proxyThread, serverError[0], "HTTP fake proxy");
        String capturedText = new String(captured[0], StandardCharsets.ISO_8859_1);
        assertContains(capturedText,
                "POST http://example.test:8081/submit?id=42 HTTP/1.1",
                "HTTP proxy absolute request target");
        assertContains(capturedText, "X-Test: keep-me\r\n", "HTTP proxy header preserved");
        assertEquals(true, capturedText.endsWith("\r\n\r\nBODY"),
                "HTTP proxy body preserved");
        assertContains(new String(response, StandardCharsets.ISO_8859_1), "\r\n\r\nOK",
                "HTTP proxy response returned");
    }

    private static void testProxyCancellationInterruptsBlockedRequest() throws Exception {
        final ServerSocket server = new ServerSocket(0);
        final CountDownLatch accepted = new CountDownLatch(1);
        final Throwable[] serverError = new Throwable[1];
        Thread serverThread = new Thread(() -> {
            try (Socket socket = server.accept()) {
                accepted.countDown();
                while (socket.getInputStream().read() >= 0) {
                    // Wait until the client-side cancellation closes the socket.
                }
            } catch (Throwable ex) {
                serverError[0] = ex;
            }
        }, "fake-blocked-proxy");
        serverThread.start();

        ProxyTransport.Cancellation cancellation = new ProxyTransport.Cancellation();
        Throwable[] clientError = new Throwable[1];
        Thread clientThread = new Thread(() -> {
            try {
                ProxyTransport.send(new FakeHttpService("example.test", 80, "http"),
                        "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
                                .getBytes(StandardCharsets.ISO_8859_1),
                        "127.0.0.1", server.getLocalPort(), null, cancellation);
            } catch (Throwable ex) {
                clientError[0] = ex;
            }
        }, "proxy-cancellation-client");
        clientThread.start();
        assertEquals(true, accepted.await(2, TimeUnit.SECONDS), "blocked proxy accepted");
        cancellation.cancel();
        clientThread.join(2000L);
        serverThread.join(2000L);
        server.close();
        assertThreadFinished(clientThread, null, "cancelled proxy client");
        assertThreadFinished(serverThread, serverError[0], "blocked proxy server");
        assertEquals(true, clientError[0] instanceof ProxyTransport.RequestCancelledException,
                "cancelled proxy reports cancellation");
    }

    private static void testPauseAndStopCancelActiveProxyRequest() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                SwingWorker<Void, RunnerResult> worker = new SwingWorker<Void, RunnerResult>() {
                    @Override
                    protected Void doInBackground() {
                        return null;
                    }
                };
                setPrivateField(panel, "activeWorker", worker);
                ((JButton) privateField(panel, "pauseButton")).setEnabled(true);
                ((JButton) privateField(panel, "stopButton")).setEnabled(true);
                AtomicReference<ProxyTransport.Cancellation> active =
                        (AtomicReference<ProxyTransport.Cancellation>) privateField(
                                panel, "activeProxyRequest");
                ProxyTransport.Cancellation pauseCancellation =
                        new ProxyTransport.Cancellation();
                active.set(pauseCancellation);
                ((JButton) privateField(panel, "pauseButton")).doClick();
                assertEquals(true, pauseCancellation.isCancelled(),
                        "pause cancels active proxy request");

                ProxyTransport.Cancellation stopCancellation =
                        new ProxyTransport.Cancellation();
                active.set(stopCancellation);
                ((JButton) privateField(panel, "stopButton")).doClick();
                assertEquals(true, stopCancellation.isCancelled(),
                        "stop cancels active proxy request");
                assertEquals(true, worker.isCancelled(), "stop cancels worker");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testProxyTransportHttpsConnectFailure() throws Exception {
        final ServerSocket server = new ServerSocket(0);
        server.setSoTimeout(5000);
        final byte[][] captured = new byte[1][];
        final Throwable[] serverError = new Throwable[1];
        Thread proxyThread = new Thread(() -> {
            try (Socket socket = server.accept()) {
                socket.setSoTimeout(5000);
                captured[0] = readHttpMessage(socket.getInputStream());
                OutputStream output = socket.getOutputStream();
                output.write(("HTTP/1.1 502 Bad Gateway\r\n"
                        + "Content-Length: 0\r\n"
                        + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
                output.flush();
            } catch (Throwable ex) {
                serverError[0] = ex;
            }
        }, "fake-connect-proxy");
        proxyThread.start();

        boolean rejected = false;
        try {
            ProxyTransport.send(new FakeHttpService("secure.example", 8443, "https"),
                    "GET /private HTTP/1.1\r\nHost: secure.example:8443\r\n\r\n"
                            .getBytes(StandardCharsets.ISO_8859_1),
                    "127.0.0.1", server.getLocalPort());
        } catch (IOException ex) {
            rejected = ex.getMessage() != null && ex.getMessage().contains("CONNECT");
        } finally {
            proxyThread.join(6000L);
            server.close();
        }
        assertThreadFinished(proxyThread, serverError[0], "HTTPS fake proxy");
        assertEquals(true, rejected, "HTTPS CONNECT failure reported");
        String capturedText = new String(captured[0], StandardCharsets.ISO_8859_1);
        assertContains(capturedText, "CONNECT secure.example:8443 HTTP/1.1",
                "HTTPS CONNECT target");
        assertContains(capturedText, "Host: secure.example:8443",
                "HTTPS CONNECT Host header");
    }

    private static void testProxyFailureDoesNotStopNextPayload() throws Exception {
        final ServerSocket server = new ServerSocket(0);
        server.setSoTimeout(5000);
        final Throwable[] serverError = new Throwable[1];
        Thread proxyThread = new Thread(() -> {
            try {
                try (Socket first = server.accept()) {
                    first.setSoTimeout(5000);
                    readHttpMessage(first.getInputStream());
                }
                try (Socket second = server.accept()) {
                    second.setSoTimeout(5000);
                    readHttpMessage(second.getInputStream());
                    OutputStream output = second.getOutputStream();
                    output.write(("HTTP/1.1 200 OK\r\n"
                            + "Content-Length: 2\r\n"
                            + "\r\n"
                            + "OK").getBytes(StandardCharsets.ISO_8859_1));
                    output.flush();
                }
            } catch (Throwable ex) {
                serverError[0] = ex;
            }
        }, "fake-flaky-proxy");
        proxyThread.start();

        final RunnerResult[] results = new RunnerResult[2];
        final FakeCallbacks callbacks = new FakeCallbacks();
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                    RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                            FakeMessage.queryWithMarker());
                    PayloadInsertionPoint insertionPoint = template.getInsertionPoints().get(0);
                    TransportConfig config = TransportConfig.parse(
                            TrafficDestination.BURP_PROXY, "127.0.0.1",
                            Integer.toString(server.getLocalPort()));
                    Class<?>[] types = new Class<?>[] {RequestTemplate.class,
                            PayloadInsertionPoint.class, String.class, String.class,
                            EncodingStrategy.class, List.class, int.class, int.class,
                            TransportConfig.class, HitHighlightColor.class};
                    results[0] = (RunnerResult) invokePrivate(panel, "sendPayload", types,
                            template, insertionPoint, "ids", "41", EncodingStrategy.URL_ENCODE,
                            Collections.<HitRule>emptyList(), Integer.valueOf(1),
                            Integer.valueOf(1024), config, HitHighlightColor.RED);
                    results[1] = (RunnerResult) invokePrivate(panel, "sendPayload", types,
                            template, insertionPoint, "ids", "42", EncodingStrategy.URL_ENCODE,
                            Collections.<HitRule>emptyList(), Integer.valueOf(2),
                            Integer.valueOf(1024), config, HitHighlightColor.RED);
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            });
        } finally {
            proxyThread.join(6000L);
            server.close();
        }
        assertThreadFinished(proxyThread, serverError[0], "flaky fake proxy");
        assertEquals(true, results[0].getError() != null, "first proxy result marked error");
        assertEquals(200, results[1].getStatusCode(), "later proxy request still succeeds");
        assertEquals(0, callbacks.httpRequestCount, "proxy mode bypasses direct callback");
    }

    private static void testRequestTemplateAcceptsUrlMarkerWithoutBody() {
        FakeHelpers helpers = new FakeHelpers();
        RequestTemplate template = RequestTemplate.fromMessage(helpers, FakeMessage.queryWithMarker());

        assertEquals(1, template.getInsertionPoints().size(), "query-only template marker count");
        assertEquals("url:id", template.getInsertionPoints().get(0).getName(),
                "query-only insertion point");

        String request = helpers.bytesToString(template.getInsertionPoints().get(0).buildRequest("42"));
        assertContains(request, "POST /submit?id=42 HTTP/1.1", "query-only request replacement");
    }

    private static void testRequestTemplateBuildsMissingService() {
        FakeHelpers helpers = new FakeHelpers();
        RequestTemplate template = RequestTemplate.fromMessage(helpers,
                FakeMessage.queryWithMarkerWithoutService());

        assertEquals("example.test", template.getService().getHost(), "derived service host");
        assertEquals(1, template.getInsertionPoints().size(), "derived service marker count");
    }

    private static void testFormInsertionPoints() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "POST /submit HTTP/1.1",
                "Host: example.test",
                "Content-Type: application/x-www-form-urlencoded");
        List<BodyInsertionPoint> points = BodyInsertionPoint.fromFormUrlEncoded(
                helpers, headers, "a=1&name=pre§§post&encoded=%2A");

        assertEquals(1, points.size(), "form marker count");
        String firstRequest = helpers.bytesToString(points.get(0).buildRequest("A B"));
        assertContains(firstRequest, "name=preA+Bpost", "raw marker replacement");
    }

    private static void testJsonInsertionPoints() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "POST /api HTTP/1.1",
                "Host: example.test",
                "Content-Type: application/json");
        List<BodyInsertionPoint> points = BodyInsertionPoint.fromJson(
                helpers, headers, "{\"name\":\"pre§§post\",\"items\":[\"§§\"]}");

        assertEquals(2, points.size(), "json marker count");
        assertEquals("name", points.get(0).getName(), "json object key");
        assertEquals("items", points.get(1).getName(), "json array key");

        String request = helpers.bytesToString(points.get(0).buildRequest("PAY"));
        assertContains(request, "\"name\":\"prePAYpost\"", "json replacement");
        assertContains(request, "\"items\":[\"\"]", "inactive json marker stripped to original");
        assertEquals(false, request.contains("§"), "json sniper has no leftover markers");
    }

    private static void testMultipartInsertionPoints() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "POST /upload HTTP/1.1",
                "Host: example.test",
                "Content-Type: multipart/form-data; boundary=abc123");
        String body = ""
                + "--abc123\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"§§\"\r\n"
                + "\r\n"
                + "pre§§post\r\n"
                + "--abc123--\r\n";

        List<BodyInsertionPoint> points = BodyInsertionPoint.fromMultipart(helpers, headers, body);
        assertEquals(2, points.size(), "multipart marker count");
        assertEquals("multipart:filename:file", points.get(0).getName(),
                "multipart filename marker");
        assertEquals("multipart:file", points.get(1).getName(), "multipart parameter name");

        String request = helpers.bytesToString(points.get(1).buildRequest("A B"));
        assertContains(request, "preA+Bpost", "multipart replacement");
        assertContains(request, "filename=\"\"", "inactive multipart filename stripped");
        assertEquals(false, request.contains("§"), "multipart sniper has no leftover markers");
        String filenameRequest = helpers.bytesToString(points.get(0).buildRequest("upload.txt"));
        assertContains(filenameRequest, "filename=\"upload.txt\"", "multipart filename replacement");
        assertContains(filenameRequest, "prepost", "inactive multipart body stripped to original");

        String encodedFilenameBody = body.replace("filename=\"§§\"",
                "filename*=UTF-8''§§");
        List<BodyInsertionPoint> encodedFilenamePoints = BodyInsertionPoint.fromMultipart(
                helpers, headers, encodedFilenameBody);
        assertEquals("multipart:filename:file", encodedFilenamePoints.get(0).getName(),
                "multipart RFC filename marker");
        String encodedFilenameRequest = helpers.bytesToString(encodedFilenamePoints.get(0)
                .buildRequest("upload.txt", EncodingStrategy.RAW));
        assertContains(encodedFilenameRequest, "filename*=UTF-8''upload.txt",
                "multipart RFC filename replacement");
    }

    private static void testRawBodyInsertionPoints() {
        FakeHelpers helpers = new FakeHelpers();
        RequestTemplate template = RequestTemplate.fromMessage(helpers,
                FakeMessage.rawBodyWithMarker());
        // raw body "binary§§tail§§" now yields one insertion point per region (sniper).
        assertEquals(2, template.getInsertionPoints().size(), "raw body marker count");
        assertEquals("body:raw", template.getInsertionPoints().get(0).getName(),
                "raw body marker name");
        assertEquals("body:raw@2", template.getInsertionPoints().get(1).getName(),
                "raw body second region name");
        String request = helpers.bytesToString(template.getInsertionPoints().get(0)
                .buildRequest("PAY", EncodingStrategy.RAW));
        assertContains(request, "binaryPAYtail", "raw body first region only");
        assertEquals(false, request.contains("§"), "raw body sniper has no leftover markers");
        String second = helpers.bytesToString(template.getInsertionPoints().get(1)
                .buildRequest("PAY", EncodingStrategy.RAW));
        assertContains(second, "binarytailPAY", "raw body second region only");

        RequestTemplate jsonScalar = RequestTemplate.fromMessage(helpers,
                FakeMessage.jsonScalarWithMarker());
        assertEquals("body:raw", jsonScalar.getInsertionPoints().get(0).getName(),
                "unquoted JSON marker raw fallback");
        String jsonRequest = helpers.bytesToString(jsonScalar.getInsertionPoints().get(0)
                .buildRequest("42", EncodingStrategy.RAW));
        assertContains(jsonRequest, "{\"id\":42}", "unquoted JSON marker replacement");
    }

    private static void testXmlInsertionPoints() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "POST /xml HTTP/1.1",
                "Host: example.test",
                "Content-Type: application/xml");
        String body = "<root id=\"§§\"><name>pre§§post</name></root>";

        List<BodyInsertionPoint> points = BodyInsertionPoint.fromXml(helpers, headers, body);
        assertEquals(2, points.size(), "xml marker count");
        assertEquals("xml:root@id", points.get(0).getName(), "xml attribute marker");
        assertEquals("xml:name", points.get(1).getName(), "xml text marker");

        String attributeRequest = helpers.bytesToString(points.get(0).buildRequest("A B"));
        assertContains(attributeRequest, "id=\"A+B\"", "xml attribute replacement");
        assertContains(attributeRequest, "<name>prepost</name>",
                "inactive xml text marker stripped to original");
        assertEquals(false, attributeRequest.contains("§"), "xml sniper has no leftover markers");
        String textRequest = helpers.bytesToString(points.get(1).buildRequest("A B"));
        assertContains(textRequest, "<name>preA+Bpost</name>", "xml text replacement");
        assertContains(textRequest, "id=\"\"", "inactive xml attribute stripped to original");
    }

    private static void testResponseDiffAndHitRules() {
        FakeHelpers helpers = new FakeHelpers();
        byte[] baseline = helpers.stringToBytes("HTTP/1.1 200 OK\r\n\r\nhello");
        byte[] response = helpers.stringToBytes("HTTP/1.1 500 Server Error\r\n\r\nhello root extra");

        ResponseDiff diff = ResponseDiff.between(helpers, baseline, response, 500);
        assertEquals(true, diff.isAvailable(), "diff availability");
        assertEquals(true, diff.getLengthDelta() > 0, "diff length delta");

        List<HitRule> rules = HitRule.parse("root",
                "regex:extra\nstatus:5xx\nlength>20\ndiff>0\nsim<100\ntime>=4500");
        String hits = HitRule.evaluate(rules,
                new HitRule.MatchInput(helpers.bytesToString(response), 500, response.length,
                        diff, 5000L));
        assertContains(hits, "keyword:root", "keyword hit rule");
        assertContains(hits, "regex:extra", "regex hit rule");
        assertContains(hits, "status:5xx", "status hit rule");
        assertContains(hits, "diff>0", "diff hit rule");
        assertContains(hits, "time>=4500", "elapsed time hit rule");
    }

    private static void testPracticalHitRules() {
        List<HitRule> rules = HitRule.parse("", HitRuleTemplate.practicalRules());
        assertEquals(true, rules.size() >= 20, "practical hit rule count");

        String response = "HTTP/1.1 500 Internal Server Error\r\n"
                + "X-Payload-Runner: true\r\n\r\n"
                + "SQL syntax error root:x:0:0:root:/root:/bin/bash 7777777";
        String hits = HitRule.evaluate(rules,
                new HitRule.MatchInput(response, 500, response.length(),
                        ResponseDiff.unavailable(), 5000L));
        assertContains(hits, "status:5xx", "practical status rule");
        assertContains(hits, "time>=4500", "practical delay rule");
        assertContains(hits, "keyword:root:x:0:0", "practical file read rule");
        assertContains(hits, "keyword:7777777", "practical SSTI rule");
        assertContains(hits, "X-Payload-Runner", "practical CRLF rule");
    }

    private static void testProxyHighlightSupport() {
        FakeCallbacks callbacks = new FakeCallbacks();
        ProxyHighlightSupport support = new ProxyHighlightSupport(callbacks);
        byte[] original = ("POST /submit HTTP/1.1\r\n"
                + "Host: example.test\r\n"
                + "Content-Length: 4\r\n"
                + "\r\n"
                + "BODY").getBytes(StandardCharsets.ISO_8859_1);
        IHttpService service = new FakeHttpService();
        String traceId = support.begin(service, original);
        FakeMessage message = new FakeMessage(original, service, null);
        support.processProxyMessage(true, new FakeInterceptedProxyMessage(message));
        assertContains(new String(message.getRequest(), StandardCharsets.ISO_8859_1),
                "POST /submit HTTP/1.1", "proxy request line preserved");
        assertContains(new String(message.getRequest(), StandardCharsets.ISO_8859_1),
                "BODY", "proxy request body preserved");
        assertEquals(true, message.isEdited(), "proxy request marked Edited");
        assertContains(new String(message.getRequest(), StandardCharsets.ISO_8859_1),
                "X-Payload-Runner-Edited: 1", "proxy Edited header added");
        support.complete(traceId, true, HitHighlightColor.ORANGE);
        assertEquals("orange", message.getHighlight(), "proxy history hit highlighted");

        String noHitTrace = support.begin(service, original);
        FakeMessage noHitMessage = new FakeMessage(original, service, null);
        support.processProxyMessage(true, new FakeInterceptedProxyMessage(noHitMessage));
        support.complete(noHitTrace, false, HitHighlightColor.RED);
        assertEquals(true, noHitMessage.isEdited(), "non-hit proxy request marked Edited");
        assertContains(new String(noHitMessage.getRequest(), StandardCharsets.ISO_8859_1),
                "X-Payload-Runner-Edited: 1", "non-hit Edited header added");
        assertEquals(null, noHitMessage.getHighlight(), "non-hit proxy request not highlighted");
    }

    private static void testProxyHitHighlightsHistory() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        final ProxyHighlightSupport support = new ProxyHighlightSupport(callbacks);
        final ServerSocket server = new ServerSocket(0);
        server.setSoTimeout(5000);
        final FakeMessage[] proxyMessage = new FakeMessage[1];
        final Throwable[] serverError = new Throwable[1];
        Thread proxyThread = new Thread(() -> {
            try (Socket socket = server.accept()) {
                socket.setSoTimeout(5000);
                byte[] request = readHttpMessage(socket.getInputStream());
                proxyMessage[0] = new FakeMessage(request,
                        new FakeHttpService("example.test", 80, "http"), null);
                support.processProxyMessage(true,
                        new FakeInterceptedProxyMessage(proxyMessage[0]));
                byte[] body = "SQL syntax error".getBytes(StandardCharsets.ISO_8859_1);
                OutputStream output = socket.getOutputStream();
                output.write(("HTTP/1.1 500 Internal Server Error\r\nContent-Length: "
                        + body.length + "\r\n\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1));
                output.write(body);
                output.flush();
            } catch (Throwable ex) {
                serverError[0] = ex;
            }
        }, "fake-highlight-proxy");
        proxyThread.start();

        final RunnerResult[] result = new RunnerResult[1];
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks,
                            callbacks.helpers, support);
                    RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                            FakeMessage.queryWithMarker());
                    PayloadInsertionPoint insertionPoint = template.getInsertionPoints().get(0);
                    TransportConfig config = TransportConfig.parse(
                            TrafficDestination.BURP_PROXY, "127.0.0.1",
                            Integer.toString(server.getLocalPort()));
                    result[0] = (RunnerResult) invokePrivate(panel, "sendPayload",
                            new Class<?>[] {RequestTemplate.class, PayloadInsertionPoint.class,
                                    String.class, String.class, EncodingStrategy.class, List.class,
                                    int.class, int.class, TransportConfig.class,
                                    HitHighlightColor.class},
                            template, insertionPoint, "sql注入", "'", EncodingStrategy.RAW,
                            HitRule.parse("", "keyword:SQL syntax"), Integer.valueOf(1),
                            Integer.valueOf(1024), config, HitHighlightColor.ORANGE);
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            });
        } finally {
            proxyThread.join(6000L);
            server.close();
        }
        assertThreadFinished(proxyThread, serverError[0], "highlight fake proxy");
        assertContains(result[0].getHitMatch(), "keyword:SQL syntax",
                "proxy response hit detected");
        assertEquals(true, proxyMessage[0].isEdited(),
                "proxy history message marked Edited");
        assertContains(new String(proxyMessage[0].getRequest(), StandardCharsets.ISO_8859_1),
                "X-Payload-Runner-Edited: 1", "proxy history Edited header added");
        assertEquals("orange", proxyMessage[0].getHighlight(),
                "proxy history message highlighted after hit");
        assertContains(new String(proxyMessage[0].getRequest(), StandardCharsets.ISO_8859_1),
                "POST http://example.test/submit?id='",
                "proxy history request matched by canonical target");
    }

    private static void testHitResultRowColor() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                ResultTableModel model = (ResultTableModel) privateField(panel, "resultModel");
                JTable table = (JTable) privateField(panel, "resultTable");
                RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                        FakeMessage.queryWithMarker());
                RunnerResult hit = new RunnerResult(template, "url:id", "XSS", "payload",
                        callbacks.helpers.stringToBytes("GET / HTTP/1.1\r\n\r\n"),
                        callbacks.helpers.stringToBytes("HTTP/1.1 200 OK\r\n\r\nhit"),
                        200, 21, 1L, "keyword:hit", "", false, "", null);
                model.addResult(hit);
                Component component = table.prepareRenderer(table.getCellRenderer(0, 0), 0, 0);
                assertEquals(HitHighlightColor.RED.getTableColor(), component.getBackground(),
                        "hit result row background");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testRepeaterCaptionAndSend() {
        FakeCallbacks callbacks = new FakeCallbacks();
        byte[] request = callbacks.helpers.stringToBytes("POST /api HTTP/1.1\r\n\r\n");

        RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                FakeMessage.queryWithMarker());
        HistoryRecord record = new HistoryRecord(1L, template, "url:id", "sqli", "42",
                request, null, 200, 0, 3L, System.currentTimeMillis());

        RepeaterSupport.SendResult result = RepeaterSupport.sendRecord(callbacks, record, 3);
        assertEquals(true, result.isSent(), "repeater send success");
        assertEquals(1, callbacks.repeaterSendCount, "repeater send count");
        assertEquals("example.test", callbacks.repeaterHost, "repeater host");
        assertEquals(80, callbacks.repeaterPort, "repeater port");
        assertEquals(false, callbacks.repeaterUseHttps, "repeater https");
        assertEquals("3", callbacks.repeaterCaption,
                "blank prefix manual repeater caption");

        RepeaterSupport.SendResult customResult = RepeaterSupport.sendRecord(callbacks, record,
                4, "查询");
        assertEquals(true, customResult.isSent(), "custom prefix repeater send success");
        assertEquals("查询4", callbacks.repeaterCaption, "custom prefix repeater caption");

        String longCaption = RepeaterSupport.buildCaption("POST", "/path",
                "sqli", "username", 12,
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz");
        assertEquals(true, longCaption.length() <= 80, "truncated repeater caption length");
        assertContains(longCaption, "12", "truncated repeater caption index");

        String blankCaption = RepeaterSupport.buildCaption("POST", "/path",
                "sqli", "username", 12, "   ");
        assertEquals("12", blankCaption, "blank prefix build caption");
    }

    private static void testRepeaterSendFailureDoesNotThrow() {
        FakeCallbacks callbacks = new FakeCallbacks();
        callbacks.failRepeaterSend = true;
        RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                FakeMessage.queryWithMarker());
        HistoryRecord record = new HistoryRecord(1L, template, "url:id", "ids", "42",
                callbacks.helpers.stringToBytes("GET / HTTP/1.1\r\n\r\n"), null, 200, 0,
                1L, System.currentTimeMillis());
        RepeaterSupport.SendResult result = RepeaterSupport.sendRecord(callbacks, record, 1);
        assertEquals(false, result.isSent(), "repeater send failure");
        assertEquals(true, result.getError().contains("boom"), "repeater send error");
        assertEquals(true, callbacks.lastError.contains("发送到 Repeater 失败"),
                "repeater error logged");
    }

    private static void testRepeaterSkippedWhenHistoryBytesDropped() {
        FakeCallbacks callbacks = new FakeCallbacks();
        RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                FakeMessage.queryWithMarker());
        HistoryRecord record = new HistoryRecord(1L, template, "url:id", "ids", "42",
                callbacks.helpers.stringToBytes("GET / HTTP/1.1\r\n\r\n"), null, 200, 0,
                1L, System.currentTimeMillis());
        record.discardMessages();

        RepeaterSupport.SendResult result = RepeaterSupport.sendRecord(callbacks, record, 1);
        assertEquals(false, result.isSent(), "dropped history repeater send failure");
        assertEquals(0, callbacks.repeaterSendCount, "dropped history repeater send count");
        assertContains(result.getError(), "根据历史上限释放",
                "dropped history repeater error");
        assertContains(callbacks.lastError, "发送到 Repeater 失败",
                "dropped history repeater error logged");
    }

    private static void testSendPayloadCreatesHistoryWithoutAutoRepeater() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                        FakeMessage.queryWithMarker());
                PayloadInsertionPoint insertionPoint = template.getInsertionPoints().get(0);
                callbacks.nextResponse = callbacks.helpers.stringToBytes(
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
                TransportConfig transportConfig = TransportConfig.parse(
                        TrafficDestination.DIRECT, "", "not-a-port");

                invokePrivate(panel, "sendPayload",
                        new Class<?>[] {RequestTemplate.class, PayloadInsertionPoint.class,
                                String.class, String.class, EncodingStrategy.class, List.class,
                                int.class, int.class, TransportConfig.class,
                                HitHighlightColor.class},
                        template, insertionPoint, "ids", "42", EncodingStrategy.URL_ENCODE,
                        Collections.<HitRule>emptyList(), Integer.valueOf(3), Integer.valueOf(1024),
                        transportConfig, HitHighlightColor.RED);

                RunnerResult result = (RunnerResult) invokePrivate(panel, "sendPayload",
                        new Class<?>[] {RequestTemplate.class, PayloadInsertionPoint.class,
                                String.class, String.class, EncodingStrategy.class, List.class,
                                int.class, int.class, TransportConfig.class,
                                HitHighlightColor.class},
                        template, insertionPoint, "ids", "43", EncodingStrategy.URL_ENCODE,
                        HitRule.parse("", "keyword:OK"), Integer.valueOf(4), Integer.valueOf(1024),
                        transportConfig, HitHighlightColor.RED);
                assertEquals(0, callbacks.repeaterSendCount, "sendPayload does not auto repeater");
                assertEquals(2, callbacks.httpRequestCount, "direct transport callback count");
                assertEquals("red", callbacks.lastHttpResult.getHighlight(),
                        "direct hit result highlighted");
                assertContains(result.getHistoryRecord().getEndpointKey(),
                        "POST http://example.test:80/submit", "history endpoint key");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testHistoryStoreNavigationAndLimit() {
        FakeCallbacks callbacks = new FakeCallbacks();
        RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                FakeMessage.queryWithMarker());
        HistoryStore store = new HistoryStore(2);
        HistoryRecord first = new HistoryRecord(store.nextId(), template, "url:id", "ids", "1",
                callbacks.helpers.stringToBytes("GET /1 HTTP/1.1\r\n\r\n"), null, 200, 0,
                1L, System.currentTimeMillis());
        HistoryRecord second = new HistoryRecord(store.nextId(), template, "url:id", "ids", "2",
                callbacks.helpers.stringToBytes("GET /2 HTTP/1.1\r\n\r\n"), null, 200, 0,
                1L, System.currentTimeMillis());
        HistoryRecord third = new HistoryRecord(store.nextId(), template, "url:id", "ids", "3",
                callbacks.helpers.stringToBytes("GET /3 HTTP/1.1\r\n\r\n"), null, 200, 0,
                1L, System.currentTimeMillis());

        store.append(first);
        store.append(second);
        assertEquals(2, store.size(first.getEndpointKey()), "history size before trim");
        assertEquals(true, store.next(first.getEndpointKey()) == second, "history next");
        HistoryStore.AppendResult appendResult = store.append(third);
        assertEquals(1, appendResult.getDroppedCount(), "history trim dropped oldest");
        assertEquals(2, store.size(first.getEndpointKey()), "history size after trim");
        assertEquals(-1, store.indexOf(first), "oldest history removed");
        assertEquals(null, first.getRequestBytes(), "trimmed history request bytes discarded");
        assertEquals(true, second.getRequestBytes() != null, "kept history request bytes retained");
        assertEquals(true, store.currentRecord(first.getEndpointKey()) == second,
                "current record adjusted after trim");
    }

    private static void testEndpointKeyExcludesQuery() {
        FakeCallbacks callbacks = new FakeCallbacks();
        RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                FakeMessage.queryWithMarker());
        HistoryRecord record = new HistoryRecord(1L, template, "url:id", "ids", "42",
                callbacks.helpers.stringToBytes("POST /submit?id=42 HTTP/1.1\r\n\r\n"),
                null, 200, 0, 1L, System.currentTimeMillis());

        assertEquals("POST http://example.test:80/submit", record.getEndpointKey(),
                "endpoint key strips query");
    }

    private static void testHistoryResponseTruncationAndScore() throws Exception {
        FakeCallbacks callbacks = new FakeCallbacks();
        RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                FakeMessage.queryWithMarker());
        byte[] response = callbacks.helpers.stringToBytes("HTTP/1.1 500 Error\r\n\r\n"
                + "abcdefghijklmnopqrstuvwxyz");
        HistoryRecord record = new HistoryRecord(1L, template, "url:id", "ids", "1",
                callbacks.helpers.stringToBytes("GET / HTTP/1.1\r\n\r\n"), response,
                500, response.length, 2500L, System.currentTimeMillis(), 16);

        assertEquals(true, record.isResponseTruncated(), "response truncation flag");
        assertEquals(16, record.getResponseBytes().length, "truncated response length");

        final FakeCallbacks panelCallbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel =
                        new PayloadRunnerPanel(panelCallbacks, panelCallbacks.helpers);
                byte[] baseline = panelCallbacks.helpers.stringToBytes(
                        "HTTP/1.1 200 OK\r\n\r\nabc");
                ResponseDiff diff = ResponseDiff.between(panelCallbacks.helpers, baseline,
                        response, 500);
                Integer score = (Integer) invokePrivate(panel, "scoreResult",
                        new Class<?>[] {int.class, long.class, String.class,
                                ResponseDiff.class, String.class},
                        Integer.valueOf(500), Long.valueOf(2500L), "keyword:root", diff, null);
                assertEquals(true, score.intValue() >= 80, "high signal score");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testResultRowSelectsHistoryRecord() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                        FakeMessage.queryWithMarker());
                ResultTableModel resultModel = (ResultTableModel) privateField(panel, "resultModel");
                JTable resultTable = (JTable) privateField(panel, "resultTable");
                HistoryStore historyStore = (HistoryStore) privateField(panel, "historyStore");

                HistoryRecord first = new HistoryRecord(historyStore.nextId(), template, "url:id",
                        "ids", "1", callbacks.helpers.stringToBytes("GET /1 HTTP/1.1\r\n\r\n"),
                        null, 200, 0, 1L, System.currentTimeMillis());
                HistoryRecord second = new HistoryRecord(historyStore.nextId(), template, "url:id",
                        "ids", "2", callbacks.helpers.stringToBytes("GET /2 HTTP/1.1\r\n\r\n"),
                        null, 200, 0, 1L, System.currentTimeMillis());
                resultModel.addResult(new RunnerResult(template, first, "", "", null));
                resultModel.addResult(new RunnerResult(template, second, "", "", null));
                historyStore.append(first);
                historyStore.append(second);

                resultTable.setRowSelectionInterval(1, 1);

                HistoryRecord selected =
                        (HistoryRecord) privateField(panel, "currentHistoryRecord");
                assertEquals(true, selected == second, "selected row updates current history");
                assertEquals(true, historyStore.currentRecord(second.getEndpointKey()) == second,
                        "selected row updates endpoint current index");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testManualRepeaterButtons() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                        FakeMessage.queryWithMarker());
                ResultTableModel resultModel = (ResultTableModel) privateField(panel, "resultModel");
                JTable resultTable = (JTable) privateField(panel, "resultTable");
                HistoryStore historyStore = (HistoryStore) privateField(panel, "historyStore");
                JButton sendCurrent =
                        (JButton) privateField(panel, "sendCurrentRepeaterButton");
                JButton sendSelected =
                        (JButton) privateField(panel, "sendSelectedRepeaterButton");
                JButton sendInteresting =
                        (JButton) privateField(panel, "sendInterestingRepeaterButton");
                JTextField repeaterCaptionPrefixField =
                        (JTextField) privateField(panel, "repeaterCaptionPrefixField");

                HistoryRecord first = new HistoryRecord(historyStore.nextId(), template, "url:id",
                        "ids", "1", callbacks.helpers.stringToBytes("GET /1 HTTP/1.1\r\n\r\n"),
                        null, 200, 0, 1L, System.currentTimeMillis());
                HistoryRecord second = new HistoryRecord(historyStore.nextId(), template, "url:id",
                        "xss", "<x>", callbacks.helpers.stringToBytes("GET /2 HTTP/1.1\r\n\r\n"),
                        null, 200, 0, 1L, System.currentTimeMillis());
                resultModel.addResult(new RunnerResult(template, first, "", "", null));
                resultModel.addResult(new RunnerResult(template, second, "", "", null));
                historyStore.append(first);
                historyStore.append(second);

                assertEquals(0, callbacks.repeaterSendCount, "no automatic repeater send");

                invokePrivate(panel, "showHistoryRecord",
                        new Class<?>[] {HistoryRecord.class}, first);
                sendCurrent.doClick();
                assertEquals(1, callbacks.repeaterSendCount, "current repeater send count");
                assertEquals("1", callbacks.repeaterCaption, "current blank prefix caption");
                assertEquals(true, first.isSentToRepeater(), "current record sent flag");

                repeaterCaptionPrefixField.setText("查询");
                resultTable.setRowSelectionInterval(0, 1);
                sendSelected.doClick();
                assertEquals(3, callbacks.repeaterSendCount, "selected repeater send count");
                assertEquals("查询2", callbacks.repeaterCaption, "selected custom prefix caption");
                assertEquals(true, second.isSentToRepeater(), "selected record sent flag");

                second.setInteresting(true);
                sendInteresting.doClick();
                assertEquals(4, callbacks.repeaterSendCount, "interesting repeater send count");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testProfileSaveAndLoad() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                panel.addRequests(new IHttpRequestResponse[] {FakeMessage.queryWithMarker()});
                @SuppressWarnings("unchecked")
                JList<String> categories = (JList<String>) privateField(panel, "categoryList");
                @SuppressWarnings("unchecked")
                JComboBox<EncodingStrategy> encodingCombo =
                        (JComboBox<EncodingStrategy>) privateField(panel, "encodingCombo");
                @SuppressWarnings("unchecked")
                JComboBox<RateLimit> rateLimitCombo =
                        (JComboBox<RateLimit>) privateField(panel, "rateLimitCombo");
                JTextField maxHistoryField =
                        (JTextField) privateField(panel, "maxHistoryField");
                JTextField maxResponseKbField =
                        (JTextField) privateField(panel, "maxResponseKbField");
                JTextField keywordField =
                        (JTextField) privateField(panel, "keywordField");
                JTextArea rulesArea = (JTextArea) privateField(panel, "rulesArea");
                JTextField repeaterCaptionPrefixField =
                        (JTextField) privateField(panel, "repeaterCaptionPrefixField");
                JCheckBox followLatestCheckBox =
                        (JCheckBox) privateField(panel, "followLatestCheckBox");
                @SuppressWarnings("unchecked")
                JComboBox<TrafficDestination> trafficDestinationCombo =
                        (JComboBox<TrafficDestination>) privateField(panel,
                                "trafficDestinationCombo");
                JTextField proxyHostField = (JTextField) privateField(panel, "proxyHostField");
                JTextField proxyPortField = (JTextField) privateField(panel, "proxyPortField");
                @SuppressWarnings("unchecked")
                JComboBox<HitHighlightColor> hitHighlightColorCombo =
                        (JComboBox<HitHighlightColor>) privateField(panel,
                                "hitHighlightColorCombo");

                categories.setSelectedIndex(indexOfCategory(categories, "XSS"));
                encodingCombo.setSelectedItem(EncodingStrategy.RAW);
                rateLimitCombo.setSelectedItem(RateLimit.LOW);
                maxHistoryField.setText("321");
                maxResponseKbField.setText("64");
                keywordField.setText("root");
                rulesArea.setText("status:5xx");
                repeaterCaptionPrefixField.setText("profile");
                followLatestCheckBox.setSelected(false);
                trafficDestinationCombo.setSelectedItem(TrafficDestination.BURP_PROXY);
                proxyHostField.setText("127.0.0.2");
                proxyPortField.setText("9090");
                hitHighlightColorCombo.setSelectedItem(HitHighlightColor.ORANGE);
                invokePrivate(panel, "saveCurrentProfile", new Class<?>[] {});

                PayloadRunnerPanel loaded = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                invokePrivate(loaded, "loadSelectedProfile", new Class<?>[] {});
                @SuppressWarnings("unchecked")
                JComboBox<EncodingStrategy> loadedEncoding =
                        (JComboBox<EncodingStrategy>) privateField(loaded, "encodingCombo");
                @SuppressWarnings("unchecked")
                JComboBox<RateLimit> loadedRate =
                        (JComboBox<RateLimit>) privateField(loaded, "rateLimitCombo");
                @SuppressWarnings("unchecked")
                JList<String> loadedCategories =
                        (JList<String>) privateField(loaded, "categoryList");

                assertEquals(EncodingStrategy.RAW, loadedEncoding.getSelectedItem(),
                        "profile encoding");
                assertEquals(RateLimit.LOW, loadedRate.getSelectedItem(), "profile rate");
                assertEquals("321", ((JTextField) privateField(loaded, "maxHistoryField")).getText(),
                        "profile max history");
                assertEquals("64", ((JTextField) privateField(loaded, "maxResponseKbField")).getText(),
                        "profile max response");
                assertEquals("root", ((JTextField) privateField(loaded, "keywordField")).getText(),
                        "profile keywords");
                assertEquals("status:5xx", ((JTextArea) privateField(loaded, "rulesArea")).getText(),
                        "profile rules");
                assertEquals("profile", ((JTextField) privateField(loaded,
                        "repeaterCaptionPrefixField")).getText(), "profile repeater prefix");
                assertEquals(false, ((JCheckBox) privateField(loaded,
                        "followLatestCheckBox")).isSelected(), "profile follow latest");
                assertEquals(TrafficDestination.BURP_PROXY,
                        ((JComboBox<?>) privateField(loaded,
                                "trafficDestinationCombo")).getSelectedItem(),
                        "profile traffic destination");
                assertEquals("127.0.0.2",
                        ((JTextField) privateField(loaded, "proxyHostField")).getText(),
                        "profile proxy host");
                assertEquals("9090",
                        ((JTextField) privateField(loaded, "proxyPortField")).getText(),
                        "profile proxy port");
                assertEquals(HitHighlightColor.ORANGE,
                        ((JComboBox<?>) privateField(loaded,
                                "hitHighlightColorCombo")).getSelectedItem(),
                        "profile hit highlight color");
                assertEquals(Collections.singletonList("XSS"),
                        loadedCategories.getSelectedValuesList(), "profile categories");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testRerunSelectedResults() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        final PayloadRunnerPanel[] panelHolder = new PayloadRunnerPanel[1];
        final ResultTableModel[] resultModelHolder = new ResultTableModel[1];
        final RunnerResult[] originalHolder = new RunnerResult[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                        FakeMessage.queryWithMarker());
                RunnerResult original = new RunnerResult(template, "url:id", "ids", "42",
                        callbacks.helpers.stringToBytes("GET /old HTTP/1.1\r\n\r\n"),
                        callbacks.helpers.stringToBytes("HTTP/1.1 200 OK\r\n\r\nold"),
                        200, 19, 1L, "", "", false, "", null);
                ResultTableModel resultModel =
                        (ResultTableModel) privateField(panel, "resultModel");
                resultModel.addResult(original);
                callbacks.nextResponse = callbacks.helpers.stringToBytes(
                        "HTTP/1.1 200 OK\r\n\r\nrerun");
                invokePrivate(panel, "rerunResults",
                        new Class<?>[] {List.class, String.class},
                        Collections.singletonList(original), "selected result(s)");
                panelHolder[0] = panel;
                resultModelHolder[0] = resultModel;
                originalHolder[0] = original;
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });

        @SuppressWarnings("unchecked")
        SwingWorker<Void, RunnerResult> worker =
                (SwingWorker<Void, RunnerResult>) privateField(panelHolder[0], "activeWorker");
        worker.get();
        for (int i = 0; i < 20 && resultModelHolder[0].getRowCount() < 2; i++) {
            Thread.sleep(25L);
            SwingUtilities.invokeAndWait(() -> {});
        }

        assertEquals(1, callbacks.httpRequestCount, "rerun http request count");
        assertEquals(2, resultModelHolder[0].getRowCount(), "rerun appends result");
        RunnerResult rerun = resultModelHolder[0].getResult(1);
        assertEquals("42", rerun.getPayload(), "rerun payload");
        assertEquals(originalHolder[0].getParameterName(), rerun.getParameterName(),
                "rerun parameter");
    }

    private static void testResultFiltersAndSummary() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                        FakeMessage.queryWithMarker());
                ResultTableModel resultModel = (ResultTableModel) privateField(panel, "resultModel");
                JTable resultTable = (JTable) privateField(panel, "resultTable");
                JCheckBox filterHitsCheckBox =
                        (JCheckBox) privateField(panel, "filterHitsCheckBox");
                JCheckBox filterInterestingCheckBox =
                        (JCheckBox) privateField(panel, "filterInterestingCheckBox");
                @SuppressWarnings("unchecked")
                JComboBox<String> statusFilterCombo =
                        (JComboBox<String>) privateField(panel, "statusFilterCombo");
                JTextField resultFilterField =
                        (JTextField) privateField(panel, "resultFilterField");
                JLabel resultSummaryLabel =
                        (JLabel) privateField(panel, "resultSummaryLabel");
                @SuppressWarnings("unchecked")
                JComboBox<String> exportScopeCombo =
                        (JComboBox<String>) privateField(panel, "exportScopeCombo");

                RunnerResult plain = new RunnerResult(template, "url:id", "ids", "aaa",
                        callbacks.helpers.stringToBytes("GET /plain HTTP/1.1\r\n\r\n"),
                        callbacks.helpers.stringToBytes("HTTP/1.1 200 OK\r\n\r\nplain"),
                        200, 19, 1L, "", "", false, "", null);
                RunnerResult hit = new RunnerResult(template, "url:id", "xss", "bbb",
                        callbacks.helpers.stringToBytes("GET /hit HTTP/1.1\r\n\r\n"),
                        callbacks.helpers.stringToBytes("HTTP/1.1 500 Error\r\n\r\nhit"),
                        500, 22, 2L, "keyword:hit", "diff>0", false, "", null);
                plain.getHistoryRecord().setInteresting(true);
                resultModel.addResult(plain);
                resultModel.addResult(hit);

                invokePrivate(panel, "applyResultFilters", new Class<?>[] {});
                assertEquals(2, resultTable.getRowCount(), "unfiltered result row count");
                assertContains(resultSummaryLabel.getText(), "显示 2 / 共 2", "summary visible count");

                filterHitsCheckBox.setSelected(true);
                invokePrivate(panel, "applyResultFilters", new Class<?>[] {});
                assertEquals(1, resultTable.getRowCount(), "hit filter row count");

                filterHitsCheckBox.setSelected(false);
                filterInterestingCheckBox.setSelected(true);
                invokePrivate(panel, "applyResultFilters", new Class<?>[] {});
                assertEquals(1, resultTable.getRowCount(), "interesting filter row count");

                filterInterestingCheckBox.setSelected(false);
                statusFilterCombo.setSelectedItem("5xx");
                invokePrivate(panel, "applyResultFilters", new Class<?>[] {});
                assertEquals(1, resultTable.getRowCount(), "status filter row count");

                statusFilterCombo.setSelectedItem("全部状态");
                resultFilterField.setText("xss");
                invokePrivate(panel, "applyResultFilters", new Class<?>[] {});
                assertEquals(1, resultTable.getRowCount(), "text filter row count");

                resultFilterField.setText("");
                invokePrivate(panel, "applyResultFilters", new Class<?>[] {});
                resultTable.setRowSelectionInterval(1, 1);
                exportScopeCombo.setSelectedItem("选中结果");
                @SuppressWarnings("unchecked")
                List<RunnerResult> selectedResults = (List<RunnerResult>) invokePrivate(panel,
                        "resultsForExportScope", new Class<?>[] {});
                assertEquals(1, selectedResults.size(), "selected export scope count");
                assertEquals(true, selectedResults.get(0) == hit, "selected export result");

                exportScopeCombo.setSelectedItem("重点结果");
                @SuppressWarnings("unchecked")
                List<RunnerResult> interestingResults = (List<RunnerResult>) invokePrivate(panel,
                        "resultsForExportScope", new Class<?>[] {});
                assertEquals(1, interestingResults.size(), "interesting export scope count");
                assertEquals(true, interestingResults.get(0) == plain, "interesting export result");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testUiSettingsPersistenceAndPayloadDedupe() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                @SuppressWarnings("unchecked")
                JComboBox<EncodingStrategy> encodingCombo =
                        (JComboBox<EncodingStrategy>) privateField(panel, "encodingCombo");
                @SuppressWarnings("unchecked")
                JComboBox<RateLimit> rateLimitCombo =
                        (JComboBox<RateLimit>) privateField(panel, "rateLimitCombo");
                JTextField maxHistoryField =
                        (JTextField) privateField(panel, "maxHistoryField");
                JTextField maxResponseKbField =
                        (JTextField) privateField(panel, "maxResponseKbField");
                JTextField repeaterCaptionPrefixField =
                        (JTextField) privateField(panel, "repeaterCaptionPrefixField");
                JCheckBox followLatestCheckBox =
                        (JCheckBox) privateField(panel, "followLatestCheckBox");
                @SuppressWarnings("unchecked")
                JComboBox<TrafficDestination> trafficDestinationCombo =
                        (JComboBox<TrafficDestination>) privateField(panel,
                                "trafficDestinationCombo");
                JTextField proxyHostField = (JTextField) privateField(panel, "proxyHostField");
                JTextField proxyPortField = (JTextField) privateField(panel, "proxyPortField");
                @SuppressWarnings("unchecked")
                JComboBox<HitHighlightColor> hitHighlightColorCombo =
                        (JComboBox<HitHighlightColor>) privateField(panel,
                                "hitHighlightColorCombo");

                encodingCombo.setSelectedItem(EncodingStrategy.RAW);
                rateLimitCombo.setSelectedItem(RateLimit.LOW);
                maxHistoryField.setText("123");
                maxResponseKbField.setText("456");
                repeaterCaptionPrefixField.setText("查询");
                followLatestCheckBox.setSelected(false);
                trafficDestinationCombo.setSelectedItem(TrafficDestination.BURP_PROXY);
                proxyHostField.setText("localhost");
                proxyPortField.setText("8181");
                hitHighlightColorCombo.setSelectedItem(HitHighlightColor.GREEN);
                invokePrivate(panel, "saveUiSettings", new Class<?>[] {});

                @SuppressWarnings("unchecked")
                List<String> unique = (List<String>) invokePrivate(panel, "uniquePayloads",
                        new Class<?>[] {List.class}, Arrays.asList("a", "b", "a"));
                assertEquals(Arrays.asList("a", "b"), unique, "payload dedupe order");

                PayloadRunnerPanel loaded = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                @SuppressWarnings("unchecked")
                JComboBox<EncodingStrategy> loadedEncoding =
                        (JComboBox<EncodingStrategy>) privateField(loaded, "encodingCombo");
                @SuppressWarnings("unchecked")
                JComboBox<RateLimit> loadedRate =
                        (JComboBox<RateLimit>) privateField(loaded, "rateLimitCombo");
                JTextField loadedMaxHistory =
                        (JTextField) privateField(loaded, "maxHistoryField");
                JTextField loadedMaxResponseKb =
                        (JTextField) privateField(loaded, "maxResponseKbField");
                JTextField loadedPrefix =
                        (JTextField) privateField(loaded, "repeaterCaptionPrefixField");
                JCheckBox loadedFollowLatest =
                        (JCheckBox) privateField(loaded, "followLatestCheckBox");

                assertEquals(EncodingStrategy.RAW, loadedEncoding.getSelectedItem(),
                        "loaded encoding setting");
                assertEquals(RateLimit.LOW, loadedRate.getSelectedItem(),
                        "loaded rate setting");
                assertEquals("123", loadedMaxHistory.getText(), "loaded max history");
                assertEquals("456", loadedMaxResponseKb.getText(), "loaded max response");
                assertEquals("查询", loadedPrefix.getText(), "loaded repeater prefix");
                assertEquals(false, loadedFollowLatest.isSelected(), "loaded follow latest");
                assertEquals(TrafficDestination.BURP_PROXY,
                        ((JComboBox<?>) privateField(loaded,
                                "trafficDestinationCombo")).getSelectedItem(),
                        "loaded traffic destination");
                assertEquals("localhost",
                        ((JTextField) privateField(loaded, "proxyHostField")).getText(),
                        "loaded proxy host");
                assertEquals("8181",
                        ((JTextField) privateField(loaded, "proxyPortField")).getText(),
                        "loaded proxy port");
                assertEquals(true,
                        ((JTextField) privateField(loaded, "proxyHostField")).isEnabled(),
                        "proxy fields enabled for proxy mode");
                assertEquals(HitHighlightColor.GREEN,
                        ((JComboBox<?>) privateField(loaded,
                                "hitHighlightColorCombo")).getSelectedItem(),
                        "loaded hit highlight color");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testHitRuleTemplate() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                @SuppressWarnings("unchecked")
                JComboBox<HitRuleTemplate> hitRuleTemplateCombo =
                        (JComboBox<HitRuleTemplate>) privateField(panel, "hitRuleTemplateCombo");
                JTextArea rulesArea = (JTextArea) privateField(panel, "rulesArea");
                hitRuleTemplateCombo.setSelectedItem(HitRuleTemplate.SQLI);
                invokePrivate(panel, "applyRuleTemplate", new Class<?>[] {});

                assertContains(rulesArea.getText(), "SQL 注入特征",
                        "sqli template text");
                assertEquals(true, HitRule.parse("", rulesArea.getText()).size() > 0,
                        "sqli template parses");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testCsvExport() throws Exception {
        FakeHelpers helpers = new FakeHelpers();
        RequestTemplate template = RequestTemplate.fromMessage(helpers, FakeMessage.queryWithMarker());
        RunnerResult result = new RunnerResult(template, "url:id", "ids", "42",
                helpers.stringToBytes("GET / HTTP/1.1\r\n\r\n"),
                helpers.stringToBytes("HTTP/1.1 200 OK\r\n\r\nok"),
                200, 19, 7L, "keyword:ok", "len +1, sim 90%", true, "", null);
        File file = File.createTempFile("payload-runner", ".csv");
        CsvExporter.export(file, Collections.singletonList(result));
        String csv = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        assertContains(csv, "keyword:ok", "csv hit export");
        assertContains(csv, "score", "csv score header");
        assertContains(csv, "len +1, sim 90%", "csv diff export");
        file.delete();
    }

    private static void testExtensionLoadBanner() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        final BurpExtender extender = new BurpExtender();
        SwingUtilities.invokeAndWait(() -> extender.registerExtenderCallbacks(callbacks));

        assertContains(callbacks.outputText(), "Payload Runner 加载成功。",
                "extension load success banner");
        assertContains(callbacks.outputText(), "https://github.com/Aur4r0/Payload-Runner",
                "extension load github link");
        assertEquals(true, callbacks.proxyListener != null,
                "extension registers official proxy listener");
    }

    private static void testLocalizedUiLabels() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                assertEquals("运行选中项",
                        ((JButton) privateField(panel, "runButton")).getText(),
                        "localized run button");
                assertEquals("自动跟随最新结果",
                        ((JCheckBox) privateField(panel, "followLatestCheckBox")).getText(),
                        "localized follow latest");
                assertEquals("全部状态",
                        ((JComboBox<?>) privateField(panel, "statusFilterCombo")).getItemAt(0),
                        "localized status filter");
                JComboBox<?> destination =
                        (JComboBox<?>) privateField(panel, "trafficDestinationCombo");
                assertEquals(TrafficDestination.DIRECT, destination.getSelectedItem(),
                        "default traffic destination");
                assertEquals("直接发送", destination.getItemAt(0).toString(),
                        "localized direct destination");
                assertEquals("经 Burp Proxy 发送", destination.getItemAt(1).toString(),
                        "localized proxy destination");
                assertEquals(false,
                        ((JTextField) privateField(panel, "proxyHostField")).isEnabled(),
                        "proxy host disabled in direct mode");
                assertEquals("127.0.0.1",
                        ((JTextField) privateField(panel, "proxyHostField")).getText(),
                        "default proxy host");
                assertEquals(false,
                        ((JTextField) privateField(panel, "proxyPortField")).isEnabled(),
                        "proxy port disabled in direct mode");
                assertEquals("8080",
                        ((JTextField) privateField(panel, "proxyPortField")).getText(),
                        "default proxy port");
                assertEquals("导入 Burp CA...",
                        ((JButton) privateField(panel, "importProxyCaButton")).getText(),
                        "localized import proxy CA button");
                assertEquals("从 Proxy 获取 CA...",
                        ((JButton) privateField(panel, "fetchProxyCaButton")).getText(),
                        "localized fetch proxy CA button");
                assertEquals(false,
                        ((JButton) privateField(panel, "importProxyCaButton")).isEnabled(),
                        "import proxy CA disabled in direct mode");
                assertEquals(HitHighlightColor.RED,
                        ((JComboBox<?>) privateField(panel,
                                "hitHighlightColorCombo")).getSelectedItem(),
                        "default hit highlight color");
                assertContains(((JTextArea) privateField(panel, "rulesArea")).getText(),
                        "time>=4500", "default practical delay rule");
                assertEquals("接口", ((JTable) privateField(panel, "resultTable"))
                        .getColumnName(1), "localized result column");
                JTabbedPane tabs = (JTabbedPane) privateField(panel, "mainTabs");
                assertEquals("请求标记", tabs.getTitleAt(0), "localized marker tab");
                assertEquals("任务配置", tabs.getTitleAt(1), "localized runner tab");
                assertEquals("运行结果", tabs.getTitleAt(2), "localized results tab");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testContextMenuCapturesSelectionSnapshot() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        final BurpExtender extender = new BurpExtender();
        SwingUtilities.invokeAndWait(() -> {
            extender.registerExtenderCallbacks(callbacks);
            List<JMenuItem> items = extender.createMenuItems(new FlakyInvocation(
                    new IHttpRequestResponse[] {FakeMessage.formWithMarker()}));

            assertEquals(1, items.size(), "menu item count");
            items.get(0).doClick();
        });

        assertEquals(1, callbacks.helpers.analyzeRequestCalls, "captured selected message");
    }

    private static void testCategorySelectionDoesNotExpandOnParse() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                @SuppressWarnings("unchecked")
                JList<String> categories = (JList<String>) privateField(panel, "categoryList");

                assertEquals(0, categories.getSelectedValuesList().size(),
                        "initial category selection");

                int xssIndex = -1;
                for (int i = 0; i < categories.getModel().getSize(); i++) {
                    if ("XSS".equals(categories.getModel().getElementAt(i))) {
                        xssIndex = i;
                    }
                }
                assertEquals(true, xssIndex >= 0, "xss category exists");
                categories.setSelectedIndex(xssIndex);
                invokePrivate(panel, "parseYamlIntoCategories",
                        new Class<?>[] {boolean.class}, Boolean.FALSE);

                List<String> selected = categories.getSelectedValuesList();
                assertEquals(1, selected.size(), "single category selection after parse");
                assertEquals("XSS", selected.get(0), "selected category after parse");

                categories.clearSelection();
                invokePrivate(panel, "parseYamlIntoCategories",
                        new Class<?>[] {boolean.class}, Boolean.FALSE);
                assertEquals(0, categories.getSelectedValuesList().size(),
                        "empty category selection after parse");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testQueuedRequestSelectionControlsRunSnapshot() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                panel.addRequests(new IHttpRequestResponse[] {
                        FakeMessage.formWithMarker(), FakeMessage.queryWithMarker()
                });

                @SuppressWarnings("unchecked")
                JList<RequestTemplate> requests =
                        (JList<RequestTemplate>) privateField(panel, "requestList");
                @SuppressWarnings("unchecked")
                DefaultListModel<RequestTemplate> requestModel =
                        (DefaultListModel<RequestTemplate>) privateField(panel, "requestModel");

                requests.clearSelection();
                @SuppressWarnings("unchecked")
                List<RequestTemplate> allRequests = (List<RequestTemplate>) invokePrivate(panel,
                        "snapshotRunRequests", new Class<?>[0]);
                assertEquals(2, allRequests.size(), "all queued requests without selection");

                requests.setSelectedIndex(1);
                @SuppressWarnings("unchecked")
                List<RequestTemplate> selectedRequests = (List<RequestTemplate>) invokePrivate(panel,
                        "snapshotRunRequests", new Class<?>[0]);
                assertEquals(1, selectedRequests.size(), "selected queued request count");
                assertEquals(true, selectedRequests.get(0) == requestModel.getElementAt(1),
                        "selected queued request identity");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testQueuedRequestDeleteSelected() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                panel.addRequests(new IHttpRequestResponse[] {
                        FakeMessage.formWithMarker(), FakeMessage.queryWithMarker()
                });

                @SuppressWarnings("unchecked")
                JList<RequestTemplate> requests =
                        (JList<RequestTemplate>) privateField(panel, "requestList");
                @SuppressWarnings("unchecked")
                DefaultListModel<RequestTemplate> requestModel =
                        (DefaultListModel<RequestTemplate>) privateField(panel, "requestModel");

                RequestTemplate second = requestModel.getElementAt(1);
                requests.setSelectedIndex(0);
                invokePrivate(panel, "deleteSelectedRequests", new Class<?>[0]);

                assertEquals(1, requestModel.size(), "queued request count after delete");
                assertEquals(true, requestModel.getElementAt(0) == second,
                        "only selected queued request deleted");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testNewlyQueuedRequestsBecomeSelected() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                panel.addRequests(new IHttpRequestResponse[] {FakeMessage.formWithMarker()});

                @SuppressWarnings("unchecked")
                JList<RequestTemplate> requests =
                        (JList<RequestTemplate>) privateField(panel, "requestList");
                @SuppressWarnings("unchecked")
                DefaultListModel<RequestTemplate> requestModel =
                        (DefaultListModel<RequestTemplate>) privateField(panel, "requestModel");

                assertEquals(1, requests.getSelectedValuesList().size(),
                        "first queued request selected");
                assertEquals(true, requests.getSelectedValue() == requestModel.getElementAt(0),
                        "first queued request selection identity");

                panel.addRequests(new IHttpRequestResponse[] {FakeMessage.queryWithMarker()});
                assertEquals(1, requests.getSelectedValuesList().size(),
                        "new queued request replaces stale selection");
                assertEquals(true, requests.getSelectedValue() == requestModel.getElementAt(1),
                        "new queued request selection identity");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static void testResultSelectionUsesSortedViewRow() throws Exception {
        final FakeCallbacks callbacks = new FakeCallbacks();
        SwingUtilities.invokeAndWait(() -> {
            try {
                PayloadRunnerPanel panel = new PayloadRunnerPanel(callbacks, callbacks.helpers);
                RequestTemplate template = RequestTemplate.fromMessage(callbacks.helpers,
                        FakeMessage.queryWithMarker());
                RunnerResult first = new RunnerResult(template, "url:id", "ids", "zzz",
                        callbacks.helpers.stringToBytes("GET /first HTTP/1.1\r\n\r\n"),
                        callbacks.helpers.stringToBytes("HTTP/1.1 200 OK\r\n\r\nfirst"),
                        200, 19, 1L, "", "", false, "", null);
                RunnerResult second = new RunnerResult(template, "url:id", "ids", "aaa",
                        callbacks.helpers.stringToBytes("GET /second HTTP/1.1\r\n\r\n"),
                        callbacks.helpers.stringToBytes("HTTP/1.1 200 OK\r\n\r\nsecond"),
                        200, 20, 2L, "", "", false, "", null);

                ResultTableModel resultModel = (ResultTableModel) privateField(panel, "resultModel");
                JTable resultTable = (JTable) privateField(panel, "resultTable");
                resultModel.addResult(first);
                resultModel.addResult(second);
                resultTable.getRowSorter().toggleSortOrder(7);

                assertEquals(1, resultTable.convertRowIndexToModel(0),
                        "sorted first view row maps to second model row");
                resultTable.setRowSelectionInterval(0, 0);

                HistoryRecord selected =
                        (HistoryRecord) privateField(panel, "currentHistoryRecord");
                assertEquals(true, selected == second.getHistoryRecord(),
                        "sorted result selection history identity");
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static int indexOfCategory(JList<String> categories, String name) {
        for (int i = 0; i < categories.getModel().getSize(); i++) {
            if (name.equals(categories.getModel().getElementAt(i))) {
                return i;
            }
        }
        throw new AssertionError("missing category " + name);
    }

    private static byte[] readHttpMessage(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int state = 0;
        while (state < 4) {
            int value = input.read();
            if (value < 0) {
                throw new IOException("unexpected EOF while reading test request header");
            }
            output.write(value);
            if (state == 0) {
                state = value == '\r' ? 1 : 0;
            } else if (state == 1) {
                state = value == '\n' ? 2 : value == '\r' ? 1 : 0;
            } else if (state == 2) {
                state = value == '\r' ? 3 : 0;
            } else if (state == 3) {
                state = value == '\n' ? 4 : 0;
            }
        }
        String header = new String(output.toByteArray(), StandardCharsets.ISO_8859_1);
        int contentLength = 0;
        for (String line : header.split("\\r\\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && "content-length".equalsIgnoreCase(
                    line.substring(0, colon).trim())) {
                contentLength = Integer.parseInt(line.substring(colon + 1).trim());
            }
        }
        byte[] buffer = new byte[1024];
        int remaining = contentLength;
        while (remaining > 0) {
            int count = input.read(buffer, 0, Math.min(buffer.length, remaining));
            if (count < 0) {
                throw new IOException("unexpected EOF while reading test request body");
            }
            output.write(buffer, 0, count);
            remaining -= count;
        }
        return output.toByteArray();
    }

    private static void assertThreadFinished(Thread thread, Throwable error, String label) {
        if (thread.isAlive()) {
            throw new AssertionError(label + " thread did not finish");
        }
        if (error != null) {
            throw new AssertionError(label + " failed", error);
        }
    }

    private static Object privateField(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }

    private static void setPrivateField(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static Object invokePrivate(Object target, String name, Class<?>[] types,
            Object... args) throws Exception {
        Method method = target.getClass().getDeclaredMethod(name, types);
        method.setAccessible(true);
        return method.invoke(target, args);
    }

    private static void assertEquals(Object expected, Object actual, String label) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError(label + ": expected <" + expected + "> but got <"
                    + actual + ">");
        }
    }

    private static void assertContains(String text, String expectedPart, String label) {
        if (!text.contains(expectedPart)) {
            throw new AssertionError(label + ": expected text to contain <" + expectedPart
                    + "> but got <" + text + ">");
        }
    }

    private static final class FakeHelpers implements IExtensionHelpers {
        private int analyzeRequestCalls;

        @Override
        public IRequestInfo analyzeRequest(byte[] request) {
            return analyzeRequest(null, request);
        }

        @Override
        public IRequestInfo analyzeRequest(IHttpService httpService, byte[] request) {
            analyzeRequestCalls++;
            String message = bytesToString(request);
            int headerEnd = message.indexOf("\r\n\r\n");
            if (headerEnd < 0) {
                throw new IllegalArgumentException("No header separator.");
            }
            String[] headerLines = message.substring(0, headerEnd).split("\r\n");
            List<String> headers = new ArrayList<String>();
            headers.addAll(Arrays.asList(headerLines));
            int bodyOffset = headerEnd + 4;
            return new FakeRequestInfo(headers, bodyOffset);
        }

        @Override
        public IResponseInfo analyzeResponse(byte[] response) {
            String message = bytesToString(response);
            int firstSpace = message.indexOf(' ');
            int secondSpace = message.indexOf(' ', firstSpace + 1);
            if (firstSpace < 0 || secondSpace < 0) {
                return new FakeResponseInfo((short) -1);
            }
            try {
                return new FakeResponseInfo(Short.parseShort(
                        message.substring(firstSpace + 1, secondSpace)));
            } catch (NumberFormatException ex) {
                return new FakeResponseInfo((short) -1);
            }
        }

        @Override
        public String bytesToString(byte[] data) {
            return new String(data, StandardCharsets.ISO_8859_1);
        }

        @Override
        public byte[] stringToBytes(String data) {
            return data.getBytes(StandardCharsets.ISO_8859_1);
        }

        @Override
        public byte[] buildHttpMessage(List<String> headers, byte[] body) {
            StringBuilder message = new StringBuilder();
            for (String header : headers) {
                message.append(header).append("\r\n");
            }
            message.append("\r\n").append(bytesToString(body));
            return stringToBytes(message.toString());
        }

        @Override
        public String urlEncode(String data) {
            try {
                return URLEncoder.encode(data, "UTF-8");
            } catch (UnsupportedEncodingException ex) {
                throw new IllegalStateException(ex);
            }
        }

        @Override
        public String urlDecode(String data) {
            try {
                return URLDecoder.decode(data, "UTF-8");
            } catch (UnsupportedEncodingException ex) {
                throw new IllegalStateException(ex);
            }
        }

        @Override
        public IHttpService buildHttpService(String host, int port, String protocol) {
            return new FakeHttpService(host, port, protocol);
        }
    }

    private static final class FakeCallbacks implements IBurpExtenderCallbacks {
        private final FakeHelpers helpers = new FakeHelpers();
        private final Map<String, String> settings = new HashMap<String, String>();
        private int repeaterSendCount;
        private String repeaterHost;
        private int repeaterPort;
        private boolean repeaterUseHttps;
        private String repeaterCaption;
        private boolean failRepeaterSend;
        private String lastError = "";
        private final StringBuilder output = new StringBuilder();
        private byte[] nextResponse;
        private int httpRequestCount;
        private byte[] lastHttpRequest;
        private FakeMessage lastHttpResult;
        private IProxyListener proxyListener;

        @Override
        public void setExtensionName(String name) {
        }

        @Override
        public void registerContextMenuFactory(IContextMenuFactory factory) {
        }

        @Override
        public void registerProxyListener(IProxyListener listener) {
            proxyListener = listener;
        }

        @Override
        public void addSuiteTab(ITab tab) {
        }

        @Override
        public void customizeUiComponent(Component component) {
        }

        @Override
        public IExtensionHelpers getHelpers() {
            return helpers;
        }

        @Override
        public IMessageEditor createMessageEditor(IMessageEditorController controller,
                boolean editable) {
            return new FakeMessageEditor();
        }

        @Override
        public IHttpRequestResponse makeHttpRequest(IHttpService httpService, byte[] request) {
            if (nextResponse == null) {
                throw new UnsupportedOperationException();
            }
            httpRequestCount++;
            lastHttpRequest = request;
            lastHttpResult = new FakeMessage(request, httpService, nextResponse);
            return lastHttpResult;
        }

        @Override
        public void sendToRepeater(String host, int port, boolean useHttps, byte[] request,
                String tabCaption) {
            if (failRepeaterSend) {
                throw new RuntimeException("boom");
            }
            repeaterSendCount++;
            repeaterHost = host;
            repeaterPort = port;
            repeaterUseHttps = useHttps;
            repeaterCaption = tabCaption;
        }

        @Override
        public void saveExtensionSetting(String name, String value) {
            settings.put(name, value);
        }

        @Override
        public String loadExtensionSetting(String name) {
            return settings.get(name);
        }

        @Override
        public void printOutput(String message) {
            output.append(message).append('\n');
        }

        @Override
        public void printError(String message) {
            lastError = message;
        }

        private String outputText() {
            return output.toString();
        }
    }

    private static final class FakeMessageEditor implements IMessageEditor {
        private byte[] message = new byte[0];
        private int[] selectionBounds;

        @Override
        public Component getComponent() {
            return new JPanel();
        }

        @Override
        public void setMessage(byte[] message, boolean isRequest) {
            this.message = message == null ? new byte[0] : message;
        }

        @Override
        public byte[] getMessage() {
            return message;
        }

        @Override
        public boolean isMessageModified() {
            return false;
        }

        @Override
        public byte[] getSelectedData() {
            return new byte[0];
        }

        @Override
        public int[] getSelectionBounds() {
            return selectionBounds;
        }
    }

    private static final class FakeInterceptedProxyMessage
            implements IInterceptedProxyMessage {
        private final IHttpRequestResponse messageInfo;

        private FakeInterceptedProxyMessage(IHttpRequestResponse messageInfo) {
            this.messageInfo = messageInfo;
        }

        @Override
        public IHttpRequestResponse getMessageInfo() {
            return messageInfo;
        }
    }

    private static final class FlakyInvocation implements IContextMenuInvocation {
        private final IHttpRequestResponse[] firstMessages;
        private int calls;

        private FlakyInvocation(IHttpRequestResponse[] firstMessages) {
            this.firstMessages = firstMessages;
        }

        @Override
        public IHttpRequestResponse[] getSelectedMessages() {
            calls++;
            return calls == 1 ? firstMessages : null;
        }
    }

    private static final class FakeMessage implements IHttpRequestResponse {
        private byte[] request;
        private final byte[] response;
        private final IHttpService service;
        private String highlight;
        private boolean edited;

        private FakeMessage(byte[] request) {
            this(request, new FakeHttpService());
        }

        private FakeMessage(byte[] request, IHttpService service) {
            this(request, service, null);
        }

        private FakeMessage(byte[] request, IHttpService service, byte[] response) {
            this.request = request;
            this.service = service;
            this.response = response;
        }

        static FakeMessage formWithMarker() {
            String request = ""
                    + "POST /submit HTTP/1.1\r\n"
                    + "Host: example.test\r\n"
                    + "Content-Type: application/x-www-form-urlencoded\r\n"
                    + "\r\n"
                    + "name=§§";
            return new FakeMessage(request.getBytes(StandardCharsets.ISO_8859_1));
        }

        static FakeMessage rawRequestWithoutMarker() {
            String request = ""
                    + "POST /submit?id=1 HTTP/1.1\r\n"
                    + "Host: example.test\r\n"
                    + "Accept: */*\r\n"
                    + "\r\n";
            return new FakeMessage(request.getBytes(StandardCharsets.ISO_8859_1));
        }

        static FakeMessage queryWithMarkerWithoutService() {
            return new FakeMessage(queryRequestBytes(), null);
        }

        private static byte[] queryRequestBytes() {
            String request = ""
                    + "POST /submit?id=§§ HTTP/1.1\r\n"
                    + "Host: example.test\r\n"
                    + "\r\n";
            return request.getBytes(StandardCharsets.ISO_8859_1);
        }

        static FakeMessage queryWithMarker() {
            String request = ""
                    + "POST /submit?id=§§ HTTP/1.1\r\n"
                    + "Host: example.test\r\n"
                    + "\r\n";
            return new FakeMessage(request.getBytes(StandardCharsets.ISO_8859_1));
        }

        static FakeMessage rawBodyWithMarker() {
            String request = ""
                    + "POST /upload HTTP/1.1\r\n"
                    + "Host: example.test\r\n"
                    + "Content-Type: application/octet-stream\r\n"
                    + "Content-Length: 14\r\n"
                    + "\r\n"
                    + "binary§§tail§§";
            return new FakeMessage(request.getBytes(StandardCharsets.ISO_8859_1));
        }

        static FakeMessage jsonScalarWithMarker() {
            String request = ""
                    + "POST /json HTTP/1.1\r\n"
                    + "Host: example.test\r\n"
                    + "Content-Type: application/json\r\n"
                    + "Content-Length: 9\r\n"
                    + "\r\n"
                    + "{\"id\":§§}";
            return new FakeMessage(request.getBytes(StandardCharsets.ISO_8859_1));
        }

        @Override
        public byte[] getRequest() {
            return request;
        }

        @Override
        public void setRequest(byte[] newRequest) {
            request = newRequest;
            edited = true;
        }

        @Override
        public byte[] getResponse() {
            return response;
        }

        @Override
        public IHttpService getHttpService() {
            return service;
        }

        @Override
        public String getHighlight() {
            return highlight;
        }

        @Override
        public void setHighlight(String color) {
            highlight = color;
        }

        boolean isEdited() {
            return edited;
        }
    }

    private static final class FakeHttpService implements IHttpService {
        private final String host;
        private final int port;
        private final String protocol;

        private FakeHttpService() {
            this("example.test", 80, "http");
        }

        private FakeHttpService(String host, int port, String protocol) {
            this.host = host;
            this.port = port;
            this.protocol = protocol;
        }

        @Override
        public String getHost() {
            return host;
        }

        @Override
        public int getPort() {
            return port;
        }

        @Override
        public String getProtocol() {
            return protocol;
        }
    }

    private static final class FakeRequestInfo implements IRequestInfo {
        private final List<String> headers;
        private final int bodyOffset;

        private FakeRequestInfo(List<String> headers, int bodyOffset) {
            this.headers = headers;
            this.bodyOffset = bodyOffset;
        }

        @Override
        public String getMethod() {
            return "POST";
        }

        @Override
        public URL getUrl() {
            try {
                return new URL("http://example.test/submit");
            } catch (MalformedURLException ex) {
                throw new IllegalStateException(ex);
            }
        }

        @Override
        public List<String> getHeaders() {
            return headers;
        }

        @Override
        public int getBodyOffset() {
            return bodyOffset;
        }
    }

    private static final class FakeResponseInfo implements IResponseInfo {
        private final short statusCode;

        private FakeResponseInfo(short statusCode) {
            this.statusCode = statusCode;
        }

        @Override
        public short getStatusCode() {
            return statusCode;
        }
    }
}
