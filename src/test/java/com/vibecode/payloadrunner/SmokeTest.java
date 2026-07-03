package com.vibecode.payloadrunner;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpService;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IContextMenuFactory;
import burp.ITab;

import java.awt.Component;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
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
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JMenuItem;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.JTable;

public final class SmokeTest {
    public static void main(String[] args) throws Exception {
        testYamlParser();
        testDefaultPayloadResource();
        testQueryInsertionPoints();
        testEncodingStrategies();
        testRateLimitDefaultsAndDelays();
        testRequestTemplateAcceptsUrlMarkerWithoutBody();
        testRequestTemplateBuildsMissingService();
        testFormInsertionPoints();
        testJsonInsertionPoints();
        testMultipartInsertionPoints();
        testXmlInsertionPoints();
        testResponseDiffAndHitRules();
        testRepeaterCaptionAndSend();
        testRepeaterSendFailureDoesNotThrow();
        testRepeaterSkippedWhenHistoryBytesDropped();
        testSendPayloadCreatesHistoryWithoutAutoRepeater();
        testHistoryStoreNavigationAndLimit();
        testEndpointKeyExcludesQuery();
        testResultRowSelectsHistoryRecord();
        testManualRepeaterButtons();
        testCsvExport();
        testContextMenuCapturesSelectionSnapshot();
        testCategorySelectionDoesNotExpandOnParse();
        testQueuedRequestSelectionControlsRunSnapshot();
        testQueuedRequestDeleteSelected();
        testNewlyQueuedRequestsBecomeSelected();
        testResultSelectionUsesSortedViewRow();
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

    private static void testQueryInsertionPoints() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "POST /submit?name=pre*post&encoded=%2A HTTP/1.1",
                "Host: example.test");
        List<QueryInsertionPoint> points = QueryInsertionPoint.fromRequestLine(helpers, headers, "");

        assertEquals(2, points.size(), "query marker count");
        assertEquals("url:name", points.get(0).getName(), "query parameter name");

        String firstRequest = helpers.bytesToString(points.get(0).buildRequest("A B"));
        assertContains(firstRequest, "POST /submit?name=preA+Bpost&encoded=%2A HTTP/1.1",
                "raw query replacement");

        String secondRequest = helpers.bytesToString(points.get(1).buildRequest("x/y"));
        assertContains(secondRequest, "POST /submit?name=pre*post&encoded=x%2Fy HTTP/1.1",
                "decoded query replacement");
    }

    private static void testEncodingStrategies() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "POST /submit?name=* HTTP/1.1",
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
                helpers, jsonHeaders, "{\"name\":\"*\"}");

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
                helpers, headers, "a=1&name=pre*post&encoded=%2A");

        assertEquals(2, points.size(), "form marker count");
        String firstRequest = helpers.bytesToString(points.get(0).buildRequest("A B"));
        assertContains(firstRequest, "name=preA+Bpost", "raw star replacement");

        String secondRequest = helpers.bytesToString(points.get(1).buildRequest("x/y"));
        assertContains(secondRequest, "encoded=x%2Fy", "decoded star replacement");
    }

    private static void testJsonInsertionPoints() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "POST /api HTTP/1.1",
                "Host: example.test",
                "Content-Type: application/json");
        List<BodyInsertionPoint> points = BodyInsertionPoint.fromJson(
                helpers, headers, "{\"name\":\"pre*post\",\"items\":[\"*\"]}");

        assertEquals(2, points.size(), "json marker count");
        assertEquals("name", points.get(0).getName(), "json object key");
        assertEquals("items", points.get(1).getName(), "json array key");

        String request = helpers.bytesToString(points.get(0).buildRequest("PAY"));
        assertContains(request, "\"name\":\"prePAYpost\"", "json replacement");
    }

    private static void testMultipartInsertionPoints() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "POST /upload HTTP/1.1",
                "Host: example.test",
                "Content-Type: multipart/form-data; boundary=abc123");
        String body = ""
                + "--abc123\r\n"
                + "Content-Disposition: form-data; name=\"file\"\r\n"
                + "\r\n"
                + "pre*post\r\n"
                + "--abc123--\r\n";

        List<BodyInsertionPoint> points = BodyInsertionPoint.fromMultipart(helpers, headers, body);
        assertEquals(1, points.size(), "multipart marker count");
        assertEquals("multipart:file", points.get(0).getName(), "multipart parameter name");

        String request = helpers.bytesToString(points.get(0).buildRequest("A B"));
        assertContains(request, "preA+Bpost", "multipart replacement");
    }

    private static void testXmlInsertionPoints() {
        FakeHelpers helpers = new FakeHelpers();
        List<String> headers = Arrays.asList(
                "POST /xml HTTP/1.1",
                "Host: example.test",
                "Content-Type: application/xml");
        String body = "<root id=\"*\"><name>pre*post</name></root>";

        List<BodyInsertionPoint> points = BodyInsertionPoint.fromXml(helpers, headers, body);
        assertEquals(2, points.size(), "xml marker count");
        assertEquals("xml:root@id", points.get(0).getName(), "xml attribute marker");
        assertEquals("xml:name", points.get(1).getName(), "xml text marker");

        String attributeRequest = helpers.bytesToString(points.get(0).buildRequest("A B"));
        assertContains(attributeRequest, "id=\"A+B\"", "xml attribute replacement");
        String textRequest = helpers.bytesToString(points.get(1).buildRequest("A B"));
        assertContains(textRequest, "<name>preA+Bpost</name>", "xml text replacement");
    }

    private static void testResponseDiffAndHitRules() {
        FakeHelpers helpers = new FakeHelpers();
        byte[] baseline = helpers.stringToBytes("HTTP/1.1 200 OK\r\n\r\nhello");
        byte[] response = helpers.stringToBytes("HTTP/1.1 500 Server Error\r\n\r\nhello root extra");

        ResponseDiff diff = ResponseDiff.between(helpers, baseline, response, 500);
        assertEquals(true, diff.isAvailable(), "diff availability");
        assertEquals(true, diff.getLengthDelta() > 0, "diff length delta");

        List<HitRule> rules = HitRule.parse("root",
                "regex:extra\nstatus:5xx\nlength>20\ndiff>0\nsim<100");
        String hits = HitRule.evaluate(rules,
                new HitRule.MatchInput(helpers.bytesToString(response), 500, response.length, diff));
        assertContains(hits, "keyword:root", "keyword hit rule");
        assertContains(hits, "regex:extra", "regex hit rule");
        assertContains(hits, "status:5xx", "status hit rule");
        assertContains(hits, "diff>0", "diff hit rule");
    }

    private static void testRepeaterCaptionAndSend() {
        FakeCallbacks callbacks = new FakeCallbacks();
        FakeHttpService service = new FakeHttpService("example.test", 443, "https");
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
        assertEquals("POST /submit | sqli | url:id | #003", callbacks.repeaterCaption,
                "manual repeater caption");

        String longCaption = RepeaterSupport.buildCaption("POST",
                "/very/long/path/that/keeps/going/and/going/and/going/and/going",
                "sqli", "username", 12);
        assertEquals(true, longCaption.length() <= 80, "truncated repeater caption length");
        assertContains(longCaption, "#012", "truncated repeater caption index");
        assertContains(longCaption, "POST /very/long/path", "truncated repeater caption prefix");
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
        assertEquals(true, callbacks.lastError.contains("sendToRepeater failed"),
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
        assertContains(result.getError(), "dropped due to max history",
                "dropped history repeater error");
        assertContains(callbacks.lastError, "sendToRepeater failed",
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

                invokePrivate(panel, "sendPayload",
                        new Class<?>[] {RequestTemplate.class, PayloadInsertionPoint.class,
                                String.class, String.class, EncodingStrategy.class, List.class,
                                int.class},
                        template, insertionPoint, "ids", "42", EncodingStrategy.URL_ENCODE,
                        Collections.<HitRule>emptyList(), Integer.valueOf(3));

                RunnerResult result = (RunnerResult) invokePrivate(panel, "sendPayload",
                        new Class<?>[] {RequestTemplate.class, PayloadInsertionPoint.class,
                                String.class, String.class, EncodingStrategy.class, List.class,
                                int.class},
                        template, insertionPoint, "ids", "43", EncodingStrategy.URL_ENCODE,
                        Collections.<HitRule>emptyList(), Integer.valueOf(4));
                assertEquals(0, callbacks.repeaterSendCount, "sendPayload does not auto repeater");
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
                assertEquals(true, first.isSentToRepeater(), "current record sent flag");

                resultTable.setRowSelectionInterval(0, 1);
                sendSelected.doClick();
                assertEquals(3, callbacks.repeaterSendCount, "selected repeater send count");
                assertEquals(true, second.isSentToRepeater(), "selected record sent flag");

                second.setInteresting(true);
                sendInteresting.doClick();
                assertEquals(4, callbacks.repeaterSendCount, "interesting repeater send count");
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
        assertContains(csv, "len +1, sim 90%", "csv diff export");
        file.delete();
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

    private static Object privateField(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
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

        @Override
        public void setExtensionName(String name) {
        }

        @Override
        public void registerContextMenuFactory(IContextMenuFactory factory) {
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
            throw new UnsupportedOperationException();
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
        public void printError(String message) {
            lastError = message;
        }
    }

    private static final class FakeMessageEditor implements IMessageEditor {
        @Override
        public Component getComponent() {
            return new JPanel();
        }

        @Override
        public void setMessage(byte[] message, boolean isRequest) {
        }

        @Override
        public byte[] getMessage() {
            return new byte[0];
        }

        @Override
        public boolean isMessageModified() {
            return false;
        }

        @Override
        public byte[] getSelectedData() {
            return new byte[0];
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
        private final byte[] request;
        private final IHttpService service;

        private FakeMessage(byte[] request) {
            this(request, new FakeHttpService());
        }

        private FakeMessage(byte[] request, IHttpService service) {
            this.request = request;
            this.service = service;
        }

        static FakeMessage formWithMarker() {
            String request = ""
                    + "POST /submit HTTP/1.1\r\n"
                    + "Host: example.test\r\n"
                    + "Content-Type: application/x-www-form-urlencoded\r\n"
                    + "\r\n"
                    + "name=*";
            return new FakeMessage(request.getBytes(StandardCharsets.ISO_8859_1));
        }

        static FakeMessage queryWithMarkerWithoutService() {
            return new FakeMessage(queryRequestBytes(), null);
        }

        private static byte[] queryRequestBytes() {
            String request = ""
                    + "POST /submit?id=* HTTP/1.1\r\n"
                    + "Host: example.test\r\n"
                    + "\r\n";
            return request.getBytes(StandardCharsets.ISO_8859_1);
        }

        static FakeMessage queryWithMarker() {
            String request = ""
                    + "POST /submit?id=* HTTP/1.1\r\n"
                    + "Host: example.test\r\n"
                    + "\r\n";
            return new FakeMessage(request.getBytes(StandardCharsets.ISO_8859_1));
        }

        @Override
        public byte[] getRequest() {
            return request;
        }

        @Override
        public byte[] getResponse() {
            return null;
        }

        @Override
        public IHttpService getHttpService() {
            return service;
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
