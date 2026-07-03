package com.vibecode.payloadrunner;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IResponseInfo;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JList;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.TableColumnModel;

final class PayloadRunnerPanel extends JPanel implements IMessageEditorController {
    private static final String PAYLOADS_SETTING = "payloadsYaml";
    private static final String RULES_SETTING = "hitRules";
    private static final String DEFAULT_YAML = DefaultPayloads.load();
    private static final String DEFAULT_RULES =
            "# One rule per line: keyword:admin, regex:uid=\\d+, status:5xx,\n"
                    + "# length>1000, diff>200, sim<90\n";

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final JTextArea yamlArea = new JTextArea(DEFAULT_YAML, 12, 44);
    private final DefaultListModel<String> categoryModel = new DefaultListModel<String>();
    private final JList<String> categoryList = new JList<String>(categoryModel);
    private final DefaultListModel<RequestTemplate> requestModel = new DefaultListModel<RequestTemplate>();
    private final JList<RequestTemplate> requestList = new JList<RequestTemplate>(requestModel);
    private final JTextArea rulesArea = new JTextArea(DEFAULT_RULES, 5, 24);
    private final ResultTableModel resultModel = new ResultTableModel();
    private final JTable resultTable = new JTable(resultModel);
    private final JLabel statusLabel = new JLabel("Right-click a request and choose Send to Payload Runner.");
    private final JButton parseButton = new JButton("Parse YAML");
    private final JButton savePayloadsButton = new JButton("Save Payloads");
    private final JButton resetPayloadsButton = new JButton("Reset Built-in");
    private final JButton runButton = new JButton("Run Selected");
    private final JButton pauseButton = new JButton("Pause");
    private final JButton stopButton = new JButton("Stop");
    private final JButton clearRequestsButton = new JButton("Clear Requests");
    private final JButton clearResultsButton = new JButton("Clear Results");
    private final JButton exportButton = new JButton("Export CSV");
    private final JButton saveRulesButton = new JButton("Save Rules");
    private final JButton resetRulesButton = new JButton("Reset Rules");
    private final JButton selectAllCategoriesButton = new JButton("All");
    private final JButton clearCategoriesButton = new JButton("None");
    private final JCheckBox autoSendRepeaterCheckBox = new JCheckBox("Auto send to Repeater");
    private final JComboBox<EncodingStrategy> encodingCombo =
            new JComboBox<EncodingStrategy>(EncodingStrategy.values());
    private final JTextField repeaterCaptionField = new JTextField(12);
    private final JTextField keywordField = new JTextField(24);
    private final IMessageEditor requestViewer;
    private final IMessageEditor responseViewer;
    private JTabbedPane mainTabs;

    private final Object pauseLock = new Object();
    private Map<String, List<String>> parsedPayloads = new LinkedHashMap<String, List<String>>();
    private SwingWorker<Void, RunnerResult> activeWorker;
    private RunnerResult selectedResult;
    private volatile boolean paused;

    PayloadRunnerPanel(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        super(new BorderLayout(8, 8));
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.requestViewer = callbacks.createMessageEditor(this, false);
        this.responseViewer = callbacks.createMessageEditor(this, false);

        loadSavedPayloads();
        loadSavedRules();
        buildUi();
        wireActions();
        parseYamlIntoCategories(false);
    }

    void addRequests(final IHttpRequestResponse[] messages) {
        if (messages == null || messages.length == 0) {
            statusLabel.setText("Burp did not provide a selected HTTP request for this menu context.");
            return;
        }
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> addRequests(messages));
            return;
        }

        int added = 0;
        int skippedNoMarker = 0;
        int skippedError = 0;
        int firstAddedIndex = -1;
        int lastAddedIndex = -1;
        String lastSkipReason = "";
        for (IHttpRequestResponse message : messages) {
            try {
                RequestTemplate template = RequestTemplate.fromMessage(helpers, message);
                if (template.getInsertionPoints().isEmpty()) {
                    skippedNoMarker++;
                    lastSkipReason = "No URL query, form, JSON, multipart, or XML values contain '*'.";
                    continue;
                }
                int addedIndex = requestModel.size();
                requestModel.addElement(template);
                if (firstAddedIndex < 0) {
                    firstAddedIndex = addedIndex;
                }
                lastAddedIndex = addedIndex;
                added++;
            } catch (RuntimeException ex) {
                skippedError++;
                lastSkipReason = ex.getMessage() == null
                        ? ex.getClass().getSimpleName()
                        : ex.getMessage();
            }
        }

        String summary = "Added " + added + " request(s); skipped " + skippedNoMarker
                + " without markers";
        if (skippedError > 0) {
            summary += "; skipped " + skippedError + " with parse errors";
        }
        if (!lastSkipReason.isEmpty()) {
            summary += ". Last skip: " + lastSkipReason;
        } else {
            summary += ".";
        }
        statusLabel.setText(summary);
        if (added > 0) {
            requestList.setSelectionInterval(firstAddedIndex, lastAddedIndex);
            requestList.ensureIndexIsVisible(lastAddedIndex);
            if (mainTabs != null) {
                mainTabs.setSelectedIndex(0);
            }
        }
    }

    private void buildUi() {
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        yamlArea.setLineWrap(false);
        yamlArea.setTabSize(2);

        JPanel yamlPanel = new JPanel(new BorderLayout(4, 4));
        yamlPanel.setBorder(BorderFactory.createTitledBorder("YAML payloads"));
        yamlPanel.add(new JScrollPane(yamlArea), BorderLayout.CENTER);
        yamlPanel.setMinimumSize(new Dimension(420, 260));

        categoryList.setVisibleRowCount(8);
        categoryList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JPanel categoryPanel = new JPanel(new BorderLayout(4, 4));
        categoryPanel.setBorder(BorderFactory.createTitledBorder("Categories"));
        categoryPanel.add(new JScrollPane(categoryList), BorderLayout.CENTER);
        JPanel categoryButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        categoryButtonPanel.add(selectAllCategoriesButton);
        categoryButtonPanel.add(clearCategoriesButton);
        categoryPanel.add(categoryButtonPanel, BorderLayout.SOUTH);
        categoryPanel.setMinimumSize(new Dimension(360, 150));

        requestList.setVisibleRowCount(7);
        requestList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        installRequestQueueActions();
        JPanel requestPanel = new JPanel(new BorderLayout(4, 4));
        requestPanel.setBorder(BorderFactory.createTitledBorder("Queued requests"));
        requestPanel.add(new JScrollPane(requestList), BorderLayout.CENTER);
        requestPanel.setMinimumSize(new Dimension(360, 150));

        rulesArea.setLineWrap(false);
        JPanel rulesPanel = new JPanel(new BorderLayout(4, 4));
        rulesPanel.setBorder(BorderFactory.createTitledBorder("Hit rules"));
        rulesPanel.add(new JScrollPane(rulesArea), BorderLayout.CENTER);
        JPanel rulesButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        rulesButtonPanel.add(saveRulesButton);
        rulesButtonPanel.add(resetRulesButton);
        rulesPanel.add(rulesButtonPanel, BorderLayout.SOUTH);
        rulesPanel.setMinimumSize(new Dimension(360, 140));

        JSplitPane rulesCategorySplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                rulesPanel, categoryPanel);
        rulesCategorySplit.setResizeWeight(0.58);
        rulesCategorySplit.setContinuousLayout(true);
        rulesCategorySplit.setMinimumSize(new Dimension(380, 300));

        JSplitPane sideSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                rulesCategorySplit, requestPanel);
        sideSplit.setResizeWeight(0.58);
        sideSplit.setContinuousLayout(true);
        sideSplit.setMinimumSize(new Dimension(420, 460));
        sideSplit.setPreferredSize(new Dimension(560, 520));

        JPanel configButtonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JPanel runButtonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JPanel runnerControlPanel = new JPanel(new BorderLayout(0, 4));
        pauseButton.setEnabled(false);
        stopButton.setEnabled(false);
        configButtonRow.add(parseButton);
        configButtonRow.add(savePayloadsButton);
        configButtonRow.add(resetPayloadsButton);
        configButtonRow.add(new JLabel("Encoding"));
        configButtonRow.add(encodingCombo);
        configButtonRow.add(autoSendRepeaterCheckBox);
        configButtonRow.add(new JLabel("Repeater name"));
        configButtonRow.add(repeaterCaptionField);
        configButtonRow.add(new JLabel("Keywords"));
        configButtonRow.add(keywordField);
        runButtonRow.add(runButton);
        runButtonRow.add(clearRequestsButton);
        runnerControlPanel.add(configButtonRow, BorderLayout.NORTH);
        runnerControlPanel.add(runButtonRow, BorderLayout.SOUTH);

        JPanel runnerPage = new JPanel(new BorderLayout(6, 6));
        JSplitPane configSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, yamlPanel, sideSplit);
        configSplit.setResizeWeight(0.52);
        configSplit.setContinuousLayout(true);
        runnerPage.add(configSplit, BorderLayout.CENTER);
        runnerPage.add(runnerControlPanel, BorderLayout.SOUTH);

        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultTable.setAutoCreateRowSorter(true);
        configureResultColumns(resultTable.getColumnModel());
        JPanel resultPanel = new JPanel(new BorderLayout(4, 4));
        resultPanel.setBorder(BorderFactory.createTitledBorder("Results"));
        resultPanel.add(new JScrollPane(resultTable), BorderLayout.CENTER);

        Component requestComponent = requestViewer.getComponent();
        Component responseComponent = responseViewer.getComponent();
        JSplitPane messageSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestComponent, responseComponent);
        messageSplit.setResizeWeight(0.5);
        messageSplit.setPreferredSize(new Dimension(900, 280));

        JSplitPane lowerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, resultPanel, messageSplit);
        lowerSplit.setResizeWeight(0.45);
        lowerSplit.setContinuousLayout(true);

        JPanel resultControlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        resultControlPanel.add(pauseButton);
        resultControlPanel.add(stopButton);
        resultControlPanel.add(clearResultsButton);
        resultControlPanel.add(exportButton);

        JPanel resultsPage = new JPanel(new BorderLayout(6, 6));
        resultsPage.add(resultControlPanel, BorderLayout.NORTH);
        resultsPage.add(lowerSplit, BorderLayout.CENTER);

        mainTabs = new JTabbedPane();
        mainTabs.addTab("Runner", runnerPage);
        mainTabs.addTab("Results", resultsPage);

        add(mainTabs, BorderLayout.CENTER);
        add(statusLabel, BorderLayout.SOUTH);
    }

    private void configureResultColumns(TableColumnModel columns) {
        columns.getColumn(0).setPreferredWidth(44);
        columns.getColumn(1).setPreferredWidth(58);
        columns.getColumn(2).setPreferredWidth(140);
        columns.getColumn(3).setPreferredWidth(180);
        columns.getColumn(4).setPreferredWidth(120);
        columns.getColumn(5).setPreferredWidth(90);
        columns.getColumn(6).setPreferredWidth(220);
        columns.getColumn(7).setPreferredWidth(120);
        columns.getColumn(8).setPreferredWidth(90);
        columns.getColumn(9).setPreferredWidth(130);
        columns.getColumn(10).setPreferredWidth(80);
        columns.getColumn(11).setPreferredWidth(80);
        columns.getColumn(12).setPreferredWidth(80);
    }

    private void wireActions() {
        parseButton.addActionListener(event -> parseYamlIntoCategories(true));
        savePayloadsButton.addActionListener(event -> savePayloads());
        resetPayloadsButton.addActionListener(event -> resetPayloads());
        saveRulesButton.addActionListener(event -> saveRules());
        resetRulesButton.addActionListener(event -> resetRules());
        selectAllCategoriesButton.addActionListener(event -> selectAllCategories());
        clearCategoriesButton.addActionListener(event -> clearCategorySelection());
        runButton.addActionListener(event -> runSelectedCategories());
        pauseButton.addActionListener(event -> togglePause());
        stopButton.addActionListener(event -> {
            if (activeWorker != null) {
                resumeIfPaused();
                activeWorker.cancel(true);
                statusLabel.setText("Stop requested; waiting for the active request to finish.");
            }
        });
        clearRequestsButton.addActionListener(event -> {
            if (isRunnerActive()) {
                statusLabel.setText("Stop the active run before clearing queued requests.");
                return;
            }
            requestModel.clear();
            statusLabel.setText("Queued requests cleared.");
        });
        clearResultsButton.addActionListener(event -> {
            resultModel.clear();
            selectedResult = null;
            requestViewer.setMessage(null, true);
            responseViewer.setMessage(null, false);
            statusLabel.setText("Results cleared.");
        });
        exportButton.addActionListener(event -> exportResults());
        resultTable.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                showSelectedResult();
            }
        });
    }

    private void installRequestQueueActions() {
        final JPopupMenu popup = new JPopupMenu();
        final JMenuItem deleteItem = new JMenuItem("Delete Selected");
        deleteItem.addActionListener(event -> deleteSelectedRequests());
        popup.add(deleteItem);

        requestList.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent event) {
                showRequestQueuePopup(event, popup, deleteItem);
            }

            @Override
            public void mouseReleased(MouseEvent event) {
                showRequestQueuePopup(event, popup, deleteItem);
            }
        });

        requestList.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0),
                "deleteSelectedRequests");
        requestList.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE, 0),
                "deleteSelectedRequests");
        requestList.getActionMap().put("deleteSelectedRequests", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent event) {
                deleteSelectedRequests();
            }
        });
    }

    private void showRequestQueuePopup(MouseEvent event, JPopupMenu popup, JMenuItem deleteItem) {
        if (!event.isPopupTrigger()) {
            return;
        }

        int index = requestList.locationToIndex(event.getPoint());
        if (index >= 0 && requestList.getCellBounds(index, index) != null
                && requestList.getCellBounds(index, index).contains(event.getPoint())) {
            if (!requestList.isSelectedIndex(index)) {
                requestList.setSelectedIndex(index);
            }
        }

        boolean hasSelection = !requestList.isSelectionEmpty();
        if (!hasSelection && index < 0) {
            return;
        }
        deleteItem.setEnabled(hasSelection && !isRunnerActive());
        popup.show(requestList, event.getX(), event.getY());
    }

    private void deleteSelectedRequests() {
        if (isRunnerActive()) {
            statusLabel.setText("Stop the active run before deleting queued requests.");
            return;
        }

        int[] selected = requestList.getSelectedIndices();
        if (selected.length == 0) {
            statusLabel.setText("Select queued request(s) to delete.");
            return;
        }

        int nextSelection = selected[0];
        for (int i = selected.length - 1; i >= 0; i--) {
            requestModel.remove(selected[i]);
        }
        if (requestModel.size() > 0) {
            requestList.setSelectedIndex(Math.min(nextSelection, requestModel.size() - 1));
        }
        statusLabel.setText("Deleted " + selected.length + " queued request"
                + (selected.length == 1 ? "." : "s."));
    }

    private boolean parseYamlIntoCategories(boolean showDialogOnError) {
        try {
            List<String> selectedBeforeParse = categoryList.getSelectedValuesList();
            parsedPayloads = YamlPayloadParser.parse(yamlArea.getText());
            categoryModel.clear();
            for (String category : parsedPayloads.keySet()) {
                categoryModel.addElement(category);
            }
            restoreCategorySelection(selectedBeforeParse);
            statusLabel.setText("Loaded " + parsedPayloads.size() + " payload categor"
                    + (parsedPayloads.size() == 1 ? "y." : "ies.")
                    + " Select one or more categories to run.");
            return true;
        } catch (IllegalArgumentException ex) {
            statusLabel.setText("YAML error: " + ex.getMessage());
            if (showDialogOnError) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), "YAML error",
                        JOptionPane.ERROR_MESSAGE);
            }
            return false;
        }
    }

    private void restoreCategorySelection(List<String> selectedBeforeParse) {
        if (categoryModel.size() == 0) {
            return;
        }
        if (selectedBeforeParse == null || selectedBeforeParse.isEmpty()) {
            return;
        }

        List<Integer> indexes = new ArrayList<Integer>();
        for (int i = 0; i < categoryModel.size(); i++) {
            if (selectedBeforeParse.contains(categoryModel.getElementAt(i))) {
                indexes.add(i);
            }
        }
        if (indexes.isEmpty()) {
            return;
        }

        int[] selectedIndexes = new int[indexes.size()];
        for (int i = 0; i < indexes.size(); i++) {
            selectedIndexes[i] = indexes.get(i);
        }
        categoryList.setSelectedIndices(selectedIndexes);
    }

    private void selectAllCategories() {
        if (categoryModel.size() == 0) {
            statusLabel.setText("No payload categories loaded.");
            return;
        }
        categoryList.setSelectionInterval(0, categoryModel.size() - 1);
        statusLabel.setText("Selected " + categoryModel.size() + " payload categories.");
    }

    private void clearCategorySelection() {
        categoryList.clearSelection();
        statusLabel.setText("Category selection cleared.");
    }

    private void loadSavedPayloads() {
        String saved = callbacks.loadExtensionSetting(PAYLOADS_SETTING);
        if (saved != null && !saved.trim().isEmpty()) {
            yamlArea.setText(saved);
        }
    }

    private void loadSavedRules() {
        String saved = callbacks.loadExtensionSetting(RULES_SETTING);
        if (saved != null && !saved.trim().isEmpty()) {
            rulesArea.setText(saved);
        }
    }

    private void savePayloads() {
        if (!parseYamlIntoCategories(true)) {
            return;
        }
        callbacks.saveExtensionSetting(PAYLOADS_SETTING, yamlArea.getText());
        statusLabel.setText("Payload YAML saved to Burp extension settings.");
    }

    private void resetPayloads() {
        yamlArea.setText(DefaultPayloads.load());
        if (parseYamlIntoCategories(true)) {
            callbacks.saveExtensionSetting(PAYLOADS_SETTING, yamlArea.getText());
            statusLabel.setText("Payload YAML reset to built-in defaults and saved.");
        }
    }

    private void saveRules() {
        try {
            HitRule.parse(keywordField.getText(), rulesArea.getText());
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Hit rule error",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }
        callbacks.saveExtensionSetting(RULES_SETTING, rulesArea.getText());
        statusLabel.setText("Hit rules saved to Burp extension settings.");
    }

    private void resetRules() {
        rulesArea.setText(DEFAULT_RULES);
        callbacks.saveExtensionSetting(RULES_SETTING, rulesArea.getText());
        statusLabel.setText("Hit rules reset and saved.");
    }

    private void runSelectedCategories() {
        if (activeWorker != null && !activeWorker.isDone()) {
            statusLabel.setText("Payload Runner is already running.");
            return;
        }
        if (!parseYamlIntoCategories(true)) {
            return;
        }

        List<String> categories = categoryList.getSelectedValuesList();
        if (categories.isEmpty()) {
            statusLabel.setText("Select at least one payload category.");
            return;
        }

        List<RequestTemplate> requests = snapshotRunRequests();
        if (requests.isEmpty()) {
            statusLabel.setText("Queue at least one request from Burp's context menu.");
            return;
        }

        Map<String, List<String>> selectedPayloads = new LinkedHashMap<String, List<String>>();
        final EncodingStrategy encodingStrategy =
                (EncodingStrategy) encodingCombo.getSelectedItem();
        final boolean autoSendToRepeater = autoSendRepeaterCheckBox.isSelected();
        final String repeaterCaptionPrefix = repeaterCaptionField.getText();
        final List<HitRule> hitRules;
        try {
            hitRules = HitRule.parse(keywordField.getText(), rulesArea.getText());
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Hit rule error",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }
        int total = 0;
        for (String category : categories) {
            List<String> payloads = parsedPayloads.get(category);
            if (payloads != null && !payloads.isEmpty()) {
                selectedPayloads.put(category, new ArrayList<String>(payloads));
                total += countInsertionPoints(requests) * payloads.size();
            }
        }
        if (total == 0) {
            statusLabel.setText("Selected categories contain no payloads.");
            return;
        }
        final int totalRequests = total;

        setRunning(true);
        paused = false;
        statusLabel.setText("Running 0 / " + totalRequests + " payload request(s)...");
        if (mainTabs != null) {
            mainTabs.setSelectedIndex(1);
        }

        activeWorker = new SwingWorker<Void, RunnerResult>() {
            private int completed;
            private int attempted;

            @Override
            protected Void doInBackground() {
                for (RequestTemplate template : requests) {
                    if (isCancelled()) {
                        break;
                    }
                    for (PayloadInsertionPoint insertionPoint : template.getInsertionPoints()) {
                        for (Map.Entry<String, List<String>> entry : selectedPayloads.entrySet()) {
                            String category = entry.getKey();
                            for (String payload : entry.getValue()) {
                                if (isCancelled() || !waitIfPaused()) {
                                    return null;
                                }
                                int variantIndex = ++attempted;
                                publish(sendPayload(template, insertionPoint, category, payload,
                                        encodingStrategy, hitRules, autoSendToRepeater,
                                        repeaterCaptionPrefix, variantIndex));
                            }
                        }
                    }
                }
                return null;
            }

            @Override
            protected void process(List<RunnerResult> chunks) {
                String repeaterError = "";
                for (RunnerResult result : chunks) {
                    completed++;
                    resultModel.addResult(result);
                    if (!result.getRepeaterError().isEmpty()) {
                        repeaterError = result.getRepeaterError();
                    }
                }
                String status = "Running " + completed + " / " + totalRequests
                        + " payload request(s)...";
                if (!repeaterError.isEmpty()) {
                    status += " Last Repeater error: " + truncateStatus(repeaterError);
                }
                statusLabel.setText(status);
            }

            @Override
            protected void done() {
                setRunning(false);
                paused = false;
                pauseButton.setText("Pause");
                statusLabel.setText(isCancelled()
                        ? "Run stopped after " + completed + " payload request(s)."
                        : "Run complete: " + completed + " payload request(s).");
            }
        };
        activeWorker.execute();
    }

    private RunnerResult sendPayload(RequestTemplate template, PayloadInsertionPoint insertionPoint,
            String category, String payload, EncodingStrategy encodingStrategy,
            List<HitRule> hitRules, boolean autoSendToRepeater, String repeaterCaptionPrefix,
            int variantIndex) {
        byte[] request = insertionPoint.buildRequest(payload, encodingStrategy);
        RepeaterSupport.SendResult repeaterResult = RepeaterSupport.maybeSend(callbacks,
                template.getService(), request, template.getMethod(), template.getPath(),
                category, insertionPoint.getName(), repeaterCaptionPrefix, variantIndex,
                autoSendToRepeater);
        long started = System.nanoTime();
        byte[] response = null;
        int statusCode = -1;
        int responseLength = 0;
        String responseText = "";
        String hitMatch = "";
        ResponseDiff responseDiff = ResponseDiff.unavailable();
        String error = null;
        try {
            IHttpRequestResponse result = callbacks.makeHttpRequest(template.getService(), request);
            response = result == null ? null : result.getResponse();
            if (response != null) {
                responseLength = response.length;
                IResponseInfo responseInfo = helpers.analyzeResponse(response);
                statusCode = responseInfo.getStatusCode();
                responseText = helpers.bytesToString(response);
                responseDiff = ResponseDiff.between(helpers, template.getBaselineResponse(),
                        response, statusCode);
                hitMatch = HitRule.evaluate(hitRules,
                        new HitRule.MatchInput(responseText, statusCode, responseLength,
                                responseDiff));
            }
        } catch (RuntimeException ex) {
            error = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
        }
        long elapsedMillis = Math.max(0L, (System.nanoTime() - started) / 1000000L);
        return new RunnerResult(template, insertionPoint.getName(), category, payload, request,
                response, statusCode, responseLength, elapsedMillis, hitMatch,
                responseDiff.summary(), repeaterResult.isSent(), repeaterResult.getError(), error);
    }

    private List<RequestTemplate> snapshotRequests() {
        List<RequestTemplate> requests = new ArrayList<RequestTemplate>();
        for (int i = 0; i < requestModel.size(); i++) {
            requests.add(requestModel.getElementAt(i));
        }
        return requests;
    }

    private List<RequestTemplate> snapshotRunRequests() {
        List<RequestTemplate> selected = requestList.getSelectedValuesList();
        if (!selected.isEmpty()) {
            return new ArrayList<RequestTemplate>(selected);
        }
        return snapshotRequests();
    }

    private boolean isRunnerActive() {
        return activeWorker != null && !activeWorker.isDone();
    }

    private int countInsertionPoints(List<RequestTemplate> requests) {
        int count = 0;
        for (RequestTemplate request : requests) {
            count += request.getInsertionPoints().size();
        }
        return count;
    }

    private void setRunning(boolean running) {
        parseButton.setEnabled(!running);
        savePayloadsButton.setEnabled(!running);
        resetPayloadsButton.setEnabled(!running);
        saveRulesButton.setEnabled(!running);
        resetRulesButton.setEnabled(!running);
        selectAllCategoriesButton.setEnabled(!running);
        clearCategoriesButton.setEnabled(!running);
        runButton.setEnabled(!running);
        clearRequestsButton.setEnabled(!running);
        exportButton.setEnabled(!running);
        autoSendRepeaterCheckBox.setEnabled(!running);
        repeaterCaptionField.setEnabled(!running);
        encodingCombo.setEnabled(!running);
        keywordField.setEnabled(!running);
        rulesArea.setEnabled(!running);
        pauseButton.setEnabled(running);
        stopButton.setEnabled(running);
        if (!running) {
            pauseButton.setText("Pause");
        }
    }

    private void togglePause() {
        if (activeWorker == null || activeWorker.isDone()) {
            return;
        }
        synchronized (pauseLock) {
            paused = !paused;
            if (!paused) {
                pauseLock.notifyAll();
            }
        }
        pauseButton.setText(paused ? "Resume" : "Pause");
        statusLabel.setText(paused ? "Paused." : "Resumed.");
    }

    private void resumeIfPaused() {
        synchronized (pauseLock) {
            paused = false;
            pauseLock.notifyAll();
        }
        pauseButton.setText("Pause");
    }

    private boolean waitIfPaused() {
        synchronized (pauseLock) {
            while (paused && activeWorker != null && !activeWorker.isCancelled()) {
                try {
                    pauseLock.wait(250L);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        return activeWorker == null || !activeWorker.isCancelled();
    }

    private void exportResults() {
        List<RunnerResult> results = resultModel.snapshot();
        if (results.isEmpty()) {
            statusLabel.setText("No results to export.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("payload-runner-results.csv"));
        int choice = chooser.showSaveDialog(this);
        if (choice != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            CsvExporter.export(chooser.getSelectedFile(), results);
            statusLabel.setText("Exported " + results.size() + " result(s) to "
                    + chooser.getSelectedFile().getAbsolutePath());
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Export error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private String truncateStatus(String value) {
        if (value == null || value.length() <= 120) {
            return value == null ? "" : value;
        }
        return value.substring(0, 117) + "...";
    }

    private void showSelectedResult() {
        int viewRow = resultTable.getSelectedRow();
        if (viewRow < 0) {
            selectedResult = null;
            requestViewer.setMessage(null, true);
            responseViewer.setMessage(null, false);
            return;
        }
        int modelRow = resultTable.convertRowIndexToModel(viewRow);
        selectedResult = resultModel.getResult(modelRow);
        requestViewer.setMessage(selectedResult.getRequest(), true);
        responseViewer.setMessage(selectedResult.getResponse(), false);
    }

    @Override
    public IHttpService getHttpService() {
        return selectedResult == null ? null : selectedResult.getTemplate().getService();
    }

    @Override
    public byte[] getRequest() {
        return selectedResult == null ? null : selectedResult.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return selectedResult == null ? null : selectedResult.getResponse();
    }
}
