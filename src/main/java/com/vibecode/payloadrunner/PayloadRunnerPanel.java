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
import java.io.FileOutputStream;
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
import javax.swing.RowFilter;
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
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableRowSorter;

final class PayloadRunnerPanel extends JPanel implements IMessageEditorController {
    private static final String PAYLOADS_SETTING = "payloadsYaml";
    private static final String RULES_SETTING = "hitRules";
    private static final String ENCODING_SETTING = "encodingStrategy";
    private static final String RATE_SETTING = "rateLimit";
    private static final String MAX_HISTORY_SETTING = "maxHistory";
    private static final String REPEATER_PREFIX_SETTING = "repeaterPrefix";
    private static final String FOLLOW_LATEST_SETTING = "followLatest";
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
    private final TableRowSorter<ResultTableModel> resultSorter =
            new TableRowSorter<ResultTableModel>(resultModel);
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
    private final JButton exportMessagesButton = new JButton("Export Messages");
    private final JButton saveRulesButton = new JButton("Save Rules");
    private final JButton resetRulesButton = new JButton("Reset Rules");
    private final JButton applyRuleTemplateButton = new JButton("Apply Template");
    private final JButton selectAllCategoriesButton = new JButton("All");
    private final JButton clearCategoriesButton = new JButton("None");
    private final JButton previousHistoryButton = new JButton("Previous");
    private final JButton nextHistoryButton = new JButton("Next");
    private final JButton sendCurrentRepeaterButton = new JButton("Send current to Repeater");
    private final JButton sendSelectedRepeaterButton = new JButton("Send selected rows to Repeater");
    private final JButton sendInterestingRepeaterButton = new JButton("Send interesting to Repeater");
    private final JButton markInterestingButton = new JButton("Mark interesting");
    private final JCheckBox followLatestCheckBox = new JCheckBox("Follow latest", true);
    private final JComboBox<EncodingStrategy> encodingCombo =
            new JComboBox<EncodingStrategy>(EncodingStrategy.values());
    private final JComboBox<RateLimit> rateLimitCombo =
            new JComboBox<RateLimit>(RateLimit.values());
    private final JComboBox<String> endpointCombo = new JComboBox<String>();
    private final JTextField maxHistoryField = new JTextField("500", 4);
    private final JTextField repeaterCaptionPrefixField = new JTextField(10);
    private final JTextField keywordField = new JTextField(24);
    private final JTextField resultFilterField = new JTextField(16);
    private final JCheckBox filterHitsCheckBox = new JCheckBox("Hits");
    private final JCheckBox filterInterestingCheckBox = new JCheckBox("Interesting");
    private final JComboBox<String> statusFilterCombo = new JComboBox<String>(
            new String[] {"All statuses", "Errors", "2xx", "3xx", "4xx", "5xx"});
    private final JComboBox<String> exportScopeCombo = new JComboBox<String>(
            new String[] {"All", "Selected", "Interesting"});
    private final JComboBox<HitRuleTemplate> hitRuleTemplateCombo =
            new JComboBox<HitRuleTemplate>(HitRuleTemplate.values());
    private final JLabel resultSummaryLabel = new JLabel("Results: 0");
    private final JLabel historyPositionLabel = new JLabel("#000 / 0");
    private final JLabel historyCategoryLabel = new JLabel("Category: -");
    private final JLabel historyParamLabel = new JLabel("Param: -");
    private final JLabel historyPayloadLabel = new JLabel("Payload: -");
    private final IMessageEditor requestViewer;
    private final IMessageEditor responseViewer;
    private JTabbedPane mainTabs;

    private final Object pauseLock = new Object();
    private final HistoryStore historyStore = new HistoryStore(500);
    private Map<String, List<String>> parsedPayloads = new LinkedHashMap<String, List<String>>();
    private SwingWorker<Void, RunnerResult> activeWorker;
    private HistoryRecord currentHistoryRecord;
    private boolean updatingEndpointCombo;
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
        loadUiSettings();
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
        rulesButtonPanel.add(hitRuleTemplateCombo);
        rulesButtonPanel.add(applyRuleTemplateButton);
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
        rateLimitCombo.setSelectedItem(RateLimit.MEDIUM);
        configButtonRow.add(new JLabel("Rate"));
        configButtonRow.add(rateLimitCombo);
        configButtonRow.add(new JLabel("Max history"));
        configButtonRow.add(maxHistoryField);
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

        resultTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        resultTable.setAutoCreateRowSorter(false);
        resultTable.setRowSorter(resultSorter);
        configureResultColumns(resultTable.getColumnModel());
        JPanel resultPanel = new JPanel(new BorderLayout(4, 4));
        resultPanel.setBorder(BorderFactory.createTitledBorder("Results"));
        resultPanel.add(new JScrollPane(resultTable), BorderLayout.CENTER);

        Component requestComponent = requestViewer.getComponent();
        Component responseComponent = responseViewer.getComponent();
        JSplitPane messageSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestComponent, responseComponent);
        messageSplit.setResizeWeight(0.5);
        messageSplit.setPreferredSize(new Dimension(900, 280));

        JPanel historyHeaderPanel = new JPanel(new BorderLayout(4, 4));
        historyHeaderPanel.setBorder(BorderFactory.createTitledBorder("Request History"));
        JPanel historyNavPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        historyNavPanel.add(new JLabel("Endpoint"));
        endpointCombo.setPrototypeDisplayValue("POST https://example.com:443/api/search");
        historyNavPanel.add(endpointCombo);
        historyNavPanel.add(previousHistoryButton);
        historyNavPanel.add(nextHistoryButton);
        historyNavPanel.add(historyPositionLabel);
        historyNavPanel.add(followLatestCheckBox);
        JPanel historyMetaPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        historyMetaPanel.add(historyCategoryLabel);
        historyMetaPanel.add(historyParamLabel);
        historyMetaPanel.add(historyPayloadLabel);
        historyHeaderPanel.add(historyNavPanel, BorderLayout.NORTH);
        historyHeaderPanel.add(historyMetaPanel, BorderLayout.SOUTH);

        JPanel historyViewerPanel = new JPanel(new BorderLayout(4, 4));
        historyViewerPanel.add(historyHeaderPanel, BorderLayout.NORTH);
        historyViewerPanel.add(messageSplit, BorderLayout.CENTER);

        JSplitPane lowerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, resultPanel, historyViewerPanel);
        lowerSplit.setResizeWeight(0.45);
        lowerSplit.setContinuousLayout(true);

        JPanel resultControlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        resultControlPanel.add(pauseButton);
        resultControlPanel.add(stopButton);
        resultControlPanel.add(markInterestingButton);
        resultControlPanel.add(new JLabel("Repeater prefix"));
        resultControlPanel.add(repeaterCaptionPrefixField);
        resultControlPanel.add(sendCurrentRepeaterButton);
        resultControlPanel.add(sendSelectedRepeaterButton);
        resultControlPanel.add(sendInterestingRepeaterButton);
        resultControlPanel.add(clearResultsButton);
        resultControlPanel.add(exportScopeCombo);
        resultControlPanel.add(exportButton);
        resultControlPanel.add(exportMessagesButton);

        JPanel resultFilterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        resultFilterPanel.add(new JLabel("Filter"));
        resultFilterPanel.add(resultFilterField);
        resultFilterPanel.add(filterHitsCheckBox);
        resultFilterPanel.add(filterInterestingCheckBox);
        resultFilterPanel.add(statusFilterCombo);
        resultFilterPanel.add(resultSummaryLabel);

        JPanel resultTopPanel = new JPanel(new BorderLayout(0, 4));
        resultTopPanel.add(resultControlPanel, BorderLayout.NORTH);
        resultTopPanel.add(resultFilterPanel, BorderLayout.SOUTH);

        JPanel resultsPage = new JPanel(new BorderLayout(6, 6));
        resultsPage.add(resultTopPanel, BorderLayout.NORTH);
        resultsPage.add(lowerSplit, BorderLayout.CENTER);

        mainTabs = new JTabbedPane();
        mainTabs.addTab("Runner", runnerPage);
        mainTabs.addTab("Results", resultsPage);

        add(mainTabs, BorderLayout.CENTER);
        add(statusLabel, BorderLayout.SOUTH);
        updateHistoryHeader();
    }

    private void configureResultColumns(TableColumnModel columns) {
        columns.getColumn(0).setPreferredWidth(44);
        columns.getColumn(1).setPreferredWidth(260);
        columns.getColumn(2).setPreferredWidth(58);
        columns.getColumn(3).setPreferredWidth(140);
        columns.getColumn(4).setPreferredWidth(180);
        columns.getColumn(5).setPreferredWidth(120);
        columns.getColumn(6).setPreferredWidth(90);
        columns.getColumn(7).setPreferredWidth(220);
        columns.getColumn(8).setPreferredWidth(90);
        columns.getColumn(9).setPreferredWidth(120);
        columns.getColumn(10).setPreferredWidth(90);
        columns.getColumn(11).setPreferredWidth(130);
        columns.getColumn(12).setPreferredWidth(80);
        columns.getColumn(13).setPreferredWidth(80);
        columns.getColumn(14).setPreferredWidth(80);
    }

    private void wireActions() {
        parseButton.addActionListener(event -> parseYamlIntoCategories(true));
        savePayloadsButton.addActionListener(event -> savePayloads());
        resetPayloadsButton.addActionListener(event -> resetPayloads());
        applyRuleTemplateButton.addActionListener(event -> applyRuleTemplate());
        saveRulesButton.addActionListener(event -> saveRules());
        resetRulesButton.addActionListener(event -> resetRules());
        selectAllCategoriesButton.addActionListener(event -> selectAllCategories());
        clearCategoriesButton.addActionListener(event -> clearCategorySelection());
        runButton.addActionListener(event -> runSelectedCategories());
        pauseButton.addActionListener(event -> togglePause());
        previousHistoryButton.addActionListener(event -> previousHistory());
        nextHistoryButton.addActionListener(event -> nextHistory());
        endpointCombo.addActionListener(event -> {
            if (!updatingEndpointCombo) {
                showEndpointCurrentRecord((String) endpointCombo.getSelectedItem());
            }
        });
        followLatestCheckBox.addActionListener(event -> saveUiSettings());
        markInterestingButton.addActionListener(event -> toggleInteresting());
        sendCurrentRepeaterButton.addActionListener(event -> sendCurrentToRepeater());
        sendSelectedRepeaterButton.addActionListener(event -> sendSelectedRowsToRepeater());
        sendInterestingRepeaterButton.addActionListener(event -> sendInterestingToRepeater());
        addResultFilterListener();
        filterHitsCheckBox.addActionListener(event -> applyResultFilters());
        filterInterestingCheckBox.addActionListener(event -> applyResultFilters());
        statusFilterCombo.addActionListener(event -> applyResultFilters());
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
            historyStore.clear();
            currentHistoryRecord = null;
            clearEndpointCombo();
            showHistoryRecord(null);
            updateResultSummary();
            statusLabel.setText("Results cleared.");
        });
        exportButton.addActionListener(event -> exportResults());
        exportMessagesButton.addActionListener(event -> exportMessages());
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

    private void clearEndpointCombo() {
        updatingEndpointCombo = true;
        try {
            endpointCombo.removeAllItems();
        } finally {
            updatingEndpointCombo = false;
        }
    }

    private void updateEndpointCombo() {
        String selected = currentHistoryRecord == null
                ? (String) endpointCombo.getSelectedItem()
                : currentHistoryRecord.getEndpointKey();
        List<String> endpointKeys = historyStore.endpointKeys();
        updatingEndpointCombo = true;
        try {
            endpointCombo.removeAllItems();
            for (String endpointKey : endpointKeys) {
                endpointCombo.addItem(endpointKey);
            }
            if (selected != null && endpointKeys.contains(selected)) {
                endpointCombo.setSelectedItem(selected);
            } else if (!endpointKeys.isEmpty()) {
                endpointCombo.setSelectedIndex(0);
            }
        } finally {
            updatingEndpointCombo = false;
        }
    }

    private boolean shouldShowNewRecord(HistoryRecord record) {
        return currentHistoryRecord == null || followLatestCheckBox.isSelected();
    }

    private void showEndpointCurrentRecord(String endpointKey) {
        if (endpointKey == null || endpointKey.isEmpty()) {
            showHistoryRecord(null);
            return;
        }
        showHistoryRecord(historyStore.currentRecord(endpointKey));
    }

    private void previousHistory() {
        String endpointKey = currentEndpointKey();
        if (endpointKey == null) {
            return;
        }
        showHistoryRecord(historyStore.previous(endpointKey));
    }

    private void nextHistory() {
        String endpointKey = currentEndpointKey();
        if (endpointKey == null) {
            return;
        }
        showHistoryRecord(historyStore.next(endpointKey));
    }

    private String currentEndpointKey() {
        if (currentHistoryRecord != null) {
            return currentHistoryRecord.getEndpointKey();
        }
        Object selected = endpointCombo.getSelectedItem();
        return selected == null ? null : selected.toString();
    }

    private void showHistoryRecord(HistoryRecord record) {
        currentHistoryRecord = record;
        if (record == null) {
            requestViewer.setMessage(null, true);
            responseViewer.setMessage(null, false);
            updateHistoryHeader();
            return;
        }

        historyStore.select(record);
        if (endpointCombo.getItemCount() == 0) {
            updateEndpointCombo();
        }
        updatingEndpointCombo = true;
        try {
            endpointCombo.setSelectedItem(record.getEndpointKey());
        } finally {
            updatingEndpointCombo = false;
        }
        requestViewer.setMessage(record.getRequestBytes(), true);
        responseViewer.setMessage(record.getResponseBytes(), false);
        updateHistoryHeader();
    }

    private void updateHistoryHeader() {
        if (currentHistoryRecord == null) {
            historyPositionLabel.setText("#000 / 0");
            historyCategoryLabel.setText("Category: -");
            historyParamLabel.setText("Param: -");
            historyPayloadLabel.setText("Payload: -");
            previousHistoryButton.setEnabled(false);
            nextHistoryButton.setEnabled(false);
            sendCurrentRepeaterButton.setEnabled(false);
            markInterestingButton.setEnabled(false);
            markInterestingButton.setText("Mark interesting");
            return;
        }

        int index = historyStore.indexOf(currentHistoryRecord);
        int size = historyStore.size(currentHistoryRecord.getEndpointKey());
        if (index >= 0) {
            historyPositionLabel.setText("#" + pad3(index + 1) + " / " + size);
        } else {
            historyPositionLabel.setText("#- / " + size);
        }
        historyCategoryLabel.setText("Category: " + currentHistoryRecord.getCategory());
        historyParamLabel.setText("Param: " + currentHistoryRecord.getParameterName());
        historyPayloadLabel.setText("Payload: " + currentHistoryRecord.payloadPreview());
        previousHistoryButton.setEnabled(index > 0);
        nextHistoryButton.setEnabled(index >= 0 && index < size - 1);
        sendCurrentRepeaterButton.setEnabled(true);
        markInterestingButton.setEnabled(true);
        markInterestingButton.setText(currentHistoryRecord.isInteresting()
                ? "Unmark interesting"
                : "Mark interesting");
    }

    private String pad3(int value) {
        if (value < 0) {
            value = 0;
        }
        if (value >= 1000) {
            return Integer.toString(value);
        }
        String text = Integer.toString(value);
        StringBuilder padded = new StringBuilder();
        for (int i = text.length(); i < 3; i++) {
            padded.append('0');
        }
        return padded.append(text).toString();
    }

    private void toggleInteresting() {
        if (currentHistoryRecord == null) {
            statusLabel.setText("Select a history record first.");
            return;
        }
        currentHistoryRecord.setInteresting(!currentHistoryRecord.isInteresting());
        resultModel.fireRecordUpdated(currentHistoryRecord);
        updateHistoryHeader();
        applyResultFilters();
        statusLabel.setText(currentHistoryRecord.isInteresting()
                ? "Marked current history record interesting."
                : "Unmarked current history record.");
    }

    private void sendCurrentToRepeater() {
        if (currentHistoryRecord == null) {
            statusLabel.setText("Select a history record first.");
            return;
        }
        sendRecordsToRepeater(singleton(currentHistoryRecord), "current history record");
    }

    private void sendSelectedRowsToRepeater() {
        List<HistoryRecord> records = selectedResultRecords();
        if (records.isEmpty()) {
            statusLabel.setText("Select result row(s) to send to Repeater.");
            return;
        }
        sendRecordsToRepeater(records, "selected result row(s)");
    }

    private void sendInterestingToRepeater() {
        List<HistoryRecord> records = new ArrayList<HistoryRecord>();
        for (RunnerResult result : resultModel.snapshot()) {
            HistoryRecord record = result.getHistoryRecord();
            if (record.isInteresting()) {
                records.add(record);
            }
        }
        if (records.isEmpty()) {
            statusLabel.setText("No interesting history records to send.");
            return;
        }
        sendRecordsToRepeater(records, "interesting history record(s)");
    }

    private List<HistoryRecord> singleton(HistoryRecord record) {
        List<HistoryRecord> records = new ArrayList<HistoryRecord>();
        records.add(record);
        return records;
    }

    private List<HistoryRecord> selectedResultRecords() {
        List<HistoryRecord> records = new ArrayList<HistoryRecord>();
        int[] rows = resultTable.getSelectedRows();
        for (int row : rows) {
            int modelRow = resultTable.convertRowIndexToModel(row);
            records.add(resultModel.getResult(modelRow).getHistoryRecord());
        }
        return records;
    }

    private void sendRecordsToRepeater(List<HistoryRecord> records, String label) {
        saveUiSettings();
        int sent = 0;
        String error = "";
        int batchIndex = 1;
        for (HistoryRecord record : records) {
            RepeaterSupport.SendResult result = RepeaterSupport.sendRecord(callbacks, record,
                    batchIndex++, repeaterCaptionPrefixField.getText());
            if (result.isSent()) {
                sent++;
                resultModel.fireRecordUpdated(record);
            } else if (error.isEmpty()) {
                error = result.getError();
            }
        }
        if (error.isEmpty()) {
            statusLabel.setText("Sent " + sent + " " + label + " to Repeater.");
        } else {
            statusLabel.setText("Sent " + sent + " " + label
                    + " to Repeater. Last error: " + truncateStatus(error));
        }
        updateHistoryHeader();
        updateResultSummary();
    }

    private void addResultFilterListener() {
        resultFilterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent event) {
                applyResultFilters();
            }

            @Override
            public void removeUpdate(DocumentEvent event) {
                applyResultFilters();
            }

            @Override
            public void changedUpdate(DocumentEvent event) {
                applyResultFilters();
            }
        });
    }

    private void applyResultFilters() {
        final String text = resultFilterField.getText() == null
                ? ""
                : resultFilterField.getText().trim().toLowerCase();
        final boolean onlyHits = filterHitsCheckBox.isSelected();
        final boolean onlyInteresting = filterInterestingCheckBox.isSelected();
        final String statusFilter = statusFilterCombo.getSelectedItem() == null
                ? "All statuses"
                : statusFilterCombo.getSelectedItem().toString();

        resultSorter.setRowFilter(new RowFilter<ResultTableModel, Integer>() {
            @Override
            public boolean include(RowFilter.Entry<? extends ResultTableModel, ? extends Integer> entry) {
                RunnerResult result = entry.getModel().getResult(entry.getIdentifier().intValue());
                HistoryRecord record = result.getHistoryRecord();
                if (onlyHits && result.getHitMatch().trim().isEmpty()) {
                    return false;
                }
                if (onlyInteresting && !record.isInteresting()) {
                    return false;
                }
                if (!matchesStatusFilter(result, statusFilter)) {
                    return false;
                }
                return matchesResultText(result, text);
            }
        });
        updateResultSummary();
    }

    private boolean matchesStatusFilter(RunnerResult result, String statusFilter) {
        if ("All statuses".equals(statusFilter)) {
            return true;
        }
        if ("Errors".equals(statusFilter)) {
            return result.getError() != null || result.getStatusCode() < 0;
        }
        int statusCode = result.getStatusCode();
        if (statusCode < 0 || statusFilter.length() < 1) {
            return false;
        }
        char expectedHundreds = statusFilter.charAt(0);
        return Character.isDigit(expectedHundreds)
                && statusCode / 100 == Character.digit(expectedHundreds, 10);
    }

    private boolean matchesResultText(RunnerResult result, String text) {
        if (text.isEmpty()) {
            return true;
        }
        HistoryRecord record = result.getHistoryRecord();
        String haystack = (record.getEndpointKey() + " " + result.getParameterName() + " "
                + result.getCategory() + " " + result.getPayload() + " "
                + result.getHitMatch() + " " + result.getDiffSummary() + " "
                + result.getStatusCode()).toLowerCase();
        return haystack.contains(text);
    }

    private void updateResultSummary() {
        int total = resultModel.getRowCount();
        int visible = resultTable.getRowCount();
        int hits = 0;
        int interesting = 0;
        int errors = 0;
        for (RunnerResult result : resultModel.snapshot()) {
            if (!result.getHitMatch().trim().isEmpty()) {
                hits++;
            }
            if (result.getHistoryRecord().isInteresting()) {
                interesting++;
            }
            if (result.getError() != null || result.getStatusCode() < 0) {
                errors++;
            }
        }
        resultSummaryLabel.setText("Results: " + visible + " / " + total
                + " visible, hits " + hits + ", interesting " + interesting
                + ", errors " + errors);
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

    private void loadUiSettings() {
        String savedEncoding = callbacks.loadExtensionSetting(ENCODING_SETTING);
        if (savedEncoding != null) {
            try {
                encodingCombo.setSelectedItem(EncodingStrategy.valueOf(savedEncoding));
            } catch (IllegalArgumentException ignored) {
                // Ignore settings saved by a newer or edited build.
            }
        }

        String savedRate = callbacks.loadExtensionSetting(RATE_SETTING);
        if (savedRate != null) {
            try {
                rateLimitCombo.setSelectedItem(RateLimit.valueOf(savedRate));
            } catch (IllegalArgumentException ignored) {
                // Ignore settings saved by a newer or edited build.
            }
        }

        String savedMaxHistory = callbacks.loadExtensionSetting(MAX_HISTORY_SETTING);
        if (savedMaxHistory != null && !savedMaxHistory.trim().isEmpty()) {
            maxHistoryField.setText(savedMaxHistory.trim());
        }

        String savedRepeaterPrefix = callbacks.loadExtensionSetting(REPEATER_PREFIX_SETTING);
        if (savedRepeaterPrefix != null) {
            repeaterCaptionPrefixField.setText(savedRepeaterPrefix);
        }

        String savedFollowLatest = callbacks.loadExtensionSetting(FOLLOW_LATEST_SETTING);
        if (savedFollowLatest != null && !savedFollowLatest.trim().isEmpty()) {
            followLatestCheckBox.setSelected(Boolean.parseBoolean(savedFollowLatest));
        }
    }

    private void saveUiSettings() {
        EncodingStrategy encodingStrategy = (EncodingStrategy) encodingCombo.getSelectedItem();
        RateLimit rateLimit = (RateLimit) rateLimitCombo.getSelectedItem();
        callbacks.saveExtensionSetting(ENCODING_SETTING,
                encodingStrategy == null ? EncodingStrategy.URL_ENCODE.name() : encodingStrategy.name());
        callbacks.saveExtensionSetting(RATE_SETTING,
                rateLimit == null ? RateLimit.MEDIUM.name() : rateLimit.name());
        callbacks.saveExtensionSetting(MAX_HISTORY_SETTING, maxHistoryField.getText().trim());
        callbacks.saveExtensionSetting(REPEATER_PREFIX_SETTING, repeaterCaptionPrefixField.getText());
        callbacks.saveExtensionSetting(FOLLOW_LATEST_SETTING,
                Boolean.toString(followLatestCheckBox.isSelected()));
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

    private void applyRuleTemplate() {
        HitRuleTemplate template = (HitRuleTemplate) hitRuleTemplateCombo.getSelectedItem();
        if (template == null) {
            return;
        }
        rulesArea.setText(template.getRules());
        statusLabel.setText("Applied hit rule template: " + template + ".");
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
        final RateLimit rateLimit = (RateLimit) rateLimitCombo.getSelectedItem();
        int maxHistoryRecords;
        try {
            maxHistoryRecords = Integer.parseInt(maxHistoryField.getText().trim());
        } catch (NumberFormatException ex) {
            statusLabel.setText("Max history must be a positive integer.");
            return;
        }
        if (maxHistoryRecords <= 0) {
            statusLabel.setText("Max history must be a positive integer.");
            return;
        }
        historyStore.setMaxRecordsPerEndpoint(maxHistoryRecords);
        saveUiSettings();
        final List<HitRule> hitRules;
        try {
            hitRules = HitRule.parse(keywordField.getText(), rulesArea.getText());
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Hit rule error",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }
        int total = 0;
        int markerCount = countInsertionPoints(requests);
        int uniquePayloadCount = 0;
        int duplicatePayloadCount = 0;
        for (String category : categories) {
            List<String> payloads = parsedPayloads.get(category);
            if (payloads != null && !payloads.isEmpty()) {
                List<String> uniquePayloads = uniquePayloads(payloads);
                if (!uniquePayloads.isEmpty()) {
                    selectedPayloads.put(category, uniquePayloads);
                    uniquePayloadCount += uniquePayloads.size();
                    duplicatePayloadCount += payloads.size() - uniquePayloads.size();
                    total += markerCount * uniquePayloads.size();
                }
            }
        }
        if (total == 0) {
            statusLabel.setText("Selected categories contain no payloads.");
            return;
        }
        final int totalRequests = total;
        final int duplicatePayloadsSkipped = duplicatePayloadCount;
        final String planSummary = categories.size() + " categor"
                + (categories.size() == 1 ? "y" : "ies") + ", "
                + uniquePayloadCount + " unique payload(s), "
                + markerCount + " marker(s)";

        setRunning(true);
        paused = false;
        statusLabel.setText("Running 0 / " + totalRequests + " payload request(s) at "
                + rateLimit + " rate (" + planSummary + duplicateSummary(duplicatePayloadsSkipped)
                + ")...");
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
                                if (attempted > 0 && !waitForRateLimit(rateLimit)) {
                                    return null;
                                }
                                int variantIndex = ++attempted;
                                publish(sendPayload(template, insertionPoint, category, payload,
                                        encodingStrategy, hitRules, variantIndex));
                            }
                        }
                    }
                }
                return null;
            }

            @Override
            protected void process(List<RunnerResult> chunks) {
                int droppedHistoryRecords = 0;
                for (RunnerResult result : chunks) {
                    completed++;
                    resultModel.addResult(result);
                    HistoryStore.AppendResult appendResult =
                            historyStore.append(result.getHistoryRecord());
                    droppedHistoryRecords += appendResult.getDroppedCount();
                    updateEndpointCombo();
                    if (shouldShowNewRecord(result.getHistoryRecord())) {
                        historyStore.select(result.getHistoryRecord());
                        showHistoryRecord(result.getHistoryRecord());
                    } else if (currentHistoryRecord != null
                            && historyStore.indexOf(currentHistoryRecord) < 0) {
                        showHistoryRecord(historyStore.currentRecord(
                                currentHistoryRecord.getEndpointKey()));
                    } else {
                        updateHistoryHeader();
                    }
                }
                updateResultSummary();
                String status = "Running " + completed + " / " + totalRequests
                        + " payload request(s) at " + rateLimit + " rate (" + planSummary
                        + duplicateSummary(duplicatePayloadsSkipped) + ")...";
                if (droppedHistoryRecords > 0) {
                    status += " Dropped " + droppedHistoryRecords
                            + " old history record(s) due to max history.";
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
            List<HitRule> hitRules, int variantIndex) {
        byte[] request = insertionPoint.buildRequest(payload, encodingStrategy);
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
        HistoryRecord historyRecord = new HistoryRecord(historyStore.nextId(), template,
                insertionPoint.getName(), category, payload, request, response, statusCode,
                responseLength, elapsedMillis, System.currentTimeMillis());
        return new RunnerResult(template, historyRecord, hitMatch, responseDiff.summary(), error);
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

    private List<String> uniquePayloads(List<String> payloads) {
        Map<String, Boolean> seen = new LinkedHashMap<String, Boolean>();
        for (String payload : payloads) {
            if (!seen.containsKey(payload)) {
                seen.put(payload, Boolean.TRUE);
            }
        }
        return new ArrayList<String>(seen.keySet());
    }

    private String duplicateSummary(int duplicatePayloadsSkipped) {
        if (duplicatePayloadsSkipped <= 0) {
            return "";
        }
        return ", skipped " + duplicatePayloadsSkipped + " duplicate payload(s)";
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
        applyRuleTemplateButton.setEnabled(!running);
        hitRuleTemplateCombo.setEnabled(!running);
        saveRulesButton.setEnabled(!running);
        resetRulesButton.setEnabled(!running);
        selectAllCategoriesButton.setEnabled(!running);
        clearCategoriesButton.setEnabled(!running);
        runButton.setEnabled(!running);
        clearRequestsButton.setEnabled(!running);
        exportButton.setEnabled(!running);
        exportMessagesButton.setEnabled(!running);
        exportScopeCombo.setEnabled(!running);
        maxHistoryField.setEnabled(!running);
        encodingCombo.setEnabled(!running);
        rateLimitCombo.setEnabled(!running);
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

    private boolean waitForRateLimit(RateLimit rateLimit) {
        long remaining = rateLimit == null ? 0L : rateLimit.getDelayMillis();
        while (remaining > 0L) {
            if (activeWorker != null && activeWorker.isCancelled()) {
                return false;
            }
            if (!waitIfPaused()) {
                return false;
            }
            long chunk = Math.min(remaining, 100L);
            long started = System.currentTimeMillis();
            try {
                Thread.sleep(chunk);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return false;
            }
            remaining -= Math.max(1L, System.currentTimeMillis() - started);
        }
        return waitIfPaused();
    }

    private void exportResults() {
        List<RunnerResult> results = resultsForExportScope();
        if (results.isEmpty()) {
            statusLabel.setText("No " + exportScopeLabel() + " result(s) to export.");
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
            statusLabel.setText("Exported " + results.size() + " " + exportScopeLabel()
                    + " result(s) to "
                    + chooser.getSelectedFile().getAbsolutePath());
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Export error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportMessages() {
        List<RunnerResult> results = resultsForExportScope();
        if (results.isEmpty()) {
            statusLabel.setText("No " + exportScopeLabel() + " result(s) to export.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int choice = chooser.showSaveDialog(this);
        if (choice != JFileChooser.APPROVE_OPTION) {
            return;
        }

        int written = 0;
        int skipped = 0;
        File directory = chooser.getSelectedFile();
        for (int i = 0; i < results.size(); i++) {
            HistoryRecord record = results.get(i).getHistoryRecord();
            String baseName = messageExportBaseName(i + 1, record);
            try {
                if (record.getRequestBytes() != null) {
                    writeBytes(new File(directory, baseName + "-request.http"),
                            record.getRequestBytes());
                    written++;
                } else {
                    skipped++;
                }
                if (record.getResponseBytes() != null) {
                    writeBytes(new File(directory, baseName + "-response.http"),
                            record.getResponseBytes());
                    written++;
                }
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), "Export error",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
        }
        statusLabel.setText("Exported " + written + " message file(s) to "
                + directory.getAbsolutePath() + (skipped > 0
                ? "; skipped " + skipped + " dropped request(s)."
                : "."));
    }

    private List<RunnerResult> resultsForExportScope() {
        String scope = exportScopeCombo.getSelectedItem() == null
                ? "All"
                : exportScopeCombo.getSelectedItem().toString();
        if ("Selected".equals(scope)) {
            return selectedResults();
        }
        if ("Interesting".equals(scope)) {
            List<RunnerResult> results = new ArrayList<RunnerResult>();
            for (RunnerResult result : resultModel.snapshot()) {
                if (result.getHistoryRecord().isInteresting()) {
                    results.add(result);
                }
            }
            return results;
        }
        return resultModel.snapshot();
    }

    private List<RunnerResult> selectedResults() {
        List<RunnerResult> results = new ArrayList<RunnerResult>();
        int[] rows = resultTable.getSelectedRows();
        for (int row : rows) {
            results.add(resultModel.getResult(resultTable.convertRowIndexToModel(row)));
        }
        return results;
    }

    private String exportScopeLabel() {
        return exportScopeCombo.getSelectedItem() == null
                ? "all"
                : exportScopeCombo.getSelectedItem().toString().toLowerCase();
    }

    private void writeBytes(File file, byte[] data) throws IOException {
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write(data);
        }
    }

    private String messageExportBaseName(int index, HistoryRecord record) {
        String label = index + "-" + record.getMethod() + "-" + record.getEndpointPath()
                + "-" + record.getCategory() + "-" + record.getParameterName();
        return sanitizeFileName(label);
    }

    private String sanitizeFileName(String value) {
        String sanitized = value.replaceAll("[^A-Za-z0-9._-]+", "_");
        if (sanitized.length() > 96) {
            return sanitized.substring(0, 96);
        }
        return sanitized.isEmpty() ? "payload-runner-message" : sanitized;
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
            showHistoryRecord(null);
            return;
        }
        int modelRow = resultTable.convertRowIndexToModel(viewRow);
        HistoryRecord record = resultModel.getResult(modelRow).getHistoryRecord();
        showHistoryRecord(record);
        if (!record.hasRequestBytes()) {
            statusLabel.setText("Request/response bytes for this result were dropped due to max history.");
        }
    }

    @Override
    public IHttpService getHttpService() {
        if (currentHistoryRecord == null) {
            return null;
        }
        return helpers.buildHttpService(currentHistoryRecord.getHost(), currentHistoryRecord.getPort(),
                currentHistoryRecord.isUseHttps() ? "https" : "http");
    }

    @Override
    public byte[] getRequest() {
        return currentHistoryRecord == null ? null : currentHistoryRecord.getRequestBytes();
    }

    @Override
    public byte[] getResponse() {
        return currentHistoryRecord == null ? null : currentHistoryRecord.getResponseBytes();
    }
}
