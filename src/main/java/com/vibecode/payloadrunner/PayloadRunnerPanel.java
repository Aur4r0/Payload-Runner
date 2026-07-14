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
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
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
    private static final String MAX_RESPONSE_KB_SETTING = "maxResponseKb";
    private static final String REPEATER_PREFIX_SETTING = "repeaterPrefix";
    private static final String FOLLOW_LATEST_SETTING = "followLatest";
    private static final String PROFILE_INDEX_SETTING = "profileIndex";
    private static final String PROFILE_SETTING_PREFIX = "profile.";
    private static final String DEFAULT_YAML = DefaultPayloads.load();
    private static final String DEFAULT_RULES =
            "# 每行一条规则：keyword:admin、regex:uid=\\d+、status:5xx\n"
                    + "# 也支持 length>1000、diff>200、sim<90\n";

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
    private final JLabel statusLabel = new JLabel("在 Burp 请求上右键，选择“发送到 Payload Runner”即可添加任务。");
    private final JButton parseButton = new JButton("解析 YAML");
    private final JButton savePayloadsButton = new JButton("保存 Payload");
    private final JButton resetPayloadsButton = new JButton("恢复内置 Payload");
    private final JButton runButton = new JButton("运行选中项");
    private final JButton pauseButton = new JButton("暂停");
    private final JButton stopButton = new JButton("停止");
    private final JButton clearRequestsButton = new JButton("清空请求");
    private final JButton clearResultsButton = new JButton("清空结果");
    private final JButton exportButton = new JButton("导出 CSV");
    private final JButton exportMessagesButton = new JButton("导出报文");
    private final JButton saveProfileButton = new JButton("保存配置");
    private final JButton loadProfileButton = new JButton("加载配置");
    private final JButton saveRulesButton = new JButton("保存规则");
    private final JButton resetRulesButton = new JButton("重置规则");
    private final JButton applyRuleTemplateButton = new JButton("应用模板");
    private final JButton selectAllCategoriesButton = new JButton("全选");
    private final JButton clearCategoriesButton = new JButton("全不选");
    private final JButton previousHistoryButton = new JButton("上一条");
    private final JButton nextHistoryButton = new JButton("下一条");
    private final JButton sendCurrentRepeaterButton = new JButton("发送当前项到 Repeater");
    private final JButton sendSelectedRepeaterButton = new JButton("发送选中项到 Repeater");
    private final JButton sendInterestingRepeaterButton = new JButton("发送重点项到 Repeater");
    private final JButton markInterestingButton = new JButton("标记为重点");
    private final JCheckBox followLatestCheckBox = new JCheckBox("自动跟随最新结果", true);
    private final JComboBox<EncodingStrategy> encodingCombo =
            new JComboBox<EncodingStrategy>(EncodingStrategy.values());
    private final JComboBox<RateLimit> rateLimitCombo =
            new JComboBox<RateLimit>(RateLimit.values());
    private final JComboBox<String> endpointCombo = new JComboBox<String>();
    private final JComboBox<String> profileCombo = new JComboBox<String>();
    private final JTextField maxHistoryField = new JTextField("500", 4);
    private final JTextField maxResponseKbField = new JTextField("1024", 5);
    private final JTextField repeaterCaptionPrefixField = new JTextField(10);
    private final JTextField keywordField = new JTextField(24);
    private final JTextField resultFilterField = new JTextField(16);
    private final JCheckBox filterHitsCheckBox = new JCheckBox("仅看命中");
    private final JCheckBox filterInterestingCheckBox = new JCheckBox("仅看重点");
    private final JComboBox<String> statusFilterCombo = new JComboBox<String>(
            new String[] {"全部状态", "请求错误", "2xx", "3xx", "4xx", "5xx"});
    private final JComboBox<String> exportScopeCombo = new JComboBox<String>(
            new String[] {"全部结果", "选中结果", "重点结果"});
    private final JComboBox<HitRuleTemplate> hitRuleTemplateCombo =
            new JComboBox<HitRuleTemplate>(HitRuleTemplate.values());
    private final JLabel resultSummaryLabel = new JLabel("结果：0");
    private final JLabel historyPositionLabel = new JLabel("#000 / 0");
    private final JLabel historyCategoryLabel = new JLabel("分类：-");
    private final JLabel historyParamLabel = new JLabel("参数：-");
    private final JLabel historyPayloadLabel = new JLabel("Payload：-");
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
            statusLabel.setText("当前右键菜单中没有可用的 HTTP 请求。");
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
                    lastSkipReason = "没有在 URL 查询参数、表单、JSON、Multipart 或 XML 值中找到“*”标记。";
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

        String summary = "已添加 " + added + " 个请求，跳过 " + skippedNoMarker + " 个无标记请求";
        if (skippedError > 0) {
            summary += "，另有 " + skippedError + " 个请求解析失败";
        }
        if (!lastSkipReason.isEmpty()) {
            summary += "。最后一次跳过原因：" + lastSkipReason;
        } else {
            summary += "。";
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
        yamlPanel.setBorder(BorderFactory.createTitledBorder("Payload 配置（YAML）"));
        yamlPanel.add(new JScrollPane(yamlArea), BorderLayout.CENTER);
        yamlPanel.setMinimumSize(new Dimension(420, 260));

        categoryList.setVisibleRowCount(8);
        categoryList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JPanel categoryPanel = new JPanel(new BorderLayout(4, 4));
        categoryPanel.setBorder(BorderFactory.createTitledBorder("Payload 分类"));
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
        requestPanel.setBorder(BorderFactory.createTitledBorder("待执行请求"));
        requestPanel.add(new JScrollPane(requestList), BorderLayout.CENTER);
        requestPanel.setMinimumSize(new Dimension(360, 150));

        rulesArea.setLineWrap(false);
        JPanel rulesPanel = new JPanel(new BorderLayout(4, 4));
        rulesPanel.setBorder(BorderFactory.createTitledBorder("命中规则"));
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
        configButtonRow.add(new JLabel("编码方式"));
        configButtonRow.add(encodingCombo);
        rateLimitCombo.setSelectedItem(RateLimit.MEDIUM);
        configButtonRow.add(new JLabel("发送速率"));
        configButtonRow.add(rateLimitCombo);
        configButtonRow.add(new JLabel("单接口历史上限"));
        configButtonRow.add(maxHistoryField);
        configButtonRow.add(new JLabel("响应保存上限(KB)"));
        configButtonRow.add(maxResponseKbField);
        configButtonRow.add(new JLabel("命中关键词"));
        configButtonRow.add(keywordField);
        runButtonRow.add(runButton);
        runButtonRow.add(clearRequestsButton);
        runButtonRow.add(new JLabel("接口配置"));
        profileCombo.setPrototypeDisplayValue("POST https://example.com:443/api/search");
        runButtonRow.add(profileCombo);
        runButtonRow.add(saveProfileButton);
        runButtonRow.add(loadProfileButton);
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
        installResultTableActions();
        JPanel resultPanel = new JPanel(new BorderLayout(4, 4));
        resultPanel.setBorder(BorderFactory.createTitledBorder("执行结果"));
        resultPanel.add(new JScrollPane(resultTable), BorderLayout.CENTER);

        Component requestComponent = requestViewer.getComponent();
        Component responseComponent = responseViewer.getComponent();
        JSplitPane messageSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestComponent, responseComponent);
        messageSplit.setResizeWeight(0.5);
        messageSplit.setPreferredSize(new Dimension(900, 280));

        JPanel historyHeaderPanel = new JPanel(new BorderLayout(4, 4));
        historyHeaderPanel.setBorder(BorderFactory.createTitledBorder("请求历史"));
        JPanel historyNavPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        historyNavPanel.add(new JLabel("接口"));
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
        resultControlPanel.add(new JLabel("Repeater 标签前缀"));
        resultControlPanel.add(repeaterCaptionPrefixField);
        resultControlPanel.add(sendCurrentRepeaterButton);
        resultControlPanel.add(sendSelectedRepeaterButton);
        resultControlPanel.add(sendInterestingRepeaterButton);
        resultControlPanel.add(clearResultsButton);
        resultControlPanel.add(exportScopeCombo);
        resultControlPanel.add(exportButton);
        resultControlPanel.add(exportMessagesButton);

        JPanel resultFilterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        resultFilterPanel.add(new JLabel("快速筛选"));
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
        mainTabs.addTab("任务配置", runnerPage);
        mainTabs.addTab("运行结果", resultsPage);

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
        columns.getColumn(11).setPreferredWidth(60);
        columns.getColumn(12).setPreferredWidth(130);
        columns.getColumn(13).setPreferredWidth(80);
        columns.getColumn(14).setPreferredWidth(80);
        columns.getColumn(15).setPreferredWidth(80);
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
        saveProfileButton.addActionListener(event -> saveCurrentProfile());
        loadProfileButton.addActionListener(event -> loadSelectedProfile());
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
                statusLabel.setText("正在停止，等待当前请求结束……");
            }
        });
        clearRequestsButton.addActionListener(event -> {
            if (isRunnerActive()) {
                statusLabel.setText("请先停止当前任务，再清空待执行请求。");
                return;
            }
            requestModel.clear();
            statusLabel.setText("待执行请求已清空。");
        });
        clearResultsButton.addActionListener(event -> {
            resultModel.clear();
            historyStore.clear();
            currentHistoryRecord = null;
            clearEndpointCombo();
            showHistoryRecord(null);
            updateResultSummary();
            statusLabel.setText("运行结果已清空。");
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
        final JMenuItem deleteItem = new JMenuItem("删除选中请求");
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
            statusLabel.setText("请先停止当前任务，再删除待执行请求。");
            return;
        }

        int[] selected = requestList.getSelectedIndices();
        if (selected.length == 0) {
            statusLabel.setText("请先选择要删除的请求。");
            return;
        }

        int nextSelection = selected[0];
        for (int i = selected.length - 1; i >= 0; i--) {
            requestModel.remove(selected[i]);
        }
        if (requestModel.size() > 0) {
            requestList.setSelectedIndex(Math.min(nextSelection, requestModel.size() - 1));
        }
        statusLabel.setText("已删除 " + selected.length + " 个待执行请求。");
    }

    private void installResultTableActions() {
        final JPopupMenu popup = new JPopupMenu();
        JMenuItem rerunSelected = new JMenuItem("重新运行选中项");
        JMenuItem rerunFailed = new JMenuItem("重新运行失败项");
        JMenuItem rerunHits = new JMenuItem("重新运行命中项");
        JMenuItem rerunInteresting = new JMenuItem("重新运行重点项");

        rerunSelected.addActionListener(event -> rerunResults(selectedResults(), "选中结果"));
        rerunFailed.addActionListener(event -> rerunResults(failedResults(), "失败结果"));
        rerunHits.addActionListener(event -> rerunResults(hitResults(), "命中结果"));
        rerunInteresting.addActionListener(event -> rerunResults(interestingResults(), "重点结果"));

        popup.add(rerunSelected);
        popup.add(rerunFailed);
        popup.add(rerunHits);
        popup.add(rerunInteresting);

        resultTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent event) {
                showResultTablePopup(event, popup, rerunSelected, rerunFailed, rerunHits,
                        rerunInteresting);
            }

            @Override
            public void mouseReleased(MouseEvent event) {
                showResultTablePopup(event, popup, rerunSelected, rerunFailed, rerunHits,
                        rerunInteresting);
            }
        });
    }

    private void showResultTablePopup(MouseEvent event, JPopupMenu popup, JMenuItem rerunSelected,
            JMenuItem rerunFailed, JMenuItem rerunHits, JMenuItem rerunInteresting) {
        if (!event.isPopupTrigger()) {
            return;
        }
        int row = resultTable.rowAtPoint(event.getPoint());
        if (row >= 0 && !resultTable.isRowSelected(row)) {
            resultTable.setRowSelectionInterval(row, row);
        }
        boolean running = isRunnerActive();
        rerunSelected.setEnabled(!running && resultTable.getSelectedRowCount() > 0);
        rerunFailed.setEnabled(!running && !failedResults().isEmpty());
        rerunHits.setEnabled(!running && !hitResults().isEmpty());
        rerunInteresting.setEnabled(!running && !interestingResults().isEmpty());
        popup.show(resultTable, event.getX(), event.getY());
    }

    private List<RunnerResult> failedResults() {
        List<RunnerResult> results = new ArrayList<RunnerResult>();
        for (RunnerResult result : resultModel.snapshot()) {
            if (result.getError() != null || result.getStatusCode() < 0) {
                results.add(result);
            }
        }
        return results;
    }

    private List<RunnerResult> hitResults() {
        List<RunnerResult> results = new ArrayList<RunnerResult>();
        for (RunnerResult result : resultModel.snapshot()) {
            if (!result.getHitMatch().trim().isEmpty()) {
                results.add(result);
            }
        }
        return results;
    }

    private List<RunnerResult> interestingResults() {
        List<RunnerResult> results = new ArrayList<RunnerResult>();
        for (RunnerResult result : resultModel.snapshot()) {
            if (result.getHistoryRecord().isInteresting()) {
                results.add(result);
            }
        }
        return results;
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
            historyCategoryLabel.setText("分类：-");
            historyParamLabel.setText("参数：-");
            historyPayloadLabel.setText("Payload：-");
            previousHistoryButton.setEnabled(false);
            nextHistoryButton.setEnabled(false);
            sendCurrentRepeaterButton.setEnabled(false);
            markInterestingButton.setEnabled(false);
            markInterestingButton.setText("标记为重点");
            return;
        }

        int index = historyStore.indexOf(currentHistoryRecord);
        int size = historyStore.size(currentHistoryRecord.getEndpointKey());
        if (index >= 0) {
            historyPositionLabel.setText("#" + pad3(index + 1) + " / " + size);
        } else {
            historyPositionLabel.setText("#- / " + size);
        }
        historyCategoryLabel.setText("分类：" + currentHistoryRecord.getCategory());
        historyParamLabel.setText("参数：" + currentHistoryRecord.getParameterName());
        historyPayloadLabel.setText("Payload：" + currentHistoryRecord.payloadPreview());
        previousHistoryButton.setEnabled(index > 0);
        nextHistoryButton.setEnabled(index >= 0 && index < size - 1);
        sendCurrentRepeaterButton.setEnabled(true);
        markInterestingButton.setEnabled(true);
        markInterestingButton.setText(currentHistoryRecord.isInteresting()
                ? "取消重点标记"
                : "标记为重点");
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
            statusLabel.setText("请先选择一条历史记录。");
            return;
        }
        currentHistoryRecord.setInteresting(!currentHistoryRecord.isInteresting());
        resultModel.fireRecordUpdated(currentHistoryRecord);
        updateHistoryHeader();
        applyResultFilters();
        statusLabel.setText(currentHistoryRecord.isInteresting()
                ? "已将当前记录标记为重点。"
                : "已取消当前记录的重点标记。");
    }

    private void sendCurrentToRepeater() {
        if (currentHistoryRecord == null) {
            statusLabel.setText("请先选择一条历史记录。");
            return;
        }
        sendRecordsToRepeater(singleton(currentHistoryRecord), "当前记录");
    }

    private void sendSelectedRowsToRepeater() {
        List<HistoryRecord> records = selectedResultRecords();
        if (records.isEmpty()) {
            statusLabel.setText("请先选择要发送到 Repeater 的结果。");
            return;
        }
        sendRecordsToRepeater(records, "选中结果");
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
            statusLabel.setText("当前没有可发送的重点记录。");
            return;
        }
        sendRecordsToRepeater(records, "重点记录");
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
            statusLabel.setText("已将 " + sent + " 条" + label + "发送到 Repeater。");
        } else {
            statusLabel.setText("已将 " + sent + " 条" + label
                    + "发送到 Repeater。最后一个错误：" + truncateStatus(error));
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
                ? "全部状态"
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
        if ("全部状态".equals(statusFilter)) {
            return true;
        }
        if ("请求错误".equals(statusFilter)) {
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
                + result.getScore() + " " + result.getStatusCode()).toLowerCase();
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
        resultSummaryLabel.setText("结果：显示 " + visible + " / 共 " + total
                + "，命中 " + hits + "，重点 " + interesting + "，错误 " + errors);
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
            statusLabel.setText("已加载 " + parsedPayloads.size()
                    + " 个 Payload 分类，请选择一个或多个分类后运行。");
            return true;
        } catch (IllegalArgumentException ex) {
            statusLabel.setText("YAML 格式错误：" + ex.getMessage());
            if (showDialogOnError) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), "YAML 格式错误",
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
            statusLabel.setText("尚未加载任何 Payload 分类。");
            return;
        }
        categoryList.setSelectionInterval(0, categoryModel.size() - 1);
        statusLabel.setText("已选择全部 " + categoryModel.size() + " 个 Payload 分类。");
    }

    private void clearCategorySelection() {
        categoryList.clearSelection();
        statusLabel.setText("已取消选择所有 Payload 分类。");
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

        String savedMaxResponseKb = callbacks.loadExtensionSetting(MAX_RESPONSE_KB_SETTING);
        if (savedMaxResponseKb != null && !savedMaxResponseKb.trim().isEmpty()) {
            maxResponseKbField.setText(savedMaxResponseKb.trim());
        }

        String savedRepeaterPrefix = callbacks.loadExtensionSetting(REPEATER_PREFIX_SETTING);
        if (savedRepeaterPrefix != null) {
            repeaterCaptionPrefixField.setText(savedRepeaterPrefix);
        }

        String savedFollowLatest = callbacks.loadExtensionSetting(FOLLOW_LATEST_SETTING);
        if (savedFollowLatest != null && !savedFollowLatest.trim().isEmpty()) {
            followLatestCheckBox.setSelected(Boolean.parseBoolean(savedFollowLatest));
        }
        loadProfilesIntoCombo();
    }

    private void saveUiSettings() {
        EncodingStrategy encodingStrategy = (EncodingStrategy) encodingCombo.getSelectedItem();
        RateLimit rateLimit = (RateLimit) rateLimitCombo.getSelectedItem();
        callbacks.saveExtensionSetting(ENCODING_SETTING,
                encodingStrategy == null ? EncodingStrategy.URL_ENCODE.name() : encodingStrategy.name());
        callbacks.saveExtensionSetting(RATE_SETTING,
                rateLimit == null ? RateLimit.MEDIUM.name() : rateLimit.name());
        callbacks.saveExtensionSetting(MAX_HISTORY_SETTING, maxHistoryField.getText().trim());
        callbacks.saveExtensionSetting(MAX_RESPONSE_KB_SETTING, maxResponseKbField.getText().trim());
        callbacks.saveExtensionSetting(REPEATER_PREFIX_SETTING, repeaterCaptionPrefixField.getText());
        callbacks.saveExtensionSetting(FOLLOW_LATEST_SETTING,
                Boolean.toString(followLatestCheckBox.isSelected()));
    }

    private void loadProfilesIntoCombo() {
        Object selected = profileCombo.getSelectedItem();
        profileCombo.removeAllItems();
        List<String> endpointKeys = profileIndex();
        for (String endpointKey : endpointKeys) {
            profileCombo.addItem(endpointKey);
        }
        if (selected != null && endpointKeys.contains(selected.toString())) {
            profileCombo.setSelectedItem(selected.toString());
        }
    }

    private void saveCurrentProfile() {
        if (!parseYamlIntoCategories(true)) {
            return;
        }
        String endpointKey = selectedProfileEndpointKey();
        if (endpointKey == null || endpointKey.isEmpty()) {
            statusLabel.setText("请先添加或选择一个请求，再保存接口配置。");
            return;
        }

        Properties profile = new Properties();
        profile.setProperty("endpoint", endpointKey);
        profile.setProperty("categories", joinLines(categoryList.getSelectedValuesList()));
        EncodingStrategy encodingStrategy = (EncodingStrategy) encodingCombo.getSelectedItem();
        RateLimit rateLimit = (RateLimit) rateLimitCombo.getSelectedItem();
        profile.setProperty("encoding",
                encodingStrategy == null ? EncodingStrategy.URL_ENCODE.name() : encodingStrategy.name());
        profile.setProperty("rate", rateLimit == null ? RateLimit.MEDIUM.name() : rateLimit.name());
        profile.setProperty("maxHistory", maxHistoryField.getText().trim());
        profile.setProperty("maxResponseKb", maxResponseKbField.getText().trim());
        profile.setProperty("keywords", keywordField.getText());
        profile.setProperty("rules", rulesArea.getText());
        profile.setProperty("repeaterPrefix", repeaterCaptionPrefixField.getText());
        profile.setProperty("followLatest", Boolean.toString(followLatestCheckBox.isSelected()));

        try {
            StringWriter writer = new StringWriter();
            profile.store(writer, "Payload Runner profile");
            callbacks.saveExtensionSetting(profileSettingName(endpointKey), writer.toString());
            saveProfileIndex(endpointKey);
            loadProfilesIntoCombo();
            profileCombo.setSelectedItem(endpointKey);
            saveUiSettings();
            statusLabel.setText("已保存接口配置：" + endpointKey + "。");
        } catch (IOException ex) {
            statusLabel.setText("接口配置保存失败：" + truncateStatus(ex.getMessage()));
        }
    }

    private void loadSelectedProfile() {
        String endpointKey = profileCombo.getSelectedItem() == null
                ? selectedProfileEndpointKey()
                : profileCombo.getSelectedItem().toString();
        if (endpointKey == null || endpointKey.isEmpty()) {
            statusLabel.setText("请选择一个已保存的接口配置，或添加对应接口的请求。");
            return;
        }
        String saved = callbacks.loadExtensionSetting(profileSettingName(endpointKey));
        if (saved == null || saved.trim().isEmpty()) {
            statusLabel.setText("该接口尚未保存配置：" + endpointKey + "。");
            return;
        }

        Properties profile = new Properties();
        try {
            profile.load(new StringReader(saved));
        } catch (IOException ex) {
            statusLabel.setText("接口配置加载失败：" + truncateStatus(ex.getMessage()));
            return;
        }

        if (!parseYamlIntoCategories(true)) {
            return;
        }
        applyEnumSelection(encodingCombo, EncodingStrategy.class, profile.getProperty("encoding"),
                EncodingStrategy.URL_ENCODE);
        applyEnumSelection(rateLimitCombo, RateLimit.class, profile.getProperty("rate"),
                RateLimit.MEDIUM);
        maxHistoryField.setText(profile.getProperty("maxHistory", maxHistoryField.getText()).trim());
        maxResponseKbField.setText(profile.getProperty("maxResponseKb", maxResponseKbField.getText()).trim());
        keywordField.setText(profile.getProperty("keywords", ""));
        rulesArea.setText(profile.getProperty("rules", DEFAULT_RULES));
        repeaterCaptionPrefixField.setText(profile.getProperty("repeaterPrefix", ""));
        followLatestCheckBox.setSelected(Boolean.parseBoolean(
                profile.getProperty("followLatest", "true")));
        restoreCategorySelection(splitLines(profile.getProperty("categories", "")));
        saveUiSettings();
        statusLabel.setText("已加载接口配置：" + endpointKey + "。");
    }

    private <T extends Enum<T>> void applyEnumSelection(JComboBox<T> combo, Class<T> enumType,
            String value, T fallback) {
        if (value == null || value.trim().isEmpty()) {
            combo.setSelectedItem(fallback);
            return;
        }
        try {
            combo.setSelectedItem(Enum.valueOf(enumType, value.trim()));
        } catch (IllegalArgumentException ex) {
            combo.setSelectedItem(fallback);
        }
    }

    private List<String> profileIndex() {
        return splitLines(callbacks.loadExtensionSetting(PROFILE_INDEX_SETTING));
    }

    private void saveProfileIndex(String endpointKey) {
        List<String> endpointKeys = profileIndex();
        if (!endpointKeys.contains(endpointKey)) {
            endpointKeys.add(endpointKey);
        }
        callbacks.saveExtensionSetting(PROFILE_INDEX_SETTING, joinLines(endpointKeys));
    }

    private String profileSettingName(String endpointKey) {
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(endpointKey.getBytes(StandardCharsets.UTF_8));
        return PROFILE_SETTING_PREFIX + encoded;
    }

    private String selectedProfileEndpointKey() {
        List<RequestTemplate> selectedRequests = requestList.getSelectedValuesList();
        if (!selectedRequests.isEmpty()) {
            return endpointKeyForTemplate(selectedRequests.get(0));
        }
        if (currentHistoryRecord != null) {
            return currentHistoryRecord.getEndpointKey();
        }
        if (requestModel.size() > 0) {
            return endpointKeyForTemplate(requestModel.getElementAt(0));
        }
        Object selectedProfile = profileCombo.getSelectedItem();
        return selectedProfile == null ? "" : selectedProfile.toString();
    }

    private String endpointKeyForTemplate(RequestTemplate template) {
        if (template == null || template.getService() == null) {
            return "";
        }
        String protocol = template.getService().getProtocol();
        boolean useHttps = "https".equalsIgnoreCase(protocol);
        return template.getMethod() + " " + (useHttps ? "https" : "http") + "://"
                + template.getHost() + ":" + template.getService().getPort()
                + stripQuery(template.getPath());
    }

    private String stripQuery(String value) {
        if (value == null || value.isEmpty()) {
            return "/";
        }
        int query = value.indexOf('?');
        return query >= 0 ? value.substring(0, query) : value;
    }

    private String joinLines(List<String> values) {
        StringBuilder joined = new StringBuilder();
        for (String value : values) {
            if (value == null || value.isEmpty()) {
                continue;
            }
            if (joined.length() > 0) {
                joined.append('\n');
            }
            joined.append(value);
        }
        return joined.toString();
    }

    private List<String> splitLines(String value) {
        List<String> values = new ArrayList<String>();
        if (value == null || value.trim().isEmpty()) {
            return values;
        }
        String[] lines = value.replace("\r\n", "\n").replace('\r', '\n').split("\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                values.add(trimmed);
            }
        }
        return values;
    }

    private void savePayloads() {
        if (!parseYamlIntoCategories(true)) {
            return;
        }
        callbacks.saveExtensionSetting(PAYLOADS_SETTING, yamlArea.getText());
        statusLabel.setText("Payload YAML 已保存到 Burp 扩展配置。");
    }

    private void resetPayloads() {
        yamlArea.setText(DefaultPayloads.load());
        if (parseYamlIntoCategories(true)) {
            callbacks.saveExtensionSetting(PAYLOADS_SETTING, yamlArea.getText());
            statusLabel.setText("已恢复并保存内置 Payload YAML。");
        }
    }

    private void saveRules() {
        try {
            HitRule.parse(keywordField.getText(), rulesArea.getText());
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "命中规则错误",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }
        callbacks.saveExtensionSetting(RULES_SETTING, rulesArea.getText());
        statusLabel.setText("命中规则已保存到 Burp 扩展配置。");
    }

    private void applyRuleTemplate() {
        HitRuleTemplate template = (HitRuleTemplate) hitRuleTemplateCombo.getSelectedItem();
        if (template == null) {
            return;
        }
        rulesArea.setText(template.getRules());
        statusLabel.setText("已应用命中规则模板：“" + template + "”。");
    }

    private void resetRules() {
        rulesArea.setText(DEFAULT_RULES);
        callbacks.saveExtensionSetting(RULES_SETTING, rulesArea.getText());
        statusLabel.setText("命中规则已重置并保存。");
    }

    private void runSelectedCategories() {
        if (activeWorker != null && !activeWorker.isDone()) {
            statusLabel.setText("Payload Runner 正在运行，请等待当前任务结束。");
            return;
        }
        if (!parseYamlIntoCategories(true)) {
            return;
        }

        List<String> categories = categoryList.getSelectedValuesList();
        if (categories.isEmpty()) {
            statusLabel.setText("请至少选择一个 Payload 分类。");
            return;
        }

        List<RequestTemplate> requests = snapshotRunRequests();
        if (requests.isEmpty()) {
            statusLabel.setText("请通过 Burp 右键菜单至少添加一个请求。");
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
            statusLabel.setText("单接口历史上限必须是正整数。");
            return;
        }
        if (maxHistoryRecords <= 0) {
            statusLabel.setText("单接口历史上限必须是正整数。");
            return;
        }
        int maxResponseBytes = parseMaxResponseBytes();
        if (maxResponseBytes <= 0) {
            return;
        }
        historyStore.setMaxRecordsPerEndpoint(maxHistoryRecords);
        saveUiSettings();
        final List<HitRule> hitRules;
        try {
            hitRules = HitRule.parse(keywordField.getText(), rulesArea.getText());
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "命中规则错误",
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
            statusLabel.setText("所选分类中没有可执行的 Payload。");
            return;
        }
        final int totalRequests = total;
        final int duplicatePayloadsSkipped = duplicatePayloadCount;
        final String planSummary = categories.size() + " 个分类，"
                + uniquePayloadCount + " 个去重 Payload，"
                + markerCount + " 个标记点";

        setRunning(true);
        paused = false;
        statusLabel.setText("正在执行 0 / " + totalRequests + " 个请求，速率："
                + rateLimit + "（" + planSummary + duplicateSummary(duplicatePayloadsSkipped)
                + "）……");
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
                                        encodingStrategy, hitRules, variantIndex,
                                        maxResponseBytes));
                            }
                        }
                    }
                }
                return null;
            }

            @Override
            protected void process(List<RunnerResult> chunks) {
                completed += chunks.size();
                int droppedHistoryRecords = appendRunnerResults(chunks);
                updateResultSummary();
                String status = "正在执行 " + completed + " / " + totalRequests
                        + " 个请求，速率：" + rateLimit + "（" + planSummary
                        + duplicateSummary(duplicatePayloadsSkipped) + "）……";
                if (droppedHistoryRecords > 0) {
                    status += " 已根据历史上限释放 " + droppedHistoryRecords + " 条较早记录的报文数据。";
                }
                statusLabel.setText(status);
            }

            @Override
            protected void done() {
                setRunning(false);
                paused = false;
                pauseButton.setText("暂停");
                statusLabel.setText(isCancelled()
                        ? "任务已停止，共完成 " + completed + " 个请求。"
                        : "任务执行完成，共发送 " + completed + " 个请求。");
            }
        };
        activeWorker.execute();
    }

    private void rerunResults(List<RunnerResult> sourceResults, String label) {
        if (isRunnerActive()) {
            statusLabel.setText("Payload Runner 正在运行，请等待当前任务结束。");
            return;
        }
        if (sourceResults == null || sourceResults.isEmpty()) {
            statusLabel.setText("没有可重新运行的" + label + "。");
            return;
        }

        List<PayloadVariant> variants = new ArrayList<PayloadVariant>();
        int skipped = 0;
        for (RunnerResult result : sourceResults) {
            PayloadInsertionPoint insertionPoint = findInsertionPoint(result.getTemplate(),
                    result.getParameterName());
            if (insertionPoint == null) {
                skipped++;
                continue;
            }
            variants.add(new PayloadVariant(result.getTemplate(), insertionPoint,
                    result.getCategory(), result.getPayload()));
        }
        if (variants.isEmpty()) {
            statusLabel.setText("无法重新运行" + label + "：原请求中的标记点已不存在。");
            return;
        }

        int maxHistoryRecords;
        try {
            maxHistoryRecords = Integer.parseInt(maxHistoryField.getText().trim());
        } catch (NumberFormatException ex) {
            statusLabel.setText("单接口历史上限必须是正整数。");
            return;
        }
        if (maxHistoryRecords <= 0) {
            statusLabel.setText("单接口历史上限必须是正整数。");
            return;
        }
        int maxResponseBytes = parseMaxResponseBytes();
        if (maxResponseBytes <= 0) {
            return;
        }
        historyStore.setMaxRecordsPerEndpoint(maxHistoryRecords);
        saveUiSettings();

        final List<HitRule> hitRules;
        try {
            hitRules = HitRule.parse(keywordField.getText(), rulesArea.getText());
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "命中规则错误",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        final EncodingStrategy encodingStrategy =
                (EncodingStrategy) encodingCombo.getSelectedItem();
        final RateLimit rateLimit = (RateLimit) rateLimitCombo.getSelectedItem();
        final int totalRequests = variants.size();
        final String skippedSummary = skipped > 0
                ? "，跳过 " + skipped + " 个缺少标记点的结果"
                : "";

        setRunning(true);
        paused = false;
        statusLabel.setText("正在重新运行" + label + "：0 / " + totalRequests
                + "，速率：" + rateLimit + skippedSummary + "……");
        if (mainTabs != null) {
            mainTabs.setSelectedIndex(1);
        }

        activeWorker = new SwingWorker<Void, RunnerResult>() {
            private int completed;
            private int attempted;

            @Override
            protected Void doInBackground() {
                for (PayloadVariant variant : variants) {
                    if (isCancelled() || !waitIfPaused()) {
                        return null;
                    }
                    if (attempted > 0 && !waitForRateLimit(rateLimit)) {
                        return null;
                    }
                    int variantIndex = ++attempted;
                    publish(sendPayload(variant.template, variant.insertionPoint,
                            variant.category, variant.payload, encodingStrategy, hitRules,
                            variantIndex, maxResponseBytes));
                }
                return null;
            }

            @Override
            protected void process(List<RunnerResult> chunks) {
                completed += chunks.size();
                int droppedHistoryRecords = appendRunnerResults(chunks);
                updateResultSummary();
                String status = "正在重新运行" + label + "：" + completed + " / "
                        + totalRequests + "，速率：" + rateLimit + skippedSummary + "……";
                if (droppedHistoryRecords > 0) {
                    status += " 已根据历史上限释放 " + droppedHistoryRecords + " 条较早记录的报文数据。";
                }
                statusLabel.setText(status);
            }

            @Override
            protected void done() {
                setRunning(false);
                paused = false;
                pauseButton.setText("暂停");
                statusLabel.setText(isCancelled()
                        ? "重新运行已停止，共完成 " + completed + " 个请求。"
                        : "重新运行完成，共发送 " + completed + " 个请求。");
            }
        };
        activeWorker.execute();
    }

    private PayloadInsertionPoint findInsertionPoint(RequestTemplate template, String parameterName) {
        if (template == null) {
            return null;
        }
        for (PayloadInsertionPoint insertionPoint : template.getInsertionPoints()) {
            if (insertionPoint.getName().equals(parameterName)) {
                return insertionPoint;
            }
        }
        return null;
    }

    private int appendRunnerResults(List<RunnerResult> chunks) {
        int droppedHistoryRecords = 0;
        for (RunnerResult result : chunks) {
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
        return droppedHistoryRecords;
    }

    private RunnerResult sendPayload(RequestTemplate template, PayloadInsertionPoint insertionPoint,
            String category, String payload, EncodingStrategy encodingStrategy,
            List<HitRule> hitRules, int variantIndex, int maxResponseBytes) {
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
                responseLength, elapsedMillis, System.currentTimeMillis(), maxResponseBytes);
        int score = scoreResult(statusCode, elapsedMillis, hitMatch, responseDiff, error);
        return new RunnerResult(template, historyRecord, hitMatch, responseDiff.summary(), score, error);
    }

    private int parseMaxResponseBytes() {
        int maxResponseKb;
        try {
            maxResponseKb = Integer.parseInt(maxResponseKbField.getText().trim());
        } catch (NumberFormatException ex) {
            statusLabel.setText("响应保存上限必须是正整数。");
            return -1;
        }
        if (maxResponseKb <= 0) {
            statusLabel.setText("响应保存上限必须是正整数。");
            return -1;
        }
        long bytes = maxResponseKb * 1024L;
        if (bytes > Integer.MAX_VALUE) {
            return Integer.MAX_VALUE;
        }
        return (int) bytes;
    }

    private int scoreResult(int statusCode, long elapsedMillis, String hitMatch,
            ResponseDiff responseDiff, String error) {
        int score = 0;
        if (hitMatch != null && !hitMatch.trim().isEmpty()) {
            score += 40;
        }
        if (error != null && !error.trim().isEmpty()) {
            score += 35;
        }
        if (statusCode >= 500) {
            score += 25;
        } else if (statusCode >= 400) {
            score += 10;
        }
        if (responseDiff != null && responseDiff.isAvailable()) {
            if (responseDiff.getStatusDelta() != 0) {
                score += 25;
            }
            int lengthDelta = Math.abs(responseDiff.getLengthDelta());
            if (lengthDelta >= 1000) {
                score += 20;
            } else if (lengthDelta >= 200) {
                score += 10;
            }
            if (responseDiff.getSimilarityPercent() >= 0
                    && responseDiff.getSimilarityPercent() < 90) {
                score += 15;
            }
        }
        if (elapsedMillis >= 2000L) {
            score += 10;
        }
        return Math.min(100, Math.max(0, score));
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
        return "，已跳过 " + duplicatePayloadsSkipped + " 个重复 Payload";
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
        saveProfileButton.setEnabled(!running);
        loadProfileButton.setEnabled(!running);
        profileCombo.setEnabled(!running);
        clearRequestsButton.setEnabled(!running);
        exportButton.setEnabled(!running);
        exportMessagesButton.setEnabled(!running);
        exportScopeCombo.setEnabled(!running);
        maxHistoryField.setEnabled(!running);
        maxResponseKbField.setEnabled(!running);
        encodingCombo.setEnabled(!running);
        rateLimitCombo.setEnabled(!running);
        keywordField.setEnabled(!running);
        rulesArea.setEnabled(!running);
        pauseButton.setEnabled(running);
        stopButton.setEnabled(running);
        if (!running) {
            pauseButton.setText("暂停");
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
        pauseButton.setText(paused ? "继续" : "暂停");
        statusLabel.setText(paused ? "任务已暂停。" : "任务已继续。" );
    }

    private void resumeIfPaused() {
        synchronized (pauseLock) {
            paused = false;
            pauseLock.notifyAll();
        }
        pauseButton.setText("暂停");
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
            statusLabel.setText("没有可导出的" + exportScopeLabel() + "。");
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
            statusLabel.setText("已将 " + results.size() + " 条" + exportScopeLabel()
                    + "导出至 " + chooser.getSelectedFile().getAbsolutePath());
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "导出失败",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportMessages() {
        List<RunnerResult> results = resultsForExportScope();
        if (results.isEmpty()) {
            statusLabel.setText("没有可导出的" + exportScopeLabel() + "。");
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
        int truncatedResponses = 0;
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
                    if (record.isResponseTruncated()) {
                        truncatedResponses++;
                    }
                }
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), "导出失败",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
        }
        statusLabel.setText("已将 " + written + " 个报文文件导出至 "
                + directory.getAbsolutePath() + (skipped > 0
                ? "；跳过 " + skipped + " 个已释放报文数据的请求。"
                : "。") + (truncatedResponses > 0
                ? " 其中 " + truncatedResponses + " 个响应为截断后的内容。"
                : ""));
    }

    private List<RunnerResult> resultsForExportScope() {
        String scope = exportScopeCombo.getSelectedItem() == null
                ? "全部结果"
                : exportScopeCombo.getSelectedItem().toString();
        if ("选中结果".equals(scope)) {
            return selectedResults();
        }
        if ("重点结果".equals(scope)) {
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
                ? "全部结果"
                : exportScopeCombo.getSelectedItem().toString();
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
            statusLabel.setText("该结果的请求/响应报文已根据历史上限释放。");
        } else if (record.isResponseTruncated()) {
            statusLabel.setText("该结果的响应报文已按响应保存上限截断。");
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

    private static final class PayloadVariant {
        private final RequestTemplate template;
        private final PayloadInsertionPoint insertionPoint;
        private final String category;
        private final String payload;

        private PayloadVariant(RequestTemplate template, PayloadInsertionPoint insertionPoint,
                String category, String payload) {
            this.template = template;
            this.insertionPoint = insertionPoint;
            this.category = category;
            this.payload = payload;
        }
    }
}
