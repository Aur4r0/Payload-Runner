package com.vibecode.payloadrunner;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;

final class ResultTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {
            "#", "接口", "方法", "主机", "路径", "参数", "分类", "Payload",
            "重点", "已发送至 Repeater", "命中", "评分", "差异", "状态码", "长度", "耗时(ms)"
    };

    private final List<RunnerResult> results = new ArrayList<RunnerResult>();

    int addResult(RunnerResult result) {
        int row = results.size();
        results.add(result);
        result.getHistoryRecord().setResultRowId(row);
        fireTableRowsInserted(row, row);
        return row;
    }

    RunnerResult getResult(int row) {
        return results.get(row);
    }

    void clear() {
        int last = results.size() - 1;
        results.clear();
        if (last >= 0) {
            fireTableRowsDeleted(0, last);
        }
    }

    void fireRecordUpdated(HistoryRecord record) {
        int row = rowFor(record);
        if (row >= 0) {
            fireTableRowsUpdated(row, row);
        }
    }

    int rowFor(HistoryRecord record) {
        int rowId = record.getResultRowId();
        if (rowId >= 0 && rowId < results.size()
                && results.get(rowId).getHistoryRecord().getId() == record.getId()) {
            return rowId;
        }
        for (int i = 0; i < results.size(); i++) {
            if (results.get(i).getHistoryRecord().getId() == record.getId()) {
                return i;
            }
        }
        return -1;
    }

    @Override
    public int getRowCount() {
        return results.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0 || columnIndex == 11 || columnIndex == 14) {
            return Integer.class;
        }
        if (columnIndex == 15) {
            return Long.class;
        }
        return String.class;
    }

    List<RunnerResult> snapshot() {
        return new ArrayList<RunnerResult>(results);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        RunnerResult result = results.get(rowIndex);
        RequestTemplate template = result.getTemplate();
        HistoryRecord record = result.getHistoryRecord();
        switch (columnIndex) {
            case 0:
                return rowIndex + 1;
            case 1:
                return record.getEndpointKey();
            case 2:
                return template.getMethod();
            case 3:
                return template.getHost();
            case 4:
                return template.getPath();
            case 5:
                return result.getParameterName();
            case 6:
                return result.getCategory();
            case 7:
                return record.payloadPreview();
            case 8:
                return record.isInteresting() ? "是" : "否";
            case 9:
                return result.isSentToRepeater() ? "是" : "否";
            case 10:
                return result.getHitMatch();
            case 11:
                return result.getScore();
            case 12:
                return result.getDiffSummary();
            case 13:
                return result.getError() == null
                        ? Integer.toString(result.getStatusCode())
                        : "错误: " + result.getError();
            case 14:
                return result.getResponseLength();
            case 15:
                return result.getElapsedMillis();
            default:
                return "";
        }
    }
}
