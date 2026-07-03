package com.vibecode.payloadrunner;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;

final class ResultTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {
            "#", "Method", "Host", "Path", "Param", "Category", "Payload",
            "Sent to Repeater", "Hit", "Diff", "Status", "Length", "Time ms"
    };

    private final List<RunnerResult> results = new ArrayList<RunnerResult>();

    void addResult(RunnerResult result) {
        int row = results.size();
        results.add(result);
        fireTableRowsInserted(row, row);
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
        if (columnIndex == 0 || columnIndex == 11) {
            return Integer.class;
        }
        if (columnIndex == 12) {
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
        switch (columnIndex) {
            case 0:
                return rowIndex + 1;
            case 1:
                return template.getMethod();
            case 2:
                return template.getHost();
            case 3:
                return template.getPath();
            case 4:
                return result.getParameterName();
            case 5:
                return result.getCategory();
            case 6:
                return result.getPayload();
            case 7:
                return result.isSentToRepeater() ? "Yes" : "No";
            case 8:
                return result.getHitMatch();
            case 9:
                return result.getDiffSummary();
            case 10:
                return result.getError() == null
                        ? Integer.toString(result.getStatusCode())
                        : "ERR: " + result.getError();
            case 11:
                return result.getResponseLength();
            case 12:
                return result.getElapsedMillis();
            default:
                return "";
        }
    }
}
