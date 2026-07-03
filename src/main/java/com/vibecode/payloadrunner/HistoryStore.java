package com.vibecode.payloadrunner;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class HistoryStore {
    private final Map<String, List<HistoryRecord>> endpointHistory =
            new LinkedHashMap<String, List<HistoryRecord>>();
    private final Map<String, Integer> endpointCurrentIndex =
            new LinkedHashMap<String, Integer>();
    private long nextId = 1L;
    private int maxRecordsPerEndpoint;

    HistoryStore(int maxRecordsPerEndpoint) {
        this.maxRecordsPerEndpoint = Math.max(1, maxRecordsPerEndpoint);
    }

    synchronized long nextId() {
        return nextId++;
    }

    synchronized AppendResult append(HistoryRecord record) {
        List<HistoryRecord> records = endpointHistory.get(record.getEndpointKey());
        if (records == null) {
            records = new ArrayList<HistoryRecord>();
            endpointHistory.put(record.getEndpointKey(), records);
        }

        records.add(record);
        if (!endpointCurrentIndex.containsKey(record.getEndpointKey())) {
            endpointCurrentIndex.put(record.getEndpointKey(), Integer.valueOf(records.size() - 1));
        }
        int dropped = trimEndpoint(record.getEndpointKey(), records);
        return new AppendResult(dropped);
    }

    synchronized void setMaxRecordsPerEndpoint(int maxRecordsPerEndpoint) {
        this.maxRecordsPerEndpoint = Math.max(1, maxRecordsPerEndpoint);
        for (Map.Entry<String, List<HistoryRecord>> entry : endpointHistory.entrySet()) {
            trimEndpoint(entry.getKey(), entry.getValue());
        }
    }

    synchronized List<String> endpointKeys() {
        return new ArrayList<String>(endpointHistory.keySet());
    }

    synchronized List<HistoryRecord> recordsFor(String endpointKey) {
        List<HistoryRecord> records = endpointHistory.get(endpointKey);
        return records == null
                ? new ArrayList<HistoryRecord>()
                : new ArrayList<HistoryRecord>(records);
    }

    synchronized HistoryRecord currentRecord(String endpointKey) {
        List<HistoryRecord> records = endpointHistory.get(endpointKey);
        if (records == null || records.isEmpty()) {
            return null;
        }
        int index = currentIndex(endpointKey, records);
        return records.get(index);
    }

    synchronized HistoryRecord previous(String endpointKey) {
        List<HistoryRecord> records = endpointHistory.get(endpointKey);
        if (records == null || records.isEmpty()) {
            return null;
        }
        int index = currentIndex(endpointKey, records);
        if (index > 0) {
            index--;
            endpointCurrentIndex.put(endpointKey, Integer.valueOf(index));
        }
        return records.get(index);
    }

    synchronized HistoryRecord next(String endpointKey) {
        List<HistoryRecord> records = endpointHistory.get(endpointKey);
        if (records == null || records.isEmpty()) {
            return null;
        }
        int index = currentIndex(endpointKey, records);
        if (index < records.size() - 1) {
            index++;
            endpointCurrentIndex.put(endpointKey, Integer.valueOf(index));
        }
        return records.get(index);
    }

    synchronized boolean select(HistoryRecord record) {
        List<HistoryRecord> records = endpointHistory.get(record.getEndpointKey());
        if (records == null) {
            return false;
        }
        int index = indexOf(records, record);
        if (index < 0) {
            return false;
        }
        endpointCurrentIndex.put(record.getEndpointKey(), Integer.valueOf(index));
        return true;
    }

    synchronized int indexOf(HistoryRecord record) {
        List<HistoryRecord> records = endpointHistory.get(record.getEndpointKey());
        return records == null ? -1 : indexOf(records, record);
    }

    synchronized int size(String endpointKey) {
        List<HistoryRecord> records = endpointHistory.get(endpointKey);
        return records == null ? 0 : records.size();
    }

    synchronized void clear() {
        endpointHistory.clear();
        endpointCurrentIndex.clear();
        nextId = 1L;
    }

    private int trimEndpoint(String endpointKey, List<HistoryRecord> records) {
        int dropped = 0;
        while (records.size() > maxRecordsPerEndpoint) {
            HistoryRecord droppedRecord = records.remove(0);
            droppedRecord.discardMessages();
            dropped++;
        }
        if (records.isEmpty()) {
            endpointCurrentIndex.remove(endpointKey);
            return dropped;
        }

        Integer current = endpointCurrentIndex.get(endpointKey);
        int index = current == null ? records.size() - 1 : current.intValue() - dropped;
        if (index < 0) {
            index = 0;
        }
        if (index >= records.size()) {
            index = records.size() - 1;
        }
        endpointCurrentIndex.put(endpointKey, Integer.valueOf(index));
        return dropped;
    }

    private int currentIndex(String endpointKey, List<HistoryRecord> records) {
        Integer value = endpointCurrentIndex.get(endpointKey);
        int index = value == null ? records.size() - 1 : value.intValue();
        if (index < 0) {
            index = 0;
        }
        if (index >= records.size()) {
            index = records.size() - 1;
        }
        endpointCurrentIndex.put(endpointKey, Integer.valueOf(index));
        return index;
    }

    private int indexOf(List<HistoryRecord> records, HistoryRecord record) {
        for (int i = 0; i < records.size(); i++) {
            if (records.get(i).getId() == record.getId()) {
                return i;
            }
        }
        return -1;
    }

    static final class AppendResult {
        private final int droppedCount;

        private AppendResult(int droppedCount) {
            this.droppedCount = droppedCount;
        }

        int getDroppedCount() {
            return droppedCount;
        }
    }
}
