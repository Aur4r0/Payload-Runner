package com.vibecode.payloadrunner;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;

final class CsvExporter {
    private CsvExporter() {
    }

    static void export(File file, List<RunnerResult> results) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(file), StandardCharsets.UTF_8))) {
            writer.write("index,endpoint,method,host,path,param,category,payload,interesting,sent_to_repeater,repeater_error,hit,score,diff,status,length,time_ms,error");
            writer.newLine();
            for (int i = 0; i < results.size(); i++) {
                RunnerResult result = results.get(i);
                RequestTemplate template = result.getTemplate();
                HistoryRecord record = result.getHistoryRecord();
                writer.write(csv(Integer.toString(i + 1)));
                writer.write(',');
                writer.write(csv(record.getEndpointKey()));
                writer.write(',');
                writer.write(csv(template.getMethod()));
                writer.write(',');
                writer.write(csv(template.getHost()));
                writer.write(',');
                writer.write(csv(template.getPath()));
                writer.write(',');
                writer.write(csv(result.getParameterName()));
                writer.write(',');
                writer.write(csv(result.getCategory()));
                writer.write(',');
                writer.write(csv(result.getPayload()));
                writer.write(',');
                writer.write(csv(record.isInteresting() ? "Yes" : "No"));
                writer.write(',');
                writer.write(csv(result.isSentToRepeater() ? "Yes" : "No"));
                writer.write(',');
                writer.write(csv(result.getRepeaterError()));
                writer.write(',');
                writer.write(csv(result.getHitMatch()));
                writer.write(',');
                writer.write(csv(Integer.toString(result.getScore())));
                writer.write(',');
                writer.write(csv(result.getDiffSummary()));
                writer.write(',');
                writer.write(csv(Integer.toString(result.getStatusCode())));
                writer.write(',');
                writer.write(csv(Integer.toString(result.getResponseLength())));
                writer.write(',');
                writer.write(csv(Long.toString(result.getElapsedMillis())));
                writer.write(',');
                writer.write(csv(result.getError() == null ? "" : result.getError()));
                writer.newLine();
            }
        }
    }

    private static String csv(String value) {
        String safe = value == null ? "" : value;
        return "\"" + safe.replace("\"", "\"\"") + "\"";
    }
}
