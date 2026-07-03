package com.vibecode.payloadrunner;

enum HitRuleTemplate {
    BASIC("Basic anomalies",
            "# Basic anomalies\n"
                    + "status:5xx\n"
                    + "length>1000\n"
                    + "diff>200\n"
                    + "sim<90\n"),
    SQLI("SQLi",
            "# SQL injection signals\n"
                    + "status:5xx\n"
                    + "keyword:SQL syntax\n"
                    + "keyword:mysql_fetch\n"
                    + "keyword:ORA-\n"
                    + "regex:(?i)(sql|mysql|postgres|sqlite|oracle).*(error|exception)\n"),
    XSS("XSS reflection",
            "# XSS reflection signals\n"
                    + "keyword:<script\n"
                    + "keyword:onerror=\n"
                    + "keyword:onmouseover=\n"
                    + "regex:(?i)<[^>]+(script|onerror|onload|onmouseover)\n"),
    FILE_READ("File read",
            "# File read / path traversal signals\n"
                    + "keyword:root:x:0:0\n"
                    + "keyword:/bin/bash\n"
                    + "keyword:boot.ini\n"
                    + "keyword:win.ini\n"),
    AUTH_BYPASS("Auth/status changes",
            "# Auth bypass and status-change signals\n"
                    + "status:2xx\n"
                    + "status:3xx\n"
                    + "diff>200\n");

    private final String label;
    private final String rules;

    HitRuleTemplate(String label, String rules) {
        this.label = label;
        this.rules = rules;
    }

    String getRules() {
        return rules;
    }

    @Override
    public String toString() {
        return label;
    }
}
