package com.vibecode.payloadrunner;

enum HitRuleTemplate {
    BASIC("基础异常",
            "# 基础异常检测\n"
                    + "status:5xx\n"
                    + "length>1000\n"
                    + "diff>200\n"
                    + "sim<90\n"),
    SQLI("SQL 注入",
            "# SQL 注入特征\n"
                    + "status:5xx\n"
                    + "keyword:SQL syntax\n"
                    + "keyword:mysql_fetch\n"
                    + "keyword:ORA-\n"
                    + "regex:(?i)(sql|mysql|postgres|sqlite|oracle).*(error|exception)\n"),
    XSS("XSS 回显",
            "# XSS 回显特征\n"
                    + "keyword:<script\n"
                    + "keyword:onerror=\n"
                    + "keyword:onmouseover=\n"
                    + "regex:(?i)<[^>]+(script|onerror|onload|onmouseover)\n"),
    FILE_READ("文件读取",
            "# 文件读取 / 路径穿越特征\n"
                    + "keyword:root:x:0:0\n"
                    + "keyword:/bin/bash\n"
                    + "keyword:boot.ini\n"
                    + "keyword:win.ini\n"),
    AUTH_BYPASS("鉴权与状态变化",
            "# 鉴权绕过与状态码变化特征\n"
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
