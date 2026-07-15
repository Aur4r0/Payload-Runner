package com.vibecode.payloadrunner;

enum HitRuleTemplate {
    PRACTICAL("实战综合（按内置 Payload）",
            "# 通用异常与延时 Payload\n"
                    + "status:5xx\n"
                    + "diff>500\n"
                    + "diff<-500\n"
                    + "sim<70\n"
                    + "time>=4500\n"
                    + "\n"
                    + "# XSS 回显\n"
                    + "keyword:<script>alert(1)</script>\n"
                    + "keyword:<img src=x onerror=alert(1)>\n"
                    + "keyword:<svg onload=alert(1)>\n"
                    + "keyword:javascript:alert(1)\n"
                    + "regex:(?i)<(?:script|img|svg)[^>]*(?:alert\\(|onerror=|onload=)\n"
                    + "\n"
                    + "# SQL 注入错误\n"
                    + "regex:(?i)(SQL syntax|SQLSTATE|mysql_fetch|mysqli|PDOException|ORA-\\d+|PG::SyntaxError|PostgreSQL.*ERROR|SQLiteException|Unclosed quotation mark|quoted string not properly terminated)\n"
                    + "\n"
                    + "# 命令执行输出\n"
                    + "regex:(?m)^uid=\\d+\\([^)]+\\)\\s+gid=\\d+\n"
                    + "regex:(?i)(Reply from 127\\.0\\.0\\.1|bytes from 127\\.0\\.0\\.1|TTL=\\d+)\n"
                    + "\n"
                    + "# 边界值与类型处理异常\n"
                    + "regex:(?i)(NumberFormatException|numeric overflow|out of range|cannot deserialize|invalid (?:number|boolean)|not a finite number|NaN|Infinity)\n"
                    + "\n"
                    + "# 文件读取与环境信息\n"
                    + "keyword:root:x:0:0\n"
                    + "keyword:/bin/bash\n"
                    + "regex:(?im)^\\[(?:extensions|fonts|files|Mail|MCI Extensions)\\]$\n"
                    + "regex:(?m)^(?:APP_KEY|DB_PASSWORD|DATABASE_URL|DOCUMENT_ROOT|HTTP_HOST)=\n"
                    + "\n"
                    + "# SSRF 常见内网服务与云元数据\n"
                    + "regex:(?i)(ami-id|instance-id|security-credentials|AccessKeyId|metadata-flavor|computeMetadata|redis_version|docker|cluster_name)\n"
                    + "\n"
                    + "# SSTI 计算结果与模板引擎错误\n"
                    + "keyword:7777777\n"
                    + "regex:(?i)(TemplateSyntaxError|jinja2|twig|freemarker|velocity|smarty|ELException)\n"
                    + "\n"
                    + "# CRLF 注入与开放重定向\n"
                    + "regex:(?im)^X-Payload-Runner:\\s*true\\s*$\n"
                    + "regex:(?im)^Set-Cookie:\\s*payloadrunner=1\n"
                    + "regex:(?im)^Location:\\s*(?:https?:)?//example\\.com(?:/|$)\n"),
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

    static String practicalRules() {
        return PRACTICAL.rules;
    }

    @Override
    public String toString() {
        return label;
    }
}
