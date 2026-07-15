package com.vibecode.payloadrunner;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

abstract class HitRule {
    private final String label;

    HitRule(String label) {
        this.label = label;
    }

    String getLabel() {
        return label;
    }

    abstract boolean matches(MatchInput input);

    static List<HitRule> parse(String quickKeywords, String rulesText) {
        List<HitRule> rules = new ArrayList<HitRule>();
        for (String keyword : splitQuickKeywords(quickKeywords)) {
            rules.add(keyword(keyword));
        }

        if (rulesText == null || rulesText.trim().isEmpty()) {
            return rules;
        }
        String[] lines = rulesText.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            rules.add(parseRule(line, i + 1));
        }
        return rules;
    }

    static String evaluate(List<HitRule> rules, MatchInput input) {
        if (rules == null || rules.isEmpty()) {
            return "";
        }
        List<String> hits = new ArrayList<String>();
        for (HitRule rule : rules) {
            if (rule.matches(input)) {
                hits.add(rule.getLabel());
            }
        }
        return join(hits);
    }

    private static HitRule parseRule(String line, int lineNumber) {
        String lower = line.toLowerCase(Locale.ROOT);
        if (lower.startsWith("keyword:")) {
            return keyword(line.substring("keyword:".length()).trim());
        }
        if (lower.startsWith("contains:")) {
            return keyword(line.substring("contains:".length()).trim());
        }
        if (lower.startsWith("regex:")) {
            String regex = line.substring("regex:".length()).trim();
            try {
                Pattern pattern = Pattern.compile(regex, Pattern.DOTALL);
                return new HitRule("regex:" + regex) {
                    @Override
                    boolean matches(MatchInput input) {
                        return input.responseText != null
                                && pattern.matcher(input.responseText).find();
                    }
                };
            } catch (PatternSyntaxException ex) {
                throw new IllegalArgumentException("命中规则第 " + lineNumber
                        + " 行的正则表达式无效：" + ex.getDescription());
            }
        }
        if (lower.startsWith("status:") || lower.startsWith("status=")) {
            String value = line.substring(line.indexOf(lower.startsWith("status:") ? ':' : '=') + 1)
                    .trim();
            return status(value, lineNumber);
        }
        if (lower.startsWith("status")) {
            return numeric("status", line.substring("status".length()).trim(), lineNumber);
        }
        if (lower.startsWith("length")) {
            return numeric("length", line.substring("length".length()).trim(), lineNumber);
        }
        if (lower.startsWith("diff")) {
            return numeric("diff", line.substring("diff".length()).trim(), lineNumber);
        }
        if (lower.startsWith("sim")) {
            return numeric("sim", line.substring("sim".length()).trim(), lineNumber);
        }
        if (lower.startsWith("elapsed")) {
            return numeric("time", line.substring("elapsed".length()).trim(), lineNumber);
        }
        if (lower.startsWith("time")) {
            return numeric("time", line.substring("time".length()).trim(), lineNumber);
        }
        return keyword(line);
    }

    private static HitRule keyword(String keyword) {
        if (keyword == null || keyword.isEmpty()) {
            throw new IllegalArgumentException("关键词命中规则不能为空。");
        }
        return new HitRule("keyword:" + keyword) {
            @Override
            boolean matches(MatchInput input) {
                return input.responseText != null && input.responseText.contains(keyword);
            }
        };
    }

    private static HitRule status(String value, int lineNumber) {
        String lower = value.toLowerCase(Locale.ROOT);
        if (lower.length() == 3 && lower.charAt(1) == 'x' && lower.charAt(2) == 'x'
                && Character.isDigit(lower.charAt(0))) {
            int classStart = Character.digit(lower.charAt(0), 10) * 100;
            return new HitRule("status:" + lower) {
                @Override
                boolean matches(MatchInput input) {
                    return input.statusCode >= classStart && input.statusCode < classStart + 100;
                }
            };
        }
        try {
            long expected = Long.parseLong(value);
            return new HitRule("status:" + expected) {
                @Override
                boolean matches(MatchInput input) {
                    return input.statusCode == expected;
                }
            };
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("命中规则第 " + lineNumber + " 行的状态码无效。");
        }
    }

    private static HitRule numeric(String field, String expression, int lineNumber) {
        String trimmed = expression.trim();
        String operator;
        String value;
        if (trimmed.startsWith(">=") || trimmed.startsWith("<=") || trimmed.startsWith("!=")) {
            operator = trimmed.substring(0, 2);
            value = trimmed.substring(2).trim();
        } else if (trimmed.startsWith(">") || trimmed.startsWith("<") || trimmed.startsWith("=")) {
            operator = trimmed.substring(0, 1);
            value = trimmed.substring(1).trim();
        } else {
            throw new IllegalArgumentException("命中规则第 " + lineNumber
                    + " 行缺少比较运算符，例如 " + field + ">100。");
        }
        try {
            int expected = Integer.parseInt(value);
            return new HitRule(field + operator + expected) {
                @Override
                boolean matches(MatchInput input) {
                    return compare(numericValue(field, input), operator, expected);
                }
            };
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("命中规则第 " + lineNumber + " 行的数值无效。");
        }
    }

    private static long numericValue(String field, MatchInput input) {
        if ("status".equals(field)) {
            return input.statusCode;
        }
        if ("length".equals(field)) {
            return input.responseLength;
        }
        if ("diff".equals(field)) {
            return input.diff == null || !input.diff.isAvailable() ? 0 : input.diff.getLengthDelta();
        }
        if ("sim".equals(field)) {
            return input.diff == null || !input.diff.isAvailable() ? 100 : input.diff.getSimilarityPercent();
        }
        if ("time".equals(field)) {
            return input.elapsedMillis;
        }
        return 0;
    }

    private static boolean compare(long actual, String operator, long expected) {
        if (">".equals(operator)) {
            return actual > expected;
        }
        if ("<".equals(operator)) {
            return actual < expected;
        }
        if (">=".equals(operator)) {
            return actual >= expected;
        }
        if ("<=".equals(operator)) {
            return actual <= expected;
        }
        if ("!=".equals(operator)) {
            return actual != expected;
        }
        return actual == expected;
    }

    private static List<String> splitQuickKeywords(String text) {
        List<String> keywords = new ArrayList<String>();
        if (text == null || text.trim().isEmpty()) {
            return keywords;
        }
        String[] parts = text.split("[,;\\r\\n]+");
        for (String part : parts) {
            String keyword = part.trim();
            if (!keyword.isEmpty()) {
                keywords.add(keyword);
            }
        }
        return keywords;
    }

    private static String join(List<String> values) {
        StringBuilder joined = new StringBuilder();
        for (String value : values) {
            if (joined.length() > 0) {
                joined.append(", ");
            }
            joined.append(value);
        }
        return joined.toString();
    }

    static final class MatchInput {
        private final String responseText;
        private final int statusCode;
        private final int responseLength;
        private final ResponseDiff diff;
        private final long elapsedMillis;

        MatchInput(String responseText, int statusCode, int responseLength, ResponseDiff diff) {
            this(responseText, statusCode, responseLength, diff, 0L);
        }

        MatchInput(String responseText, int statusCode, int responseLength, ResponseDiff diff,
                long elapsedMillis) {
            this.responseText = responseText;
            this.statusCode = statusCode;
            this.responseLength = responseLength;
            this.diff = diff;
            this.elapsedMillis = elapsedMillis;
        }
    }
}
