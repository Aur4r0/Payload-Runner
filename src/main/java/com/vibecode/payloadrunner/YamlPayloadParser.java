package com.vibecode.payloadrunner;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class YamlPayloadParser {
    private YamlPayloadParser() {
    }

    static Map<String, List<String>> parse(String yaml) {
        Map<String, List<String>> categories = new LinkedHashMap<String, List<String>>();
        String currentCategory = null;
        String[] lines = yaml.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);

        for (int i = 0; i < lines.length; i++) {
            String rawLine = lines[i].replace("\t", "    ");
            String trimmed = rawLine.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }

            int indent = countIndent(rawLine);
            if (indent == 0 && !trimmed.startsWith("-")) {
                int colon = trimmed.indexOf(':');
                if (colon <= 0) {
                    throw new IllegalArgumentException("第 " + (i + 1)
                            + " 行必须是以“:”结尾的顶级分类。");
                }
                currentCategory = stripScalar(trimmed.substring(0, colon).trim());
                if (currentCategory.isEmpty()) {
                    throw new IllegalArgumentException("第 " + (i + 1) + " 行的分类名称不能为空。");
                }
                if (!categories.containsKey(currentCategory)) {
                    categories.put(currentCategory, new ArrayList<String>());
                }

                String rest = trimmed.substring(colon + 1).trim();
                if (!rest.isEmpty()) {
                    if (rest.startsWith("[") && rest.endsWith("]")) {
                        categories.get(currentCategory).addAll(parseInlineList(rest));
                    } else {
                        throw new IllegalArgumentException("第 " + (i + 1)
                                + " 行必须使用 Payload 列表。");
                    }
                }
                continue;
            }

            if (currentCategory == null) {
                throw new IllegalArgumentException("第 " + (i + 1) + " 行之前缺少分类定义。");
            }

            if ("payloads:".equals(trimmed)) {
                continue;
            }
            if (trimmed.startsWith("-")) {
                String value = trimmed.length() == 1 ? "" : trimmed.substring(1).trim();
                categories.get(currentCategory).add(stripScalar(value));
                continue;
            }

            throw new IllegalArgumentException("第 " + (i + 1) + " 行不是有效的 Payload 列表项。");
        }

        removeEmptyCategories(categories);
        if (categories.isEmpty()) {
            throw new IllegalArgumentException("请至少添加一个包含 Payload 的分类。");
        }
        return categories;
    }

    private static List<String> parseInlineList(String value) {
        String content = value.substring(1, value.length() - 1).trim();
        List<String> result = new ArrayList<String>();
        if (content.isEmpty()) {
            return result;
        }

        StringBuilder current = new StringBuilder();
        char quote = 0;
        boolean escaping = false;
        for (int i = 0; i < content.length(); i++) {
            char ch = content.charAt(i);
            if (escaping) {
                current.append('\\').append(ch);
                escaping = false;
                continue;
            }
            if (quote == '"' && ch == '\\') {
                escaping = true;
                continue;
            }
            if ((ch == '"' || ch == '\'') && quote == 0) {
                quote = ch;
                current.append(ch);
                continue;
            }
            if (ch == quote) {
                quote = 0;
                current.append(ch);
                continue;
            }
            if (ch == ',' && quote == 0) {
                result.add(stripScalar(current.toString().trim()));
                current.setLength(0);
                continue;
            }
            current.append(ch);
        }
        if (quote != 0) {
            throw new IllegalArgumentException("行内列表中存在未闭合的引号。");
        }
        result.add(stripScalar(current.toString().trim()));
        return result;
    }

    private static String stripScalar(String value) {
        if (value.length() >= 2 && value.charAt(0) == '"'
                && value.charAt(value.length() - 1) == '"') {
            return unescapeDoubleQuoted(value.substring(1, value.length() - 1));
        }
        if (value.length() >= 2 && value.charAt(0) == '\''
                && value.charAt(value.length() - 1) == '\'') {
            return value.substring(1, value.length() - 1).replace("''", "'");
        }
        return value;
    }

    private static String unescapeDoubleQuoted(String value) {
        StringBuilder result = new StringBuilder();
        boolean escaping = false;
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (!escaping) {
                if (ch == '\\') {
                    escaping = true;
                } else {
                    result.append(ch);
                }
                continue;
            }

            switch (ch) {
                case '"':
                    result.append('"');
                    break;
                case '\\':
                    result.append('\\');
                    break;
                case 'n':
                    result.append('\n');
                    break;
                case 'r':
                    result.append('\r');
                    break;
                case 't':
                    result.append('\t');
                    break;
                default:
                    result.append(ch);
                    break;
            }
            escaping = false;
        }
        if (escaping) {
            result.append('\\');
        }
        return result.toString();
    }

    private static int countIndent(String line) {
        int count = 0;
        while (count < line.length() && line.charAt(count) == ' ') {
            count++;
        }
        return count;
    }

    private static void removeEmptyCategories(Map<String, List<String>> categories) {
        List<String> emptyCategories = new ArrayList<String>();
        for (Map.Entry<String, List<String>> entry : categories.entrySet()) {
            if (entry.getValue().isEmpty()) {
                emptyCategories.add(entry.getKey());
            }
        }
        for (String category : emptyCategories) {
            categories.remove(category);
        }
    }
}
