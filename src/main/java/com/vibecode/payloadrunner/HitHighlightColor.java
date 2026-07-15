package com.vibecode.payloadrunner;

import java.awt.Color;

enum HitHighlightColor {
    NONE("不着色", null, null),
    RED("红色", "red", new Color(255, 218, 218)),
    ORANGE("橙色", "orange", new Color(255, 226, 190)),
    YELLOW("黄色", "yellow", new Color(255, 247, 184)),
    GREEN("绿色", "green", new Color(218, 242, 218)),
    CYAN("青色", "cyan", new Color(207, 239, 242)),
    BLUE("蓝色", "blue", new Color(215, 228, 255)),
    MAGENTA("紫色", "magenta", new Color(240, 215, 244));

    private final String label;
    private final String burpColor;
    private final Color tableColor;

    HitHighlightColor(String label, String burpColor, Color tableColor) {
        this.label = label;
        this.burpColor = burpColor;
        this.tableColor = tableColor;
    }

    static HitHighlightColor fromSetting(String value) {
        if (value == null || value.trim().isEmpty()) {
            return RED;
        }
        try {
            return valueOf(value.trim());
        } catch (IllegalArgumentException ex) {
            return RED;
        }
    }

    String getBurpColor() {
        return burpColor;
    }

    Color getTableColor() {
        return tableColor;
    }

    boolean isEnabled() {
        return burpColor != null;
    }

    @Override
    public String toString() {
        return label;
    }
}
