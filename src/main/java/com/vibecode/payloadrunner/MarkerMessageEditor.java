package com.vibecode.payloadrunner;

import burp.IMessageEditor;
import java.awt.*;
import java.awt.event.*;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.*;
import javax.swing.*;
import javax.swing.text.*;
import javax.swing.undo.*;

/** One editor with an explicit, reversible projection from display text to raw request text. */
final class MarkerMessageEditor implements IMessageEditor {
    private final JTextPane text = new JTextPane() {
        @Override public boolean getScrollableTracksViewportWidth() {
            return getParent() == null || getUI().getPreferredSize(this).width <= getParent().getSize().width;
        }
    };
    private final JScrollPane component = new JScrollPane(text);
    private final JPanel panel = new JPanel(new BorderLayout());
    private final JCheckBox formatted = new JCheckBox("格式化显示", true);
    private final JLabel formatLabel = new JLabel("原始");
    private final JLabel positionLabel = new JLabel(" ");
    private final UndoManager undo = new UndoManager();
    private final Timer styleTimer = new Timer(50, event -> refreshStyles());
    private final java.util.List<Object> highlights = new java.util.ArrayList<Object>();
    private byte[] original = new byte[0];
    private String originalText = "";
    private String rawText = "";
    private FormattedRequestView projection = FormattedRequestView.create("", false);
    private boolean loading;
    private boolean styling;
    private boolean dragging;
    private boolean synchronizingFont;
    private JComponent fontSource;
    private java.beans.PropertyChangeListener fontSourceListener;
    private String selectionError = "请先选择要标记的内容。";
    private final Color markerBackground = new Color(255, 184, 108);

    MarkerMessageEditor() {
        text.setFont(positionLabel.getFont().deriveFont(Font.PLAIN));
        text.setMargin(new Insets(10, 12, 10, 12));
        text.setDragEnabled(false);
        ((DefaultCaret) text.getCaret()).setSelectionVisible(true);
        component.setBorder(BorderFactory.createEmptyBorder());
        component.getVerticalScrollBar().setUnitIncrement(18);
        styleTimer.setRepeats(false);
        ((AbstractDocument) text.getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override public void insertString(FilterBypass fb, int offset, String value, AttributeSet attrs)
                    throws BadLocationException { replace(fb, offset, 0, value, attrs); }
            @Override public void remove(FilterBypass fb, int offset, int length)
                    throws BadLocationException { replace(fb, offset, length, "", null); }
            @Override public void replace(FilterBypass fb, int offset, int length, String value, AttributeSet attrs)
                    throws BadLocationException {
                if (loading) { fb.replace(offset, length, value, attrs); return; }
                int[] range = projection.rawSelection(offset, offset + length);
                if (!validRange(range)) {
                    selectionError = "格式化缩进不属于报文，请选择实际内容。";
                    formatLabel.setText(selectionError);
                    return;
                }
                String inserted = value == null ? "" : value;
                String before = rawText;
                int[] beforeSelection = selectionOrCaret();
                rawText = before.substring(0, range[0]) + inserted + before.substring(range[1]);
                projection = FormattedRequestView.create(rawText, formatted.isSelected());
                loading = true;
                try { fb.replace(0, fb.getDocument().getLength(), projection.display, null); }
                finally { loading = false; }
                int caret = range[0] + inserted.length();
                text.setCaretPosition(projection.viewOffset(caret));
                if (!before.equals(rawText)) { undo.addEdit(new RawEdit(before, rawText, beforeSelection, new int[] {caret, caret})); }
                styleTimer.restart();
                updatePosition();
                formatLabel.setText(projection.format);
            }
        });
        text.addPropertyChangeListener(event -> {
            String name = event.getPropertyName();
            if ("font".equals(name)) { synchronizeFont(); }
            if (!styling && ("font".equals(name) || "foreground".equals(name) || "background".equals(name))) {
                refreshStyles();
            }
        });
        text.addCaretListener(event -> { if (!loading) { updatePosition(); } });
        text.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent event) { dragging = true; }
            @Override public void mouseReleased(MouseEvent event) { dragging = false; styleTimer.restart(); }
        });
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 3));
        formatted.setToolTipText("仅改变显示缩进，原始报文字节保持不变。");
        toolbar.add(formatted);
        toolbar.add(formatLabel);
        formatted.addActionListener(event -> render(selectionOrCaret(), true));
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 10));
        footer.add(new JLabel("§ 注入位置"), BorderLayout.WEST);
        footer.add(positionLabel, BorderLayout.EAST);
        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(component, BorderLayout.CENTER);
        panel.add(footer, BorderLayout.SOUTH);
        installPlainTextTransfer();
        bind("undo", KeyEvent.VK_Z, false, () -> { if (undo.canUndo()) { undo.undo(); } });
        bind("redo", KeyEvent.VK_Z, true, () -> { if (undo.canRedo()) { undo.redo(); } });
    }

    @Override public Component getComponent() { return panel; }

    @Override public void setMessage(byte[] message, boolean isRequest) {
        original = message == null ? new byte[0] : Arrays.copyOf(message, message.length);
        originalText = decode(original);
        rawText = originalText;
        undo.discardAllEdits();
        render(new int[] {0, 0}, false);
    }

    @Override public byte[] getMessage() {
        return isMessageModified() ? encode(rawText) : Arrays.copyOf(original, original.length);
    }
    @Override public boolean isMessageModified() { return !rawText.equals(originalText); }
    byte[] selectionMessage() { return getMessage(); }
    String selectionError() { return selectionError; }
    JTextPane textView() { return text; }

    void setFormatted(boolean enabled) {
        if (enabled != formatted.isSelected()) {
            int[] selection = selectionOrCaret();
            formatted.setSelected(enabled);
            render(selection, true);
        }
    }
    boolean isFormatted() { return formatted.isSelected(); }

    @Override public byte[] getSelectedData() {
        int[] bounds = getSelectionBounds();
        return bounds == null ? null : Arrays.copyOfRange(getMessage(), bounds[0], bounds[1]);
    }
    @Override public int[] getSelectionBounds() {
        int[] range = projection.rawSelection(text.getSelectionStart(), text.getSelectionEnd());
        if (!validRange(range)) {
            selectionError = "请选择报文内容；格式化缩进不是注入位置。";
            return null;
        }
        return new int[] {byteOffset(range[0]), byteOffset(range[1])};
    }

    private int byteOffset(int position) {
        if (isMessageModified()) { return encode(rawText.substring(0, position)).length; }
        int offset = 0;
        for (int i = 0; i < position;) {
            char c = rawText.charAt(i);
            int length = Character.isHighSurrogate(c) && i + 1 < rawText.length()
                    && Character.isLowSurrogate(rawText.charAt(i + 1)) ? 2 : 1;
            offset += c == '§' && offset < original.length && (original[offset] & 255) == 167
                    ? 1 : encode(rawText.substring(i, i + length)).length;
            i += length;
        }
        return offset;
    }

    void selectBytes(int start, int end) {
        byte[] bytes = getMessage();
        text.select(projection.viewOffset(decode(Arrays.copyOf(bytes, start)).length()),
                projection.viewOffset(decode(Arrays.copyOf(bytes, end)).length()));
    }

    private boolean validRange(int[] range) {
        if (range == null) { return false; }
        for (int offset : range) {
            if (offset > 0 && offset < rawText.length() && Character.isLowSurrogate(rawText.charAt(offset))
                    && Character.isHighSurrogate(rawText.charAt(offset - 1))) { return false; }
        }
        return true;
    }
    private int[] selectionOrCaret() {
        int[] range = projection.rawSelection(text.getSelectionStart(), text.getSelectionEnd());
        return range == null ? projection.rawSelection(text.getCaretPosition(), text.getCaretPosition()) : range;
    }

    boolean wrapSelection() {
        int[] range = projection.rawSelection(text.getSelectionStart(), text.getSelectionEnd());
        if (!validRange(range)) { selectionError = "请选择实际报文内容，不要只选择格式化缩进。"; return false; }
        int start = range[0];
        int end = range[1];
        for (int open = rawText.indexOf('§'); open >= 0;) {
            int close = rawText.indexOf('§', open + 1);
            if (close < 0) { break; }
            if ((start == end && start > open && start <= close) || (start < close + 1 && end > open)) {
                selectionError = "选区与已有标记重叠，请重新选择。";
                return false;
            }
            open = rawText.indexOf('§', close + 1);
        }
        change(rawText.substring(0, start) + "§" + rawText.substring(start, end) + "§" + rawText.substring(end),
                new int[] {start + 1, end + 1}, true);
        text.requestFocusInWindow();
        return true;
    }

    void clearMarkers() {
        int caret = selectionOrCaret()[0];
        String value = rawText.replace("~PR~", "").replace("§", "");
        if (value.equals(rawText)) { return; }
        int next = rawText.substring(0, caret).replace("~PR~", "").replace("§", "").length();
        change(value, new int[] {next, next}, true);
        text.requestFocusInWindow();
    }

    private void change(String value, int[] selection, boolean preserveScroll) {
        if (rawText.equals(value)) { render(selection, preserveScroll); return; }
        String before = rawText;
        int[] previous = selectionOrCaret();
        rawText = value;
        undo.addEdit(new RawEdit(before, value, previous, selection));
        render(selection, preserveScroll);
    }

    private void render(int[] selection, boolean preserveScroll) {
        Point scroll = component.getViewport().getViewPosition();
        projection = FormattedRequestView.create(rawText, formatted.isSelected());
        loading = true;
        try {
            ((AbstractDocument) text.getDocument()).replace(0, text.getDocument().getLength(), projection.display, null);
            text.select(projection.viewOffset(selection[0]), projection.viewOffset(selection[1]));
        } catch (BadLocationException ex) { throw new IllegalStateException(ex); }
        finally { loading = false; }
        styleTimer.stop();
        refreshStyles();
        formatLabel.setText(projection.format);
        if (preserveScroll) { component.getViewport().setViewPosition(scroll); }
    }

    private final class RawEdit extends AbstractUndoableEdit {
        private final int start;
        private final String removed;
        private final String inserted;
        private final int[] previous;
        private final int[] next;
        RawEdit(String before, String after, int[] previous, int[] next) {
            int prefix = 0;
            while (prefix < before.length() && prefix < after.length()
                    && before.charAt(prefix) == after.charAt(prefix)) { prefix++; }
            int suffix = 0;
            while (suffix < before.length() - prefix && suffix < after.length() - prefix
                    && before.charAt(before.length() - suffix - 1) == after.charAt(after.length() - suffix - 1)) { suffix++; }
            start = prefix;
            removed = before.substring(prefix, before.length() - suffix);
            inserted = after.substring(prefix, after.length() - suffix);
            this.previous = previous.clone(); this.next = next.clone();
        }
        @Override public void undo() {
            super.undo(); rawText = rawText.substring(0, start) + removed + rawText.substring(start + inserted.length());
            render(previous, true);
        }
        @Override public void redo() {
            super.redo(); rawText = rawText.substring(0, start) + inserted + rawText.substring(start + removed.length());
            render(next, true);
        }
    }

    void followUiFont(JComponent source) {
        if (fontSource != null && fontSourceListener != null) { fontSource.removePropertyChangeListener("font", fontSourceListener); }
        fontSource = source;
        fontSourceListener = event -> synchronizeFont();
        source.addPropertyChangeListener("font", fontSourceListener);
        synchronizeFont();
    }
    private void synchronizeFont() {
        if (fontSource == null || fontSource.getFont() == null || synchronizingFont) { return; }
        Font font = fontSource.getFont().deriveFont(Font.PLAIN);
        if (font.equals(text.getFont())) { return; }
        synchronizingFont = true;
        try { text.setFont(font); }
        finally { synchronizingFont = false; }
    }

    void installActions(Runnable mark, Runnable clear, Runnable apply) {
        bind("mark", KeyEvent.VK_B, false, mark);
        bind("clear", KeyEvent.VK_B, true, clear);
        bind("apply", KeyEvent.VK_ENTER, false, apply);
        JPopupMenu popup = new JPopupMenu();
        menu(popup, "添加 § 标记", mark);
        menu(popup, "清除全部标记", clear);
        popup.addSeparator();
        menu(popup, "格式化显示 / 原样显示", () -> setFormatted(!isFormatted()));
        menu(popup, "撤销", () -> { if (undo.canUndo()) { undo.undo(); } });
        menu(popup, "重做", () -> { if (undo.canRedo()) { undo.redo(); } });
        popup.addSeparator();
        menu(popup, "剪切", () -> text.cut()); menu(popup, "复制", () -> text.copy()); menu(popup, "粘贴", () -> text.paste());
        text.setComponentPopupMenu(popup);
    }
    private void menu(JPopupMenu popup, String name, Runnable action) {
        JMenuItem item = new JMenuItem(name); item.addActionListener(event -> action.run()); popup.add(item);
    }
    private void bind(String name, int key, boolean shift, Runnable action) {
        int mask = System.getProperty("os.name", "").toLowerCase().contains("mac") ? InputEvent.META_DOWN_MASK : InputEvent.CTRL_DOWN_MASK;
        text.getInputMap().put(KeyStroke.getKeyStroke(key, mask | (shift ? InputEvent.SHIFT_DOWN_MASK : 0)), name);
        text.getActionMap().put(name, new AbstractAction() { public void actionPerformed(ActionEvent e) { action.run(); } });
    }

    private void installPlainTextTransfer() {
        text.setTransferHandler(new TransferHandler() {
            private Position start;
            private Position end;
            @Override public int getSourceActions(JComponent source) { return COPY_OR_MOVE; }
            @Override protected java.awt.datatransfer.Transferable createTransferable(JComponent source) {
                try {
                    start = text.getDocument().createPosition(text.getSelectionStart());
                    end = text.getDocument().createPosition(text.getSelectionEnd());
                } catch (BadLocationException ex) { throw new IllegalStateException(ex); }
                return new java.awt.datatransfer.StringSelection(text.getSelectedText() == null ? "" : text.getSelectedText());
            }
            @Override protected void exportDone(JComponent source, java.awt.datatransfer.Transferable data, int action) {
                if (action == MOVE && start != null && end != null) {
                    try { text.getDocument().remove(start.getOffset(), end.getOffset() - start.getOffset()); }
                    catch (BadLocationException ex) { throw new IllegalStateException(ex); }
                }
                start = null; end = null;
            }
            @Override public boolean canImport(JComponent target, java.awt.datatransfer.DataFlavor[] flavors) {
                if (!text.isEditable() || !text.isEnabled()) { return false; }
                for (java.awt.datatransfer.DataFlavor f : flavors) { if (java.awt.datatransfer.DataFlavor.stringFlavor.equals(f)) { return true; } }
                return false;
            }
            @Override public boolean importData(JComponent target, java.awt.datatransfer.Transferable data) {
                if (!canImport(target, data.getTransferDataFlavors())) { return false; }
                try {
                    text.replaceSelection((String) data.getTransferData(java.awt.datatransfer.DataFlavor.stringFlavor));
                    return true;
                } catch (java.awt.datatransfer.UnsupportedFlavorException | java.io.IOException ex) { return false; }
            }
        });
    }

    private void updatePosition() {
        String value = displayText();
        int caret = Math.min(text.getCaretPosition(), value.length());
        int line = 1;
        int lastBreak = -1;
        for (int i = 0; i < caret; i++) { if (value.charAt(i) == '\n') { line++; lastBreak = i; } }
        int selected = text.getSelectionEnd() - text.getSelectionStart();
        positionLabel.setText("行 " + line + " · 列 " + (caret - lastBreak) + (selected > 0 ? " · 已选 " + selected + " 字符" : ""));
    }
    private String displayText() {
        try { return text.getDocument().getText(0, text.getDocument().getLength()); }
        catch (BadLocationException ex) { throw new IllegalStateException(ex); }
    }

    private void refreshStyles() {
        if (dragging) { return; }
        styling = true;
        try {
            StyledDocument doc = text.getStyledDocument();
            String value = displayText();
            Font font = text.getFont();
            SimpleAttributeSet normal = new SimpleAttributeSet();
            StyleConstants.setFontFamily(normal, font.getFamily()); StyleConstants.setFontSize(normal, font.getSize());
            StyleConstants.setBold(normal, false); StyleConstants.setItalic(normal, false);
            StyleConstants.setForeground(normal, text.getForeground()); StyleConstants.setBackground(normal, text.getBackground());
            doc.setCharacterAttributes(0, value.length(), normal, true);
            boolean dark = text.getBackground().getRed() * 299 + text.getBackground().getGreen() * 587
                    + text.getBackground().getBlue() * 114 < 128000;
            Color accent = UIManager.getColor("Component.linkColor");
            if (accent == null) { accent = dark ? new Color(140, 185, 235) : new Color(35, 91, 150); }
            if (value.length() <= 512 * 1024) {
                quotedColors(doc, value, dark ? new Color(166, 205, 149) : new Color(41, 111, 66), accent);
                color(doc, value, "\\A[A-Z]+|HTTP/[0-9.]+|(?m)^[A-Za-z0-9_-]+(?=:)", accent);
                if ("XML".equals(projection.format)) { color(doc, value, "</?[A-Za-z_:][^>]*>", accent); }
                color(doc, value, "(?<![A-Za-z0-9_])(?:true|false|null|-?[0-9]+(?:\\.[0-9]+)?)(?![A-Za-z0-9_])",
                        dark ? new Color(202, 175, 236) : new Color(116, 70, 148));
            }
            Highlighter highlighter = text.getHighlighter();
            for (Object tag : highlights) { highlighter.removeHighlight(tag); } highlights.clear();
            Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(markerBackground) {
                @Override public Shape paintLayer(Graphics g, int start, int end, Shape bounds, JTextComponent editor, View view) {
                    int a = editor.getSelectionStart(); int b = editor.getSelectionEnd();
                    if (a == b || b <= start || a >= end) { return super.paintLayer(g, start, end, bounds, editor, view); }
                    Shape left = start < a ? super.paintLayer(g, start, Math.min(end, a), bounds, editor, view) : null;
                    Shape right = end > b ? super.paintLayer(g, Math.max(start, b), end, bounds, editor, view) : null;
                    return left == null ? right : right == null ? left : left.getBounds().union(right.getBounds());
                }
            };
            SimpleAttributeSet markerText = new SimpleAttributeSet();
            StyleConstants.setForeground(markerText, new Color(48, 33, 18));
            for (int open = value.indexOf('§'); open >= 0;) {
                int close = value.indexOf('§', open + 1); if (close < 0) { break; }
                doc.setCharacterAttributes(open, close - open + 1, markerText, false);
                try { highlights.add(highlighter.addHighlight(open, close + 1, painter)); }
                catch (BadLocationException ex) { throw new IllegalStateException(ex); }
                open = value.indexOf('§', close + 1);
            }
        } finally { styling = false; }
        updatePosition();
    }
    private void quotedColors(StyledDocument document, String value, Color stringColor, Color keyColor) {
        // A linear scan avoids regex stack overflows on long JSON string values.
        for (int i = 0; i < value.length();) {
            if (value.charAt(i) != '"') { i++; continue; }
            int start = i++;
            boolean closed = false;
            while (i < value.length()) {
                char c = value.charAt(i++);
                if (c == '\\' && i < value.length()) { i++; }
                else if (c == '"') { closed = true; break; }
            }
            if (!closed) { break; }
            int next = i;
            while (next < value.length() && Character.isWhitespace(value.charAt(next))) { next++; }
            SimpleAttributeSet style = new SimpleAttributeSet();
            StyleConstants.setForeground(style, next < value.length() && value.charAt(next) == ':' ? keyColor : stringColor);
            document.setCharacterAttributes(start, i - start, style, false);
        }
    }

    private void color(StyledDocument doc, String value, String regex, Color color) {
        Matcher matcher = Pattern.compile(regex).matcher(value);
        SimpleAttributeSet style = new SimpleAttributeSet(); StyleConstants.setForeground(style, color);
        while (matcher.find()) { doc.setCharacterAttributes(matcher.start(), matcher.end() - matcher.start(), style, false); }
    }

    static String decode(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < bytes.length;) {
            int b = bytes[i] & 255;
            int length = b < 128 ? 1 : b >= 194 && b <= 223 ? 2
                    : b >= 224 && b <= 239 ? 3 : b >= 240 && b <= 244 ? 4 : 0;
            if (length > 0 && i + length <= bytes.length) {
                try {
                    result.append(StandardCharsets.UTF_8.newDecoder()
                            .onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT)
                            .decode(ByteBuffer.wrap(bytes, i, length)));
                    i += length;
                    continue;
                } catch (CharacterCodingException ignored) { }
            }
            // Preserve arbitrary non-UTF-8 bytes through edits; recognize the old A7 marker.
            result.append(b == 167 ? '§' : (char) (0xdc00 + b));
            i++;
        }
        return result.toString();
    }

    static byte[] encode(String value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < value.length();) {
            char c = value.charAt(i);
            if (c >= 0xdc80 && c <= 0xdcff) {
                out.write(c - 0xdc00);
                i++;
            } else {
                int length = Character.isHighSurrogate(c) && i + 1 < value.length()
                        && Character.isLowSurrogate(value.charAt(i + 1)) ? 2 : 1;
                byte[] bytes = value.substring(i, i + length).getBytes(StandardCharsets.UTF_8);
                out.write(bytes, 0, bytes.length);
                i += length;
            }
        }
        return out.toByteArray();
    }
}
