package com.vibecode.payloadrunner;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;

/** Display-only formatting. Each visible source character keeps its original UTF-16 offset. */
final class FormattedRequestView {
    final String raw;
    final String display;
    final String format;
    private final int[] origins;
    private final int[] rawToView;
    private static final Pattern NUMBER = Pattern.compile("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?");

    private FormattedRequestView(String raw, String display, int[] origins, String format) {
        this.raw = raw;
        this.display = display;
        this.origins = origins;
        this.format = format;
        rawToView = new int[raw.length() + 1];
        Arrays.fill(rawToView, display.length());
        int next = display.length();
        int view = display.length() - 1;
        for (int i = raw.length() - 1; i >= 0; i--) {
            while (view >= 0 && (origins[view] < 0 || origins[view] > i)) { view--; }
            if (view >= 0 && origins[view] == i) { next = view; }
            rawToView[i] = next;
        }
    }

    static FormattedRequestView create(String raw, boolean pretty) {
        if (!pretty || raw.length() > 512 * 1024) { return identity(raw); }
        int body = bodyOffset(raw);
        if (body < 0) { return identity(raw); }
        String trimmed = raw.substring(body).trim();
        String type = raw.substring(0, body).toLowerCase(java.util.Locale.ROOT);
        try {
            if (trimmed.startsWith("{") || trimmed.startsWith("[") || trimmed.startsWith("§{") || trimmed.startsWith("§[")
                    || type.contains("application/json") || type.contains("+json")) {
                return json(raw, body);
            }
            if ((trimmed.startsWith("<") || trimmed.startsWith("§<"))
                    && !type.contains("text/html")) { return xml(raw, body); }
        } catch (IllegalArgumentException ex) {
            return identity(raw);
        }
        return identity(raw);
    }

    static int bodyOffset(String raw) {
        int first = Integer.MAX_VALUE;
        int result = -1;
        for (String separator : new String[] {"\r\n\r\n", "\n\n", "\r\r"}) {
            int index = raw.indexOf(separator);
            if (index >= 0 && index < first) { first = index; result = index + separator.length(); }
        }
        return result;
    }

    private static FormattedRequestView identity(String raw) {
        int[] origins = new int[raw.length()];
        for (int i = 0; i < origins.length; i++) { origins[i] = i; }
        return new FormattedRequestView(raw, raw, origins, "原始");
    }

    /** Null means only virtual indentation is selected; that is never a deletion target. */
    int[] rawSelection(int start, int end) {
        if (start < 0 || end < start || end > display.length()) { return null; }
        if (start == 0 && end == display.length() && start != end) { return new int[] {0, raw.length()}; }
        if (start == end) {
            int i = start;
            while (i < origins.length && origins[i] < 0) { i++; }
            int offset = i < origins.length ? origins[i] : raw.length();
            return new int[] {offset, offset};
        }
        int first = start;
        int last = end - 1;
        while (first < end && origins[first] < 0) { first++; }
        while (last >= first && origins[last] < 0) { last--; }
        return first > last ? null : new int[] {origins[first], origins[last] + 1};
    }

    int viewOffset(int rawOffset) { return rawToView[Math.max(0, Math.min(raw.length(), rawOffset))]; }

    private static FormattedRequestView json(String raw, int body) {
        List<Token> tokens = jsonTokens(raw, body);
        List<Token> semantic = new ArrayList<Token>();
        for (int i = 0; i < tokens.size(); i++) {
            Token token = tokens.get(i);
            if (token.kind != 'm') { semantic.add(token); continue; }
            // An empty injection placeholder may stand in for a not-yet-supplied JSON value.
            if (i + 1 < tokens.size() && tokens.get(i + 1).kind == 'm') {
                int next = i + 2;
                if (next < tokens.size() && ",}]".indexOf(tokens.get(next).kind) >= 0) {
                    semantic.add(new Token('a', token.start, token.end));
                }
                i++;
            }
        }
        JsonValidator validator = new JsonValidator(semantic);
        validator.value(0);
        if (validator.cursor != semantic.size()) { throw new IllegalArgumentException("Invalid JSON"); }
        Builder out = new Builder(raw);
        out.source(0, body);
        int depth = 0;
        char previous = 0;
        boolean pending = false;
        for (int tokenIndex = 0; tokenIndex < tokens.size(); tokenIndex++) {
            Token token = tokens.get(tokenIndex);
            boolean close = token.kind == '}' || token.kind == ']';
            if (close) {
                depth--;
                if (previous != '{' && previous != '[') { out.line(depth); }
                pending = false;
            } else if (pending) {
                char next = token.kind;
                if (token.kind == 'm') {
                    int index = tokenIndex + 1;
                    while (index < tokens.size() && tokens.get(index).kind == 'm') { index++; }
                    next = index < tokens.size() ? tokens.get(index).kind : 0;
                }
                if (!(previous == '{' && next == '}') && !(previous == '[' && next == ']')) { out.line(depth); }
                pending = false;
            }
            out.source(token.start, token.end);
            if (token.kind == 'm') { continue; }
            if (token.kind == '{' || token.kind == '[') { depth++; pending = true; }
            if (token.kind == ',') { pending = true; }
            if (token.kind == ':') { out.virtual(" "); }
            previous = token.kind;
        }
        return out.finish("JSON");
    }

    private static List<Token> jsonTokens(String raw, int offset) {
        List<Token> tokens = new ArrayList<Token>();
        while (offset < raw.length()) {
            char c = raw.charAt(offset);
            if (whitespace(c)) { offset++; continue; }
            int start = offset;
            if (c == '§' || raw.startsWith("~PR~", offset)) {
                offset += c == '§' ? 1 : 4;
                tokens.add(new Token('m', start, offset));
            } else if ("{}[]:,".indexOf(c) >= 0) {
                tokens.add(new Token(c, offset, ++offset));
            } else if (c == '"') {
                offset++;
                boolean closed = false;
                while (offset < raw.length()) {
                    char next = raw.charAt(offset++);
                    if (next < 32) { throw new IllegalArgumentException("Invalid JSON string"); }
                    if (next == '"') { closed = true; break; }
                    if (next == '\\') {
                        if (offset >= raw.length()) { break; }
                        char escape = raw.charAt(offset++);
                        if (escape == 'u') {
                            for (int i = 0; i < 4; i++) {
                                if (offset >= raw.length() || Character.digit(raw.charAt(offset++), 16) < 0) {
                                    throw new IllegalArgumentException("Invalid Unicode escape");
                                }
                            }
                        } else if ("\"\\/bfnrt".indexOf(escape) < 0) { throw new IllegalArgumentException("Invalid escape"); }
                    }
                }
                if (!closed) { throw new IllegalArgumentException("Unclosed string"); }
                tokens.add(new Token('s', start, offset));
            } else {
                while (offset < raw.length() && !whitespace(raw.charAt(offset))
                        && "{}[]:,§".indexOf(raw.charAt(offset)) < 0 && !raw.startsWith("~PR~", offset)) { offset++; }
                String atom = raw.substring(start, offset);
                if (!atom.equals("true") && !atom.equals("false") && !atom.equals("null") && !NUMBER.matcher(atom).matches()) {
                    throw new IllegalArgumentException("Invalid JSON atom");
                }
                tokens.add(new Token('a', start, offset));
            }
        }
        return tokens;
    }

    private static boolean whitespace(char c) { return c == ' ' || c == '\r' || c == '\n' || c == '\t'; }

    private static FormattedRequestView xml(String raw, int body) {
        String clean = raw.substring(body).replace("~PR~", "").replace("§", "");
        if (clean.contains("<!DOCTYPE") || clean.contains("<!ENTITY")) { throw new IllegalArgumentException("DTD not formatted"); }
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            DocumentBuilder parser = factory.newDocumentBuilder();
            parser.setErrorHandler(new DefaultHandler());
            parser.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));
            Element root = parser.parse(new InputSource(new StringReader(clean))).getDocumentElement();
            if (mixed(root, 0)) { throw new IllegalArgumentException("Mixed XML content"); }
        } catch (Exception ex) { throw new IllegalArgumentException("XML not safely formattable", ex); }
        List<Token> tokens = new ArrayList<Token>();
        for (int i = body; i < raw.length();) {
            int start = i;
            if (raw.charAt(i) != '<') {
                while (i < raw.length() && raw.charAt(i) != '<') { i++; }
                String value = raw.substring(start, i);
                if (!value.trim().isEmpty()) {
                    String noMarkers = value.replace("~PR~", "").replace("§", "").trim();
                    tokens.add(new Token(noMarkers.isEmpty() ? 'm' : 't', start, i));
                }
                continue;
            }
            if (raw.startsWith("<!--", i) || raw.startsWith("<![CDATA[", i) || raw.startsWith("<?", i)) {
                String ending = raw.startsWith("<!--", i) ? "-->" : raw.startsWith("<?", i) ? "?>" : "]]>";
                int end = raw.indexOf(ending, i + 2);
                if (end < 0) { throw new IllegalArgumentException("Invalid XML token"); }
                i = end + ending.length();
                tokens.add(new Token(ending.equals("]]>") ? 't' : 'o', start, i));
                continue;
            }
            char quote = 0;
            while (++i < raw.length()) {
                char c = raw.charAt(i);
                if (quote != 0) { if (c == quote) { quote = 0; } }
                else if (c == '\'' || c == '"') { quote = c; }
                else if (c == '>') { i++; break; }
            }
            if (i > raw.length() || raw.charAt(i - 1) != '>') { throw new IllegalArgumentException("Invalid tag"); }
            String tag = raw.substring(start, i);
            tokens.add(new Token(tag.startsWith("</") ? 'c' : tag.endsWith("/>") ? 'o' : 'b', start, i));
        }
        Builder out = new Builder(raw);
        out.source(0, body);
        int depth = 0;
        char previous = 0;
        for (Token token : tokens) {
            if (token.kind == 'c') { depth--; }
            if (token.kind != 'm' && token.kind != 't' && previous != 0 && previous != 't'
                    && !(token.kind == 'c' && previous == 'b')) { out.line(depth); }
            out.source(token.start, token.end);
            if (token.kind == 'b') { depth++; }
            if (token.kind != 'm') { previous = token.kind; }
        }
        return out.finish("XML");
    }

    private static boolean mixed(Element element, int depth) {
        if (depth > 128 || "preserve".equals(element.getAttribute("xml:space"))) { return true; }
        boolean elements = false;
        boolean text = false;
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element) {
                elements = true;
                if (mixed((Element) child, depth + 1)) { return true; }
            } else if ((child.getNodeType() == Node.TEXT_NODE || child.getNodeType() == Node.CDATA_SECTION_NODE)
                    && !child.getNodeValue().trim().isEmpty()) { text = true; }
        }
        return elements && text;
    }

    private static final class Token {
        final char kind;
        final int start;
        final int end;
        Token(char kind, int start, int end) { this.kind = kind; this.start = start; this.end = end; }
    }

    private static final class JsonValidator {
        final List<Token> tokens;
        int cursor;
        JsonValidator(List<Token> tokens) { this.tokens = tokens; }
        void value(int depth) {
            if (depth > 128 || cursor >= tokens.size()) { throw new IllegalArgumentException("Invalid JSON depth/value"); }
            char kind = tokens.get(cursor++).kind;
            if (kind == 'a' || kind == 's') { return; }
            char end = kind == '{' ? '}' : kind == '[' ? ']' : 0;
            if (end == 0) { throw new IllegalArgumentException("Invalid JSON value"); }
            if (peek(end)) { cursor++; return; }
            while (true) {
                if (kind == '{') { take('s'); take(':'); }
                value(depth + 1);
                if (peek(end)) { cursor++; return; }
                take(',');
            }
        }
        boolean peek(char kind) { return cursor < tokens.size() && tokens.get(cursor).kind == kind; }
        void take(char kind) { if (!peek(kind)) { throw new IllegalArgumentException("Invalid JSON grammar"); } cursor++; }
    }

    private static final class Builder {
        final String raw;
        final StringBuilder text = new StringBuilder();
        int[] indices;
        int size;
        final int maximum;
        Builder(String raw) { this.raw = raw; maximum = Math.min(2 * 1024 * 1024, Math.max(16384, raw.length() * 8)); indices = new int[Math.max(32, raw.length())]; }
        void source(int start, int end) {
            for (int i = start; i < end; i++) { append(raw.charAt(i), i); }
        }
        void virtual(String value) { for (int i = 0; i < value.length(); i++) { append(value.charAt(i), -1); } }
        void line(int depth) {
            if (text.length() > 0 && text.charAt(text.length() - 1) != '\n') { virtual("\n"); }
            for (int i = 0; i < Math.max(0, depth); i++) { virtual("  "); }
        }
        void append(char c, int origin) {
            if (size >= maximum) { throw new IllegalArgumentException("Formatted display exceeds size budget"); }
            if (size == indices.length) { indices = Arrays.copyOf(indices, indices.length * 2); }
            text.append(c); indices[size++] = origin;
        }
        FormattedRequestView finish(String format) {
            return new FormattedRequestView(raw, text.toString(), Arrays.copyOf(indices, size), format);
        }
    }
}
