package com.vibecode.payloadrunner;

final class RequestLine {
    private final String method;
    private final String target;
    private final String version;

    private RequestLine(String method, String target, String version) {
        this.method = method;
        this.target = target;
        this.version = version;
    }

    static RequestLine parse(String line) {
        if (line == null) {
            return null;
        }
        int firstSpace = line.indexOf(' ');
        int lastSpace = line.lastIndexOf(' ');
        if (firstSpace <= 0 || lastSpace <= firstSpace) {
            return null;
        }
        String target = line.substring(firstSpace + 1, lastSpace);
        String version = line.substring(lastSpace + 1);
        if (target.isEmpty() || version.isEmpty()) {
            return null;
        }
        return new RequestLine(line.substring(0, firstSpace), target, version);
    }

    String getTarget() {
        return target;
    }

    String withTarget(String newTarget) {
        return method + " " + newTarget + " " + version;
    }
}

