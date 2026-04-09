package com.ns1903372dot.dpi;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public final class SpaceServer {
    private static final Path WEB_ROOT = Path.of("web");
    private static final AnalysisService ANALYSIS_SERVICE = new AnalysisService();

    private SpaceServer() {
    }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "7860"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/api/health", SpaceServer::handleHealth);
        server.createContext("/api/examples", SpaceServer::handleExamples);
        server.createContext("/api/analyze", SpaceServer::handleAnalyze);
        server.createContext("/download", SpaceServer::handleDownload);
        server.createContext("/", SpaceServer::handleStatic);
        server.setExecutor(null);
        server.start();
        System.out.println("Frontend + backend server running on port " + port);
    }

    private static void handleHealth(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
            return;
        }
        sendJson(exchange, 200, "{\"status\":\"ok\"}");
    }

    private static void handleExamples(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
            return;
        }
        StringBuilder builder = new StringBuilder("{\"samples\":[");
        boolean first = true;
        for (Map.Entry<String, String> entry : ANALYSIS_SERVICE.sampleCatalog().entrySet()) {
            if (!first) {
                builder.append(',');
            }
            builder.append("{\"id\":\"")
                    .append(escapeJson(entry.getKey()))
                    .append("\",\"label\":\"")
                    .append(escapeJson(entry.getValue()))
                    .append("\"}");
            first = false;
        }
        builder.append("]}");
        sendJson(exchange, 200, builder.toString());
    }

    private static void handleAnalyze(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
            return;
        }

        try {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            AnalysisService.RichAnalysisResult result = ANALYSIS_SERVICE.analyzeRich(
                    jsonValue(body, "filename"),
                    jsonValue(body, "data"),
                    jsonValue(body, "sampleId"),
                    jsonValue(body, "blockApp"),
                    jsonValue(body, "blockDomain"),
                    jsonValue(body, "blockIp")
            );

            String json = """
                    {"report":"%s","downloadPath":"/download?id=%s","stats":{"totalPackets":%d,"forwarded":%d,"dropped":%d,"activeFlows":%d},"appBreakdown":[%s],"threadStats":[%s],"detectedDomains":[%s]}
                    """.formatted(
                    escapeJson(result.report()),
                    escapeJson(result.token()),
                    result.snapshot().stats().totalPackets(),
                    result.snapshot().stats().forwarded(),
                    result.snapshot().stats().dropped(),
                    result.snapshot().stats().activeConnections(),
                    appBreakdownJson(result.snapshot()),
                    threadStatsJson(result.snapshot()),
                    detectedDomainsJson(result.snapshot())
            ).replace("\r", "").replace("\n", "");
            sendJson(exchange, 200, json);
        } catch (Exception exception) {
            String json = "{\"error\":\"" + escapeJson(exception.getMessage() == null ? exception.toString() : exception.getMessage()) + "\"}";
            sendJson(exchange, 500, json);
        }
    }

    private static void handleDownload(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed", "text/plain; charset=utf-8");
            return;
        }
        String id = queryValue(exchange.getRequestURI(), "id");
        Path file = id == null ? null : ANALYSIS_SERVICE.lookupDownload(id);
        if (file == null || !Files.exists(file)) {
            sendText(exchange, 404, "File not found", "text/plain; charset=utf-8");
            return;
        }
        byte[] data = Files.readAllBytes(file);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/vnd.tcpdump.pcap");
        headers.set("Content-Disposition", "attachment; filename=\"filtered-output.pcap\"");
        exchange.sendResponseHeaders(200, data.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(data);
        }
    }

    private static void handleStatic(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed", "text/plain; charset=utf-8");
            return;
        }

        String rawPath = exchange.getRequestURI().getPath();
        String relative = "/".equals(rawPath) ? "index.html" : rawPath.substring(1);
        Path file = WEB_ROOT.resolve(relative).normalize();
        if (!file.startsWith(WEB_ROOT) || !Files.exists(file) || Files.isDirectory(file)) {
            sendText(exchange, 404, "Not found", "text/plain; charset=utf-8");
            return;
        }

        byte[] bytes = Files.readAllBytes(file);
        sendBytes(exchange, 200, bytes, contentType(file.getFileName().toString()));
    }

    private static void sendJson(HttpExchange exchange, int status, String body) throws IOException {
        sendBytes(exchange, status, body.getBytes(StandardCharsets.UTF_8), "application/json; charset=utf-8");
    }

    private static void sendText(HttpExchange exchange, int status, String body, String contentType) throws IOException {
        sendBytes(exchange, status, body.getBytes(StandardCharsets.UTF_8), contentType);
    }

    private static void sendBytes(HttpExchange exchange, int status, byte[] bytes, String contentType) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(bytes);
        }
    }

    private static String contentType(String filename) {
        if (filename.endsWith(".css")) return "text/css; charset=utf-8";
        if (filename.endsWith(".js")) return "application/javascript; charset=utf-8";
        if (filename.endsWith(".json")) return "application/json; charset=utf-8";
        return "text/html; charset=utf-8";
    }

    private static String queryValue(URI uri, String key) {
        String query = uri.getRawQuery();
        if (query == null || query.isBlank()) {
            return null;
        }
        for (String part : query.split("&")) {
            String[] pair = part.split("=", 2);
            if (pair.length == 2 && pair[0].equals(key)) {
                return pair[1];
            }
        }
        return null;
    }

    private static String jsonValue(String body, String key) {
        String needle = "\"" + key + "\":";
        int keyIndex = body.indexOf(needle);
        if (keyIndex < 0) {
            return null;
        }
        int startQuote = body.indexOf('"', keyIndex + needle.length());
        if (startQuote < 0) {
            return null;
        }
        StringBuilder builder = new StringBuilder();
        boolean escaping = false;
        for (int index = startQuote + 1; index < body.length(); index++) {
            char current = body.charAt(index);
            if (escaping) {
                switch (current) {
                    case 'n' -> builder.append('\n');
                    case 'r' -> builder.append('\r');
                    case 't' -> builder.append('\t');
                    default -> builder.append(current);
                }
                escaping = false;
            } else if (current == '\\') {
                escaping = true;
            } else if (current == '"') {
                return builder.toString();
            } else {
                builder.append(current);
            }
        }
        return null;
    }

    private static String escapeJson(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", "")
                .replace("\n", "\\n");
    }

    private static String appBreakdownJson(DpiEngine.EngineSnapshot snapshot) {
        StringBuilder builder = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, Long> entry : snapshot.appBreakdown().entrySet()) {
            if (!first) builder.append(',');
            builder.append("{\"name\":\"")
                    .append(escapeJson(entry.getKey()))
                    .append("\",\"value\":")
                    .append(entry.getValue())
                    .append("}");
            first = false;
        }
        return builder.toString();
    }

    private static String threadStatsJson(DpiEngine.EngineSnapshot snapshot) {
        StringBuilder builder = new StringBuilder();
        boolean first = true;
        for (DpiEngine.ThreadSnapshot stat : snapshot.threadStats()) {
            if (!first) builder.append(',');
            builder.append("{\"name\":\"")
                    .append(escapeJson(stat.name()))
                    .append("\",\"dispatched\":")
                    .append(stat.dispatched())
                    .append(",\"processed\":")
                    .append(stat.processed())
                    .append(",\"forwarded\":")
                    .append(stat.forwarded())
                    .append(",\"dropped\":")
                    .append(stat.dropped())
                    .append("}");
            first = false;
        }
        return builder.toString();
    }

    private static String detectedDomainsJson(DpiEngine.EngineSnapshot snapshot) {
        StringBuilder builder = new StringBuilder();
        boolean first = true;
        for (String domain : snapshot.detectedDomains()) {
            if (!first) builder.append(',');
            builder.append("\"").append(escapeJson(domain)).append("\"");
            first = false;
        }
        return builder.toString();
    }
}
