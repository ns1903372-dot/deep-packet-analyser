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
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class SpaceServer {
    private static final String HTML = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Deep Packet Analyser</title>
              <style>
                :root {
                  --bg: #f4f1ea;
                  --card: #fffaf1;
                  --ink: #1d2a35;
                  --accent: #0e7490;
                  --accent-2: #ef4444;
                  --line: #d8cfc2;
                }
                * { box-sizing: border-box; }
                body {
                  margin: 0;
                  font-family: Georgia, "Times New Roman", serif;
                  background:
                    radial-gradient(circle at top left, #fff7db 0, transparent 30%),
                    linear-gradient(135deg, #f4f1ea, #ebe4d8);
                  color: var(--ink);
                }
                .wrap {
                  max-width: 980px;
                  margin: 0 auto;
                  padding: 32px 20px 48px;
                }
                .hero {
                  background: var(--card);
                  border: 1px solid var(--line);
                  border-radius: 24px;
                  padding: 28px;
                  box-shadow: 0 20px 40px rgba(29,42,53,0.08);
                }
                h1 {
                  margin: 0 0 12px;
                  font-size: 2.4rem;
                  line-height: 1.05;
                }
                p {
                  margin: 0;
                  font-size: 1rem;
                  line-height: 1.6;
                }
                .grid {
                  display: grid;
                  grid-template-columns: 1.3fr 0.9fr;
                  gap: 20px;
                  margin-top: 22px;
                }
                .panel {
                  background: rgba(255,250,241,0.96);
                  border: 1px solid var(--line);
                  border-radius: 20px;
                  padding: 22px;
                }
                label {
                  display: block;
                  font-weight: 700;
                  margin-bottom: 8px;
                }
                input[type=file], select, input[type=text] {
                  width: 100%;
                  padding: 12px 14px;
                  border-radius: 12px;
                  border: 1px solid #c9bcaa;
                  background: #fff;
                  margin-bottom: 14px;
                }
                button {
                  width: 100%;
                  border: 0;
                  border-radius: 14px;
                  padding: 14px 18px;
                  background: linear-gradient(135deg, var(--accent), #155e75);
                  color: white;
                  font-size: 1rem;
                  font-weight: 700;
                  cursor: pointer;
                }
                button:hover { filter: brightness(1.05); }
                .sample {
                  margin-top: 14px;
                  background: #fff;
                  border: 1px dashed var(--line);
                  border-radius: 14px;
                  padding: 14px;
                }
                pre {
                  white-space: pre-wrap;
                  word-break: break-word;
                  background: #17212b;
                  color: #f8fafc;
                  border-radius: 16px;
                  padding: 18px;
                  min-height: 280px;
                  overflow: auto;
                }
                .muted { color: #5b6873; }
                .actions {
                  display: flex;
                  gap: 12px;
                  margin-top: 12px;
                  flex-wrap: wrap;
                }
                .linkbtn {
                  display: inline-block;
                  padding: 10px 14px;
                  border-radius: 12px;
                  background: #fff;
                  color: var(--ink);
                  border: 1px solid var(--line);
                  text-decoration: none;
                  font-weight: 700;
                }
                .warn {
                  color: var(--accent-2);
                  font-weight: 700;
                }
                @media (max-width: 840px) {
                  .grid { grid-template-columns: 1fr; }
                  h1 { font-size: 2rem; }
                }
              </style>
            </head>
            <body>
              <div class="wrap">
                <section class="hero">
                  <h1>Deep Packet Analyser</h1>
                  <p>Upload a PCAP file, run the Java DPI engine, apply an optional block rule, and inspect the generated report directly inside your Hugging Face Space.</p>
                </section>

                <div class="grid">
                  <section class="panel">
                    <label for="pcap">PCAP File</label>
                    <input id="pcap" type="file" accept=".pcap">

                    <label for="blockApp">Block App</label>
                    <select id="blockApp">
                      <option value="">No app block</option>
                      <option>YouTube</option>
                      <option>Facebook</option>
                      <option>GitHub</option>
                      <option>Google</option>
                      <option>Netflix</option>
                      <option>Spotify</option>
                      <option>TikTok</option>
                      <option>Telegram</option>
                      <option>Zoom</option>
                    </select>

                    <label for="blockDomain">Block Domain</label>
                    <input id="blockDomain" type="text" placeholder="example: youtube.com">

                    <label for="blockIp">Block IP</label>
                    <input id="blockIp" type="text" placeholder="example: 192.168.1.50">

                    <button id="runBtn" type="button">Analyze PCAP</button>

                    <div class="sample">
                      <strong>Tip</strong>
                      <p class="muted">You can also test the engine with the bundled sample file path: <code>sample-data/test_dpi.pcap</code> by using the project locally.</p>
                    </div>
                  </section>

                  <section class="panel">
                    <p class="muted">Execution Output</p>
                    <pre id="report">Upload a PCAP file to begin.</pre>
                    <div class="actions" id="actions"></div>
                    <p class="warn" id="error"></p>
                  </section>
                </div>
              </div>

              <script>
                const runBtn = document.getElementById("runBtn");
                const report = document.getElementById("report");
                const actions = document.getElementById("actions");
                const error = document.getElementById("error");

                runBtn.addEventListener("click", async () => {
                  error.textContent = "";
                  actions.innerHTML = "";
                  const fileInput = document.getElementById("pcap");
                  const file = fileInput.files[0];
                  if (!file) {
                    error.textContent = "Please choose a PCAP file first.";
                    return;
                  }

                  report.textContent = "Running Java DPI engine...";

                  try {
                    const payload = {
                      filename: file.name,
                      data: await fileToBase64(file),
                      blockApp: document.getElementById("blockApp").value,
                      blockDomain: document.getElementById("blockDomain").value,
                      blockIp: document.getElementById("blockIp").value
                    };

                    const response = await fetch("/analyze", {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify(payload)
                    });

                    const result = await response.json();
                    if (!response.ok) {
                      throw new Error(result.error || "Request failed");
                    }

                    report.textContent = result.report;
                    if (result.downloadPath) {
                      const link = document.createElement("a");
                      link.className = "linkbtn";
                      link.href = result.downloadPath;
                      link.textContent = "Download Filtered PCAP";
                      actions.appendChild(link);
                    }
                  } catch (err) {
                    report.textContent = "Upload a PCAP file to begin.";
                    error.textContent = err.message || String(err);
                  }
                });

                function fileToBase64(file) {
                  return new Promise((resolve, reject) => {
                    const reader = new FileReader();
                    reader.onload = () => {
                      const result = reader.result;
                      resolve(String(result).split(",")[1]);
                    };
                    reader.onerror = reject;
                    reader.readAsDataURL(file);
                  });
                }
              </script>
            </body>
            </html>
            """;

    private static final Map<String, Path> DOWNLOADS = new ConcurrentHashMap<>();

    private SpaceServer() {
    }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "7860"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", SpaceServer::handleIndex);
        server.createContext("/analyze", SpaceServer::handleAnalyze);
        server.createContext("/download", SpaceServer::handleDownload);
        server.setExecutor(null);
        server.start();
        System.out.println("Space server running on port " + port);
    }

    private static void handleIndex(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method not allowed", "text/plain; charset=utf-8");
            return;
        }
        sendText(exchange, 200, HTML, "text/html; charset=utf-8");
    }

    private static void handleAnalyze(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
            return;
        }

        try {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String filename = jsonValue(body, "filename");
            String encodedData = jsonValue(body, "data");
            String blockApp = jsonValue(body, "blockApp");
            String blockDomain = jsonValue(body, "blockDomain");
            String blockIp = jsonValue(body, "blockIp");

            if (encodedData == null || encodedData.isBlank()) {
                sendJson(exchange, 400, "{\"error\":\"Missing PCAP data\"}");
                return;
            }

            byte[] pcapBytes = Base64.getDecoder().decode(encodedData);
            Path workDir = Files.createTempDirectory("dpi-space-" + Instant.now().toEpochMilli());
            Path input = workDir.resolve(filename == null || filename.isBlank() ? "input.pcap" : sanitizeFilename(filename));
            Path output = workDir.resolve("filtered-output.pcap");
            Files.write(input, pcapBytes);

            RuleManager ruleManager = new RuleManager();
            if (blockApp != null && !blockApp.isBlank()) {
                ruleManager.blockApp(blockApp);
            }
            if (blockDomain != null && !blockDomain.isBlank()) {
                ruleManager.blockDomain(blockDomain);
            }
            if (blockIp != null && !blockIp.isBlank()) {
                ruleManager.blockIp(blockIp);
            }

            DpiEngine.Config config = new DpiEngine.Config();
            config.numLoadBalancers = 2;
            config.fpsPerLoadBalancer = 2;
            DpiEngine engine = new DpiEngine(config, ruleManager);
            engine.processFile(input, output);

            String token = UUID.randomUUID().toString();
            DOWNLOADS.put(token, output);
            String report = engine.generateReport();
            String json = "{\"report\":\"" + escapeJson(report) + "\",\"downloadPath\":\"/download?id=" + token + "\"}";
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
        if (id == null || !DOWNLOADS.containsKey(id)) {
            sendText(exchange, 404, "File not found", "text/plain; charset=utf-8");
            return;
        }
        Path file = DOWNLOADS.get(id);
        byte[] data = Files.readAllBytes(file);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/vnd.tcpdump.pcap");
        headers.set("Content-Disposition", "attachment; filename=\"filtered-output.pcap\"");
        exchange.sendResponseHeaders(200, data.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(data);
        }
    }

    private static void sendText(HttpExchange exchange, int status, String body, String contentType) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(bytes);
        }
    }

    private static void sendJson(HttpExchange exchange, int status, String body) throws IOException {
        sendText(exchange, status, body, "application/json; charset=utf-8");
    }

    private static String sanitizeFilename(String value) {
        return value.replaceAll("[^A-Za-z0-9._-]", "_");
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
                builder.append(current);
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
}
