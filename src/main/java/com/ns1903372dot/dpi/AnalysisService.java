package com.ns1903372dot.dpi;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

final class AnalysisService {
    private final Map<String, Path> downloads = new ConcurrentHashMap<>();
    private final Map<String, Path> samples = new LinkedHashMap<>();

    AnalysisService() {
        registerSample("bundled-demo", Path.of("sample-data", "test_dpi.pcap"));
        registerSample("network-capture", Path.of("example-pcaps", "network_capture.pcap"));
        registerSample("browser-traffic", Path.of("example-pcaps", "browser_traffic.pcap"));
        registerSample("demo-input", Path.of("example-pcaps", "demo_input.pcap"));
    }

    Map<String, String> sampleCatalog() {
        Map<String, String> catalog = new LinkedHashMap<>();
        for (Map.Entry<String, Path> entry : samples.entrySet()) {
            if (Files.exists(entry.getValue())) {
                catalog.put(entry.getKey(), entry.getValue().toString().replace("\\", "/"));
            }
        }
        return catalog;
    }

    AnalysisResult analyze(String filename, String encodedData, String sampleId,
                           String blockApp, String blockDomain, String blockIp) throws Exception {
        Path workDir = Files.createTempDirectory("dpi-web-" + Instant.now().toEpochMilli());
        Path input = resolveInput(workDir, filename, encodedData, sampleId);
        Path output = workDir.resolve("filtered-output.pcap");

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
        DpiEngine.EngineStats stats = engine.processFile(input, output);

        String token = UUID.randomUUID().toString();
        downloads.put(token, output);
        return new AnalysisResult(
                token,
                engine.generateReport(),
                stats.totalPackets(),
                stats.forwarded(),
                stats.dropped(),
                stats.activeConnections()
        );
    }

    RichAnalysisResult analyzeRich(String filename, String encodedData, String sampleId,
                                   String blockApp, String blockDomain, String blockIp) throws Exception {
        Path workDir = Files.createTempDirectory("dpi-web-" + Instant.now().toEpochMilli());
        Path input = resolveInput(workDir, filename, encodedData, sampleId);
        Path output = workDir.resolve("filtered-output.pcap");

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
        downloads.put(token, output);
        return new RichAnalysisResult(token, engine.generateReport(), engine.snapshot());
    }

    Path lookupDownload(String token) {
        return downloads.get(token);
    }

    private Path resolveInput(Path workDir, String filename, String encodedData, String sampleId) throws IOException {
        if (sampleId != null && !sampleId.isBlank()) {
            Path samplePath = samples.get(sampleId);
            if (samplePath != null && Files.exists(samplePath)) {
                return samplePath;
            }
        }

        if (encodedData == null || encodedData.isBlank()) {
            throw new IOException("Missing PCAP upload or sample selection");
        }

        byte[] pcapBytes = Base64.getDecoder().decode(encodedData);
        Path input = workDir.resolve(filename == null || filename.isBlank() ? "input.pcap" : sanitizeFilename(filename));
        Files.write(input, pcapBytes);
        return input;
    }

    private void registerSample(String id, Path path) {
        samples.put(id, path);
    }

    private String sanitizeFilename(String value) {
        return value.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    record AnalysisResult(String token, String report, long totalPackets, long forwarded, long dropped, int activeFlows) {
    }

    record RichAnalysisResult(String token, String report, DpiEngine.EngineSnapshot snapshot) {
    }
}
