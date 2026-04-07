package com.ns1903372dot.dpi;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

final class RuleManager {
    record BlockReason(String type, String detail) {
    }

    private final Set<Integer> blockedIps = new HashSet<>();
    private final Set<AppType> blockedApps = new HashSet<>();
    private final Set<String> blockedDomains = new HashSet<>();
    private final Set<Integer> blockedPorts = new HashSet<>();

    synchronized void blockIp(String ip) {
        blockedIps.add(FiveTuple.parseIpv4(ip));
    }

    synchronized void blockApp(String appName) {
        AppType type = AppType.fromDisplayName(appName);
        if (type != null) {
            blockedApps.add(type);
        }
    }

    synchronized void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase(Locale.ROOT));
    }

    synchronized void blockPort(int port) {
        blockedPorts.add(port);
    }

    synchronized Optional<BlockReason> shouldBlock(int srcIp, int dstPort, AppType appType, String domain) {
        if (blockedIps.contains(srcIp)) {
            return Optional.of(new BlockReason("IP", FiveTuple.ipv4ToString(srcIp)));
        }
        if (blockedPorts.contains(dstPort)) {
            return Optional.of(new BlockReason("PORT", Integer.toString(dstPort)));
        }
        if (blockedApps.contains(appType)) {
            return Optional.of(new BlockReason("APP", appType.displayName()));
        }
        String normalized = domain == null ? "" : domain.toLowerCase(Locale.ROOT);
        for (String blockedDomain : blockedDomains) {
            if (matchesDomain(normalized, blockedDomain)) {
                return Optional.of(new BlockReason("DOMAIN", blockedDomain));
            }
        }
        return Optional.empty();
    }

    synchronized void saveRules(Path file) throws IOException {
        List<String> lines = new ArrayList<>();
        for (Integer ip : blockedIps) lines.add("IP=" + FiveTuple.ipv4ToString(ip));
        for (AppType app : blockedApps) lines.add("APP=" + app.displayName());
        for (String domain : blockedDomains) lines.add("DOMAIN=" + domain);
        for (Integer port : blockedPorts) lines.add("PORT=" + port);
        Files.write(file, lines, StandardCharsets.UTF_8);
    }

    synchronized void loadRules(Path file) throws IOException {
        if (!Files.exists(file)) return;
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            if (line.startsWith("IP=")) blockIp(line.substring(3));
            else if (line.startsWith("APP=")) blockApp(line.substring(4));
            else if (line.startsWith("DOMAIN=")) blockDomain(line.substring(7));
            else if (line.startsWith("PORT=")) blockPort(Integer.parseInt(line.substring(5)));
        }
    }

    private boolean matchesDomain(String domain, String pattern) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(2);
            return domain.equals(suffix) || domain.endsWith("." + suffix);
        }
        return domain.equals(pattern) || domain.endsWith("." + pattern) || domain.contains(pattern);
    }
}

