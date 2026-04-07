package com.ns1903372dot.dpi;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

final class DpiSupport {
    private DpiSupport() {
    }

    static Optional<String> extractTlsSni(byte[] payload) {
        if (payload.length < 9) return Optional.empty();
        if ((payload[0] & 0xFF) != 0x16) return Optional.empty();
        int version = PcapIo.readUInt16Big(payload, 1);
        if (version < 0x0300 || version > 0x0304) return Optional.empty();
        if ((payload[5] & 0xFF) != 0x01) return Optional.empty();

        int offset = 9;
        offset += 2 + 32;
        if (offset >= payload.length) return Optional.empty();

        int sessionIdLength = payload[offset] & 0xFF;
        offset += 1 + sessionIdLength;
        if (offset + 2 > payload.length) return Optional.empty();

        int cipherSuitesLength = PcapIo.readUInt16Big(payload, offset);
        offset += 2 + cipherSuitesLength;
        if (offset >= payload.length) return Optional.empty();

        int compressionLength = payload[offset] & 0xFF;
        offset += 1 + compressionLength;
        if (offset + 2 > payload.length) return Optional.empty();

        int extensionsLength = PcapIo.readUInt16Big(payload, offset);
        offset += 2;
        int extensionsEnd = Math.min(payload.length, offset + extensionsLength);
        while (offset + 4 <= extensionsEnd) {
            int extensionType = PcapIo.readUInt16Big(payload, offset);
            int extensionLength = PcapIo.readUInt16Big(payload, offset + 2);
            offset += 4;
            if (offset + extensionLength > extensionsEnd) break;
            if (extensionType == 0x0000 && extensionLength >= 5) {
                int sniType = payload[offset + 2] & 0xFF;
                int sniLength = PcapIo.readUInt16Big(payload, offset + 3);
                if (sniType == 0x00 && sniLength <= extensionLength - 5 && offset + 5 + sniLength <= payload.length) {
                    return Optional.of(new String(payload, offset + 5, sniLength, StandardCharsets.UTF_8));
                }
            }
            offset += extensionLength;
        }
        return Optional.empty();
    }

    static Optional<String> extractHttpHost(byte[] payload) {
        if (payload.length < 4) return Optional.empty();
        String text = new String(payload, StandardCharsets.ISO_8859_1);
        if (!(text.startsWith("GET ") || text.startsWith("POST") || text.startsWith("PUT ")
                || text.startsWith("HEAD") || text.startsWith("DELE") || text.startsWith("PATC")
                || text.startsWith("OPTI"))) {
            return Optional.empty();
        }

        String[] lines = text.split("\\r?\\n");
        for (String line : lines) {
            if (line.regionMatches(true, 0, "Host:", 0, 5)) {
                String host = line.substring(5).trim();
                int colon = host.indexOf(':');
                if (colon >= 0) host = host.substring(0, colon);
                if (!host.isEmpty()) return Optional.of(host);
            }
        }
        return Optional.empty();
    }

    static AppType classifyDomain(String domain) {
        if (domain == null || domain.isEmpty()) return AppType.UNKNOWN;
        String value = domain.toLowerCase(Locale.ROOT);
        if (containsAny(value, "youtube", "ytimg", "youtu.be", "yt3.ggpht")) return AppType.YOUTUBE;
        if (containsAny(value, "facebook", "fbcdn", "fbsbx") || matchesDomain(value, "facebook.com", "fb.com", "meta.com")) return AppType.FACEBOOK;
        if (containsAny(value, "instagram", "cdninstagram")) return AppType.INSTAGRAM;
        if (containsAny(value, "whatsapp") || matchesDomain(value, "wa.me")) return AppType.WHATSAPP;
        if (containsAny(value, "twitter", "twimg") || matchesDomain(value, "x.com", "t.co")) return AppType.TWITTER;
        if (containsAny(value, "netflix", "nflxvideo", "nflximg")) return AppType.NETFLIX;
        if (containsAny(value, "amazon", "amazonaws", "cloudfront") || matchesDomain(value, "aws")) return AppType.AMAZON;
        if (containsAny(value, "microsoft", "office", "azure", "outlook", "bing") || matchesDomain(value, "msn.com", "live.com")) return AppType.MICROSOFT;
        if (containsAny(value, "apple", "icloud", "mzstatic", "itunes")) return AppType.APPLE;
        if (containsAny(value, "telegram") || matchesDomain(value, "t.me")) return AppType.TELEGRAM;
        if (containsAny(value, "tiktok", "tiktokcdn", "musical.ly", "bytedance")) return AppType.TIKTOK;
        if (containsAny(value, "spotify") || matchesDomain(value, "scdn.co")) return AppType.SPOTIFY;
        if (containsAny(value, "zoom")) return AppType.ZOOM;
        if (containsAny(value, "discord", "discordapp")) return AppType.DISCORD;
        if (containsAny(value, "github", "githubusercontent")) return AppType.GITHUB;
        if (containsAny(value, "cloudflare", "cf-")) return AppType.CLOUDFLARE;
        if (containsAny(value, "google", "gstatic", "googleapis", "ggpht", "gvt1")) return AppType.GOOGLE;
        return AppType.HTTPS;
    }

    private static boolean containsAny(String value, String... patterns) {
        for (String pattern : patterns) {
            if (value.contains(pattern)) return true;
        }
        return false;
    }

    private static boolean matchesDomain(String value, String... domains) {
        for (String domain : domains) {
            if (value.equals(domain) || value.endsWith("." + domain)) {
                return true;
            }
        }
        return false;
    }

    static final class BlockingRules {
        private final Set<Integer> blockedIps = new HashSet<>();
        private final Set<AppType> blockedApps = new HashSet<>();
        private final List<String> blockedDomains = new ArrayList<>();

        void blockIp(String ip) {
            blockedIps.add(FiveTuple.parseIpv4(ip));
            System.out.println("[Rules] Blocked IP: " + ip);
        }

        void blockApp(String appName) {
            AppType appType = AppType.fromDisplayName(appName);
            if (appType == null) {
                System.err.println("[Rules] Unknown app: " + appName);
                return;
            }
            blockedApps.add(appType);
            System.out.println("[Rules] Blocked app: " + appType.displayName());
        }

        void blockDomain(String domain) {
            blockedDomains.add(domain.toLowerCase(Locale.ROOT));
            System.out.println("[Rules] Blocked domain: " + domain);
        }

        boolean isBlocked(int srcIp, AppType appType, String domain) {
            if (blockedIps.contains(srcIp) || blockedApps.contains(appType)) return true;
            String normalized = domain == null ? "" : domain.toLowerCase(Locale.ROOT);
            for (String blockedDomain : blockedDomains) {
                if (normalized.contains(blockedDomain)) return true;
            }
            return false;
        }
    }

    static final class Flow {
        final FiveTuple tuple;
        AppType appType = AppType.UNKNOWN;
        String domain = "";
        long packets;
        long bytes;
        boolean blocked;

        Flow(FiveTuple tuple) {
            this.tuple = tuple;
        }
    }

    static String buildReport(long totalPackets, long forwarded, long dropped,
                              Map<FiveTuple, Flow> flows, Map<AppType, Long> appStats) {
        StringBuilder report = new StringBuilder();
        report.append(System.lineSeparator());
        report.append("==============================================================").append(System.lineSeparator());
        report.append("PROCESSING REPORT").append(System.lineSeparator());
        report.append("==============================================================").append(System.lineSeparator());
        report.append(String.format(Locale.ROOT, "Total Packets: %d%n", totalPackets));
        report.append(String.format(Locale.ROOT, "Forwarded:     %d%n", forwarded));
        report.append(String.format(Locale.ROOT, "Dropped:       %d%n", dropped));
        report.append(String.format(Locale.ROOT, "Active Flows:  %d%n", flows.size()));
        report.append(System.lineSeparator());
        report.append("APPLICATION BREAKDOWN").append(System.lineSeparator());

        appStats.entrySet().stream()
                .sorted(Map.Entry.<AppType, Long>comparingByValue(Comparator.reverseOrder()))
                .forEach(entry -> {
                    double percent = totalPackets == 0 ? 0.0 : entry.getValue() * 100.0 / totalPackets;
                    int barLength = (int) (percent / 5.0);
                    report.append(String.format(Locale.ROOT, "%-15s %8d %5.1f%% %s%n",
                            entry.getKey().displayName(), entry.getValue(), percent, "#".repeat(Math.max(0, barLength))));
                });

        Map<String, AppType> uniqueDomains = new LinkedHashMap<>();
        for (Flow flow : flows.values()) {
            if (flow.domain != null && !flow.domain.isBlank()) {
                uniqueDomains.put(flow.domain, flow.appType);
            }
        }
        if (!uniqueDomains.isEmpty()) {
            report.append(System.lineSeparator()).append("[Detected Applications/Domains]").append(System.lineSeparator());
            for (Map.Entry<String, AppType> entry : uniqueDomains.entrySet()) {
                report.append("  - ").append(entry.getKey()).append(" -> ").append(entry.getValue().displayName()).append(System.lineSeparator());
            }
        }
        return report.toString();
    }
}
